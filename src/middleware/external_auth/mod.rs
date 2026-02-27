use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp, twoparty};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use http::StatusCode;
use once_cell::sync::Lazy;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::{mpsc, oneshot};
use tokio::task::LocalSet;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::config::RouteMiddleware;
use crate::proxy_server::https_proxy::RouterContext;

use super::Middleware;

pub mod external_auth_capnp {
    include!(concat!(env!("OUT_DIR"), "/external_auth_capnp.rs"));
}

const EXTENSION_UPSTREAM_VALUE: Cow<'static, str> = Cow::Borrowed("external_auth_upstream_value");
const EXTENSION_UPSTREAM_HEADER: Cow<'static, str> = Cow::Borrowed("external_auth_upstream_header");
const DEFAULT_TIMEOUT_MS: u64 = 1000;
const DEFAULT_UPSTREAM_HEADER: &str = "x-proksi-auth-context";
const DEFAULT_MAX_HEADERS: usize = 32;
const RPC_WORKER_QUEUE: usize = 1024;

static RPC_WORKERS: Lazy<DashMap<String, RpcWorkerHandle>> = Lazy::new(DashMap::new);

#[derive(Clone)]
struct ExternalAuthConfig {
    socket_path: String,
    timeout_ms: u64,
    upstream_header: String,
    allow_on_error: bool,
    max_headers: usize,
    header_allowlist: Option<HashSet<String>>,
}

#[derive(Clone)]
struct AuthRequestPayload {
    method: String,
    host: String,
    path: String,
    query: String,
    client_ip: String,
    headers: Vec<(String, String)>,
}

#[derive(Debug)]
enum DecisionAction {
    Pass,
    Block,
    Redirect,
}

#[derive(Debug)]
struct AuthDecisionPayload {
    action: DecisionAction,
    status_code: u16,
    upstream_value: String,
    redirect_location: String,
}

struct RpcJob {
    request: AuthRequestPayload,
    timeout_ms: u64,
    tx: oneshot::Sender<Result<AuthDecisionPayload>>,
}

#[derive(Clone)]
struct RpcWorkerHandle {
    tx: mpsc::Sender<RpcJob>,
}

pub struct ExternalAuth;

impl ExternalAuth {
    pub fn new() -> Self {
        Self
    }

    fn parse_config(
        config: &HashMap<Cow<'static, str>, serde_json::Value>,
    ) -> Result<ExternalAuthConfig> {
        let socket_path = config
            .get("socket_path")
            .and_then(|value| value.as_str())
            .map(ToString::to_string)
            .ok_or_else(|| anyhow!("external_auth: missing or invalid config.socket_path"))?;

        let timeout_ms = config
            .get("timeout_ms")
            .and_then(|value| value.as_u64())
            .unwrap_or(DEFAULT_TIMEOUT_MS);

        let max_headers = config
            .get("max_headers")
            .and_then(|value| value.as_u64())
            .map_or(DEFAULT_MAX_HEADERS, |value| value as usize);

        let header_allowlist = config
            .get("forward_headers")
            .and_then(|value| value.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|value| value.as_str())
                    .map(|value| value.to_ascii_lowercase())
                    .collect::<HashSet<_>>()
            });

        let upstream_header = config
            .get("upstream_header")
            .and_then(|value| value.as_str())
            .unwrap_or(DEFAULT_UPSTREAM_HEADER)
            .to_string();

        let allow_on_error = config
            .get("on_error")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("allow"));

        Ok(ExternalAuthConfig {
            socket_path,
            timeout_ms,
            upstream_header,
            allow_on_error,
            max_headers,
            header_allowlist,
        })
    }

    fn request_from_session(
        session: &Session,
        ctx: &RouterContext,
        cfg: &ExternalAuthConfig,
    ) -> AuthRequestPayload {
        let req = session.req_header();
        let method = req.method.to_string();
        let host = req
            .uri
            .host()
            .map(ToString::to_string)
            .unwrap_or_else(|| ctx.host.clone());
        let path = req.uri.path().to_string();
        let query = req.uri.query().unwrap_or_default().to_string();
        let client_ip = session
            .client_addr()
            .map(ToString::to_string)
            .unwrap_or_default();

        let mut headers = Vec::with_capacity(cfg.max_headers);
        for (key, value) in req.headers.iter() {
            if headers.len() >= cfg.max_headers {
                break;
            }

            if let Some(allowlist) = cfg.header_allowlist.as_ref()
                && !allowlist.contains(&key.as_str().to_ascii_lowercase())
            {
                continue;
            }

            headers.push((
                key.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            ));
        }

        AuthRequestPayload {
            method,
            host,
            path,
            query,
            client_ip,
            headers,
        }
    }

    fn get_or_start_worker(socket_path: &str) -> Result<RpcWorkerHandle> {
        match RPC_WORKERS.entry(socket_path.to_string()) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(vacant) => {
                let socket_path_owned = vacant.key().clone();
                let (tx, rx) = mpsc::channel::<RpcJob>(RPC_WORKER_QUEUE);
                let handle = RpcWorkerHandle { tx };
                vacant.insert(handle.clone());

                thread::Builder::new()
                    .name(format!(
                        "proksi-external-auth-{}",
                        socket_path_owned.replace('/', "_")
                    ))
                    .spawn(move || {
                        let runtime = TokioRuntimeBuilder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("external_auth: failed to build rpc runtime");
                        let local_set = LocalSet::new();
                        local_set.block_on(&runtime, async move {
                            Self::rpc_worker_loop(socket_path_owned, rx).await;
                        });
                    })
                    .map_err(|e| anyhow!("external_auth: failed to spawn rpc worker thread: {e}"))?;

                Ok(handle)
            }
        }
    }

    async fn rpc_worker_loop(socket_path: String, mut rx: mpsc::Receiver<RpcJob>) {
        let mut client: Option<external_auth_capnp::external_auth_service::Client> = None;

        while let Some(job) = rx.recv().await {
            if client.is_none() {
                client = match Self::connect_rpc(&socket_path).await {
                    Ok(client) => Some(client),
                    Err(err) => {
                        let _ = job.tx.send(Err(err));
                        continue;
                    }
                };
            }

            let Some(active_client) = client.as_ref() else {
                continue;
            };

            let call_result =
                Self::call_rpc(active_client.clone(), &job.request, job.timeout_ms).await;
            if call_result.is_err() {
                client = None;
            }

            let _ = job.tx.send(call_result);
        }
    }

    async fn connect_rpc(
        socket_path: &str,
    ) -> Result<external_auth_capnp::external_auth_service::Client> {
        let stream = tokio::net::UnixStream::connect(socket_path).await?;
        let (reader, writer) = stream.into_split();

        let network = twoparty::VatNetwork::new(
            reader.compat(),
            writer.compat_write(),
            rpc_twoparty_capnp::Side::Client,
            Default::default(),
        );

        let mut rpc_system = RpcSystem::new(Box::new(network), None);
        let client: external_auth_capnp::external_auth_service::Client =
            rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);
        tokio::task::spawn_local(async move {
            if let Err(err) = rpc_system.await {
                tracing::warn!("external_auth rpc system ended: {err}");
            }
        });

        Ok(client)
    }

    async fn call_rpc(
        client: external_auth_capnp::external_auth_service::Client,
        request: &AuthRequestPayload,
        timeout_ms: u64,
    ) -> Result<AuthDecisionPayload> {
        let mut rpc_request = client.check_request();
        let params = rpc_request.get();
        let mut auth_request = params.init_request();

        auth_request.set_method(&request.method);
        auth_request.set_host(&request.host);
        auth_request.set_path(&request.path);
        auth_request.set_query(&request.query);
        auth_request.set_client_ip(&request.client_ip);

        let mut headers = auth_request
            .reborrow()
            .init_headers(request.headers.len() as u32);
        for (index, (name, value)) in request.headers.iter().enumerate() {
            let mut header = headers.reborrow().get(index as u32);
            header.set_name(name);
            header.set_value(value);
        }

        let response = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            rpc_request.send().promise,
        )
        .await
        .map_err(|_| anyhow!("external_auth rpc timeout after {timeout_ms}ms"))??;

        let decision = response.get()?.get_decision()?;
        let action = match decision.get_action()? {
            external_auth_capnp::DecisionAction::Pass => DecisionAction::Pass,
            external_auth_capnp::DecisionAction::Block => DecisionAction::Block,
            external_auth_capnp::DecisionAction::Redirect => DecisionAction::Redirect,
        };

        Ok(AuthDecisionPayload {
            action,
            status_code: decision.get_status_code(),
            upstream_value: decision.get_upstream_value()?.to_string()?,
            redirect_location: decision.get_redirect_location()?.to_string()?,
        })
    }

    async fn decision_from_rpc(
        cfg: &ExternalAuthConfig,
        request: AuthRequestPayload,
    ) -> Result<AuthDecisionPayload> {
        let mut retries = 1;
        loop {
            let worker = Self::get_or_start_worker(&cfg.socket_path)?;
            let (tx, rx) = oneshot::channel();
            worker
                .tx
                .send(RpcJob {
                    request: request.clone(),
                    timeout_ms: cfg.timeout_ms,
                    tx,
                })
                .await
                .map_err(|_| {
                    tracing::warn!(
                        "external_auth rpc worker channel closed, invalidating worker for {}",
                        cfg.socket_path
                    );
                    RPC_WORKERS.remove(&cfg.socket_path);
                    anyhow!("external_auth rpc worker channel is closed")
                })?;

            match rx.await {
                Ok(res) => return res,
                Err(_) => {
                    tracing::warn!(
                        "external_auth rpc response channel closed, invalidating worker for {}",
                        cfg.socket_path
                    );
                    RPC_WORKERS.remove(&cfg.socket_path);
                    if retries > 0 {
                        retries -= 1;
                        continue;
                    }
                    return Err(anyhow!("external_auth rpc response channel closed"));
                }
            }
        }
    }

    fn status_or_default(status: u16, fallback: StatusCode) -> StatusCode {
        StatusCode::from_u16(status).unwrap_or(fallback)
    }

    async fn write_block_response(session: &mut Session, status: u16) -> Result<bool> {
        let status = Self::status_or_default(status, StatusCode::FORBIDDEN);
        let response = ResponseHeader::build_no_case(status, Some(0))?;
        session
            .write_response_header(Box::new(response), true)
            .await?;
        Ok(true)
    }

    async fn write_redirect_response(
        session: &mut Session,
        status: u16,
        location: &str,
    ) -> Result<bool> {
        let status = Self::status_or_default(status, StatusCode::TEMPORARY_REDIRECT);
        let mut response = ResponseHeader::build_no_case(status, Some(1))?;
        response.insert_header(http::header::LOCATION, location)?;
        session
            .write_response_header(Box::new(response), true)
            .await?;
        Ok(true)
    }
}

#[async_trait]
impl Middleware for ExternalAuth {
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut RouterContext,
        middleware: &RouteMiddleware,
    ) -> Result<bool> {
        let Some(config_map) = middleware.config.as_ref() else {
            return Ok(false);
        };

        let config = match Self::parse_config(config_map) {
            Ok(config) => config,
            Err(err) => {
                tracing::warn!("external_auth config is invalid, blocking request: {err}");
                return Self::write_block_response(
                    session,
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                )
                .await;
            }
        };

        let request = Self::request_from_session(session, ctx, &config);
        let decision = Self::decision_from_rpc(&config, request).await;

        let decision = match decision {
            Ok(decision) => decision,
            Err(err) if config.allow_on_error => {
                tracing::warn!(
                    "external_auth RPC failed, continuing because on_error=allow: {err}"
                );
                return Ok(false);
            }
            Err(err) => {
                tracing::warn!("external_auth RPC failed, blocking request: {err}");
                return Self::write_block_response(session, StatusCode::FORBIDDEN.as_u16()).await;
            }
        };

        match decision.action {
            DecisionAction::Pass => {
                if !decision.upstream_value.is_empty() {
                    ctx.extensions
                        .insert(EXTENSION_UPSTREAM_VALUE.clone(), decision.upstream_value);
                    ctx.extensions
                        .insert(EXTENSION_UPSTREAM_HEADER.clone(), config.upstream_header);
                }
                Ok(false)
            }
            DecisionAction::Block => {
                Self::write_block_response(session, decision.status_code).await
            }
            DecisionAction::Redirect => {
                if decision.redirect_location.is_empty() {
                    return Self::write_block_response(
                        session,
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    )
                    .await;
                }
                Self::write_redirect_response(
                    session,
                    decision.status_code,
                    &decision.redirect_location,
                )
                .await
            }
        }
    }

    async fn upstream_request_filter(
        &self,
        _: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut RouterContext,
    ) -> Result<()> {
        let Some(value) = ctx.extensions.get(EXTENSION_UPSTREAM_VALUE.as_ref()) else {
            return Ok(());
        };

        let header_name = ctx
            .extensions
            .get(EXTENSION_UPSTREAM_HEADER.as_ref())
            .map(String::as_str)
            .unwrap_or(DEFAULT_UPSTREAM_HEADER);

        let header_name = http::header::HeaderName::from_str(header_name)?;
        upstream_request.insert_header(header_name, value)?;

        Ok(())
    }

    async fn response_filter(
        &self,
        _: &mut Session,
        _: &mut RouterContext,
        _: &RouteMiddleware,
    ) -> Result<bool> {
        Ok(false)
    }

    fn upstream_response_filter(
        &self,
        _: &mut Session,
        _: &mut ResponseHeader,
        _: &mut RouterContext,
    ) -> Result<()> {
        Ok(())
    }
}
