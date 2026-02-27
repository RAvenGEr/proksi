use std::collections::HashMap;

use pingora::Result;

use crate::middleware::Middleware;

/// Executes the request and response middleware
pub async fn execute_response_middleware(
    session: &mut pingora::proxy::Session,
    ctx: &mut crate::proxy_server::https_proxy::RouterContext,
) -> Result<()> {
    for (name, value) in ctx.route_container.middleware.clone() {
        match name.as_str() {
            "oauth2" => {
                use crate::middleware::Middleware;

                if crate::middleware::MIDDLEWARE
                    .oauth2
                    .response_filter(session, ctx, &value)
                    .await
                    .is_ok_and(|v| v)
                {
                    return Ok(());
                }
            }
            "request_id" => continue,
            _ => {}
        }
    }
    Ok(())
}

/// Executes the request middleware
pub async fn execute_request_middleware(
    session: &mut pingora::proxy::Session,
    ctx: &mut crate::proxy_server::https_proxy::RouterContext,
    middleware: &HashMap<String, crate::config::RouteMiddleware>,
) -> Result<bool> {
    use crate::middleware::Middleware;
    for (name, value) in middleware {
        match name.as_str() {
            "oauth2" => {
                if crate::middleware::MIDDLEWARE
                    .oauth2
                    .request_filter(session, ctx, value)
                    .await
                    .is_ok_and(|v| v)
                {
                    return Ok(true);
                }
            }
            "request_id" => {
                crate::middleware::MIDDLEWARE
                    .request_id
                    .request_filter(session, ctx, value)
                    .await
                    .ok();
            }
            "basic_auth" => {
                if crate::middleware::MIDDLEWARE
                    .basic_auth
                    .request_filter(session, ctx, value)
                    .await
                    .is_ok_and(|v| v)
                {
                    return Ok(true);
                }
            }
            "external_auth" => {
                if crate::middleware::MIDDLEWARE
                    .external_auth
                    .request_filter(session, ctx, value)
                    .await
                    .is_ok_and(|v| v)
                {
                    return Ok(true);
                }
            }
            _ => {}
        }
    }
    Ok(false)
}

/// Executes the upstream request middleware
pub async fn execute_upstream_request_middleware(
    session: &mut pingora::proxy::Session,
    upstream_request: &mut pingora::http::RequestHeader,
    ctx: &mut crate::proxy_server::https_proxy::RouterContext,
) -> Result<()> {
    for name in ctx.route_container.middleware.clone().keys() {
        match name.as_str() {
            "request_id" => {
                crate::middleware::MIDDLEWARE
                    .request_id
                    .upstream_request_filter(session, upstream_request, ctx)
                    .await
                    .ok();
            }
            "external_auth" => {
                crate::middleware::MIDDLEWARE
                    .external_auth
                    .upstream_request_filter(session, upstream_request, ctx)
                    .await
                    .ok();
            }
            "other" => continue,
            _ => {}
        }
    }
    Ok(())
}

/// Executes the upstream response middleware
pub fn execute_upstream_response_middleware(
    session: &mut pingora::proxy::Session,
    upstream_response: &mut pingora::http::ResponseHeader,
    ctx: &mut crate::proxy_server::https_proxy::RouterContext,
) {
    for name in ctx.route_container.middleware.clone().keys() {
        match name.as_str() {
            "request_id" => {
                crate::middleware::MIDDLEWARE
                    .request_id
                    .upstream_response_filter(session, upstream_response, ctx)
                    .ok();
            }
            "other" => continue,
            _ => {}
        }
    }
}
