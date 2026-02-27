use pingora::Result;

use crate::middleware::Middleware;

/// Executes the request and response middleware
pub async fn execute_response_middleware(
    session: &mut pingora::proxy::Session,
    ctx: &mut crate::proxy_server::https_proxy::RouterContext,
) -> Result<()> {
    let middleware = ctx.route_container.middleware.clone();
    for m in &middleware {
        match m.name.as_ref() {
            "oauth2" => {
                use crate::middleware::Middleware;

                if crate::middleware::MIDDLEWARE
                    .oauth2
                    .response_filter(session, ctx, m)
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
    middleware: &[crate::config::RouteMiddleware],
) -> Result<bool> {
    use crate::middleware::Middleware;
    for m in middleware {
        match m.name.as_ref() {
            "oauth2" => {
                if crate::middleware::MIDDLEWARE
                    .oauth2
                    .request_filter(session, ctx, m)
                    .await
                    .is_ok_and(|v| v)
                {
                    return Ok(true);
                }
            }
            "request_id" => {
                crate::middleware::MIDDLEWARE
                    .request_id
                    .request_filter(session, ctx, m)
                    .await
                    .ok();
            }
            "basic_auth" => {
                if crate::middleware::MIDDLEWARE
                    .basic_auth
                    .request_filter(session, ctx, m)
                    .await
                    .is_ok_and(|v| v)
                {
                    return Ok(true);
                }
            }
            "external_auth" => {
                if crate::middleware::MIDDLEWARE
                    .external_auth
                    .request_filter(session, ctx, m)
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
    let middleware = ctx.route_container.middleware.clone();
    for m in &middleware {
        match m.name.as_ref() {
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
    let middleware = ctx.route_container.middleware.clone();
    for m in &middleware {
        match m.name.as_ref() {
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
