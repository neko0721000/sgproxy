use std::sync::Arc;

use anyhow::{Result, anyhow};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::{HeaderMap, Response, StatusCode};
use reqwest::header::HeaderMap as ReqwestHeaderMap;
use tracing::{error, warn};

use crate::config::CredentialUpsertInput;
use crate::oauth::{RefreshError, maybe_refresh_access_token};
use crate::state::{AppState, SelectedCredential};

pub async fn handle_proxy(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response<Body>, ProxyError> {
    let (parts, body) = request.into_parts();
    let credential = resolve_proxy_credential(&state).await?;
    let upstream = state.upstream_snapshot().await;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(parts.uri.path());
    let url = format!(
        "{}{}",
        upstream.base_url.trim_end_matches('/'),
        path_and_query
    );
    let headers = build_upstream_headers(
        &parts.headers,
        &upstream.anthropic_version,
        &upstream.required_beta,
        &upstream.default_user_agent,
        credential.credential.access_token.as_str(),
    )
    .map_err(|err| ProxyError::bad_gateway(err.to_string()))?;

    let stream = body.into_data_stream();
    let client = state.client().await;
    let response = client
        .request(parts.method.clone(), url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .map_err(|err| ProxyError::bad_gateway(err.to_string()))?;

    let status_code = response.status().as_u16();
    let downstream_headers = filter_response_headers(response.headers());
    let body = Body::from_stream(response.bytes_stream());

    let persist_result = state
        .record_proxy_result(
            credential.credential.id.as_str(),
            credential.credential.access_token.as_str(),
            status_code,
        )
        .await;
    if let Err(err) = persist_result {
        warn!(error = %err, "failed to persist proxy result");
    }
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY));
    for (name, value) in &downstream_headers {
        builder = builder.header(name, value);
    }
    builder
        .body(body)
        .map_err(|err| ProxyError::internal(err.to_string()))
}

async fn resolve_proxy_credential(state: &Arc<AppState>) -> Result<SelectedCredential, ProxyError> {
    let selected = state
        .select_credential_for_proxy()
        .await
        .map_err(|err| ProxyError::service_unavailable(err.to_string()))?;

    let upstream = state.upstream_snapshot().await;
    let client = state.client().await;
    match maybe_refresh_access_token(&client, &upstream, &selected.credential).await {
        Ok(Some(refreshed)) => {
            let updated = state
                .add_or_update_credential(
                    CredentialUpsertInput {
                        id: Some(selected.credential.id.clone()),
                        enabled: Some(selected.credential.enabled),
                        order: Some(selected.credential.order),
                        access_token: Some(refreshed.access_token),
                        refresh_token: Some(refreshed.refresh_token),
                        expires_at_unix_ms: Some(refreshed.expires_at_unix_ms),
                        user_email: selected.credential.user_email.clone(),
                        organization_uuid: selected.credential.organization_uuid.clone(),
                        subscription_type: refreshed
                            .subscription_type
                            .or_else(|| selected.credential.subscription_type.clone()),
                        rate_limit_tier: refreshed
                            .rate_limit_tier
                            .or_else(|| selected.credential.rate_limit_tier.clone()),
                    },
                    Some(selected.credential.id.clone()),
                )
                .await
                .map_err(|err| ProxyError::internal(err.to_string()))?;
            Ok(SelectedCredential {
                credential: updated,
            })
        }
        Ok(None) => Ok(selected),
        Err(RefreshError::InvalidCredential(message)) => {
            warn!(credential_id = %selected.credential.id, error = %message, "credential refresh failed with invalid credential");
            state
                .record_proxy_result(
                    selected.credential.id.as_str(),
                    selected.credential.access_token.as_str(),
                    401,
                )
                .await
                .map_err(|err| ProxyError::internal(err.to_string()))?;
            state
                .select_credential_for_proxy()
                .await
                .map_err(|err| ProxyError::service_unavailable(err.to_string()))
        }
        Err(RefreshError::Transient(message)) => {
            error!(credential_id = %selected.credential.id, error = %message, "credential refresh failed");
            Err(ProxyError::bad_gateway(message))
        }
    }
}

fn build_upstream_headers(
    original: &HeaderMap,
    anthropic_version: &str,
    required_beta: &[String],
    default_user_agent: &str,
    access_token: &str,
) -> Result<ReqwestHeaderMap> {
    let mut headers = ReqwestHeaderMap::new();
    let mut seen_user_agent = false;
    let mut seen_anthropic_version = false;
    let mut beta_values = Vec::new();

    for (name, value) in original {
        let lower = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop(lower.as_str())
            || matches!(
                lower.as_str(),
                "host" | "content-length" | "authorization" | "cookie"
            )
        {
            continue;
        }

        if lower == "anthropic-beta" {
            if let Ok(raw) = value.to_str() {
                collect_beta_values(raw, &mut beta_values);
            }
            continue;
        }
        if lower == "user-agent" {
            seen_user_agent = true;
        }
        if lower == "anthropic-version" {
            seen_anthropic_version = true;
        }
        headers.insert(name, value.clone());
    }

    for beta in required_beta {
        collect_beta_values(beta.as_str(), &mut beta_values);
    }

    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(format!("Bearer {access_token}").as_str())
            .map_err(|err| anyhow!("invalid authorization header: {err}"))?,
    );
    if !seen_user_agent && !default_user_agent.trim().is_empty() {
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_str(default_user_agent.trim())
                .map_err(|err| anyhow!("invalid user-agent header: {err}"))?,
        );
    }
    if !seen_anthropic_version {
        headers.insert(
            HeaderName::from_static("anthropic-version"),
            HeaderValue::from_str(anthropic_version.trim())
                .map_err(|err| anyhow!("invalid anthropic-version header: {err}"))?,
        );
    }
    if !beta_values.is_empty() {
        headers.insert(
            HeaderName::from_static("anthropic-beta"),
            HeaderValue::from_str(beta_values.join(",").as_str())
                .map_err(|err| anyhow!("invalid anthropic-beta header: {err}"))?,
        );
    }

    Ok(headers)
}

fn filter_response_headers(headers: &ReqwestHeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        out.append(name, value.clone());
    }
    out
}

fn collect_beta_values(raw: &str, out: &mut Vec<String>) {
    for item in raw.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !out
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(trimmed))
        {
            out.push(trimmed.to_string());
        }
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

pub struct ProxyError {
    status: StatusCode,
    message: String,
}

impl ProxyError {
    fn service_unavailable(message: String) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message,
        }
    }

    fn bad_gateway(message: String) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message,
        }
    }

    fn internal(message: String) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message,
        }
    }
}

impl axum::response::IntoResponse for ProxyError {
    fn into_response(self) -> Response<Body> {
        let body = serde_json::json!({ "error": self.message }).to_string();
        Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::from("{\"error\":\"internal error\"}")))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{any, get, post};
    use serde_json::json;
    use serial_test::serial;
    use tempfile::tempdir;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use crate::admin;
    use crate::config::{ConfigFile, CredentialConfig, CredentialStatus};
    use crate::state::AppState;

    async fn spawn_server(app: Router) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve app");
        });
        (addr, handle)
    }

    async fn build_state(upstream_base_url: String) -> Arc<AppState> {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("sgproxy.toml");
        let config = ConfigFile {
            server: crate::config::ServerConfig {
                admin_token: "admin-secret".to_string(),
                ..crate::config::ServerConfig::default()
            },
            upstream: crate::config::UpstreamConfig {
                base_url: upstream_base_url,
                ..crate::config::UpstreamConfig::default()
            },
            credentials: vec![
                CredentialConfig {
                    id: "cred-a".to_string(),
                    enabled: true,
                    order: 1,
                    access_token: "token-a".to_string(),
                    refresh_token: "refresh-a".to_string(),
                    expires_at_unix_ms: u64::MAX,
                    user_email: None,
                    organization_uuid: None,
                    subscription_type: None,
                    rate_limit_tier: None,
                    status: CredentialStatus::Healthy,
                    cooldown_until_unix_ms: None,
                    last_error: None,
                    last_used_at_unix_ms: None,
                },
                CredentialConfig {
                    id: "cred-b".to_string(),
                    enabled: true,
                    order: 2,
                    access_token: "token-b".to_string(),
                    refresh_token: "refresh-b".to_string(),
                    expires_at_unix_ms: u64::MAX,
                    user_email: None,
                    organization_uuid: None,
                    subscription_type: None,
                    rate_limit_tier: None,
                    status: CredentialStatus::Healthy,
                    cooldown_until_unix_ms: None,
                    last_error: None,
                    last_used_at_unix_ms: None,
                },
            ],
        };
        AppState::new(PathBuf::from(config_path), config).expect("state")
    }

    fn app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/", get(admin::index))
            .route("/v1", any(super::handle_proxy))
            .route("/v1/{*tail}", any(super::handle_proxy))
            .with_state(state)
    }

    #[tokio::test]
    #[serial]
    async fn proxy_preserves_body_and_overrides_headers() {
        async fn upstream(req: Request<Body>) -> impl IntoResponse {
            let headers = req.headers();
            let auth = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let beta = headers
                .get("anthropic-beta")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let version = headers
                .get("anthropic-version")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let custom = headers
                .get("x-test-header")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let body = axum::body::to_bytes(req.into_body(), usize::MAX)
                .await
                .expect("body bytes");
            (
                StatusCode::OK,
                axum::Json(json!({
                    "authorization": auth,
                    "anthropic_beta": beta,
                    "anthropic_version": version,
                    "x_test_header": custom,
                    "body": String::from_utf8_lossy(&body),
                })),
            )
        }

        let (upstream_addr, _upstream_handle) =
            spawn_server(Router::new().route("/v1/messages", post(upstream))).await;
        let state = build_state(format!("http://{}", upstream_addr)).await;
        let (sg_addr, _sg_handle) = spawn_server(app(state)).await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("http://{}/v1/messages", sg_addr))
            .header("authorization", "Bearer should-be-overwritten")
            .header("x-test-header", "kept")
            .header("anthropic-beta", "custom-beta")
            .body("{\"hello\":\"world\"}")
            .send()
            .await
            .expect("send request");
        assert_eq!(response.status(), StatusCode::OK);
        let payload = response
            .json::<serde_json::Value>()
            .await
            .expect("json payload");
        assert_eq!(payload["authorization"], "Bearer token-a");
        assert_eq!(payload["anthropic_version"], "2023-06-01");
        assert_eq!(payload["x_test_header"], "kept");
        assert_eq!(payload["body"], "{\"hello\":\"world\"}");
        assert!(
            payload["anthropic_beta"]
                .as_str()
                .expect("beta string")
                .contains("oauth-2025-04-20")
        );
        assert!(
            payload["anthropic_beta"]
                .as_str()
                .expect("beta string")
                .contains("custom-beta")
        );
    }

    #[tokio::test]
    #[serial]
    async fn auth_failure_switches_credential_for_next_request() {
        async fn upstream(
            State(counter): State<Arc<tokio::sync::Mutex<u64>>>,
            req: Request<Body>,
        ) -> impl IntoResponse {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let mut guard = counter.lock().await;
            *guard += 1;
            if *guard == 1 {
                return (StatusCode::UNAUTHORIZED, Body::from("nope")).into_response();
            }
            axum::Json(json!({ "authorization": auth })).into_response()
        }

        let counter = Arc::new(tokio::sync::Mutex::new(0));
        let upstream_app = Router::new()
            .route("/v1/messages", post(upstream))
            .with_state(counter);
        let (upstream_addr, _upstream_handle) = spawn_server(upstream_app).await;
        let state = build_state(format!("http://{}", upstream_addr)).await;
        let (sg_addr, _sg_handle) = spawn_server(app(state.clone())).await;
        let client = reqwest::Client::new();

        let first = client
            .post(format!("http://{}/v1/messages", sg_addr))
            .body("first")
            .send()
            .await
            .expect("first request");
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        let _ = first.bytes().await.expect("first body");

        let second = reqwest::Client::new()
            .post(format!("http://{}/v1/messages", sg_addr))
            .body("second")
            .send()
            .await
            .expect("second request");
        assert_eq!(second.status(), StatusCode::OK);
        let payload = second
            .json::<serde_json::Value>()
            .await
            .expect("json payload");
        assert_eq!(payload["authorization"], "Bearer token-b");

        let credentials = state.credentials().await;
        let first_cred = credentials
            .iter()
            .find(|item| item.id == "cred-a")
            .expect("cred-a");
        let second_cred = credentials
            .iter()
            .find(|item| item.id == "cred-b")
            .expect("cred-b");
        assert_eq!(first_cred.status, CredentialStatus::Dead);
        assert_eq!(second_cred.status, CredentialStatus::Healthy);
    }
}
