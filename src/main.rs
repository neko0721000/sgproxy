use std::env;
use std::future::IntoFuture;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::Router;
use axum::routing::{any, delete, get, post, put};
use tokio::net::TcpListener;
use tracing::info;

mod admin;
mod config;
mod oauth;
mod persist;
mod proxy;
mod state;

use crate::config::DEFAULT_CONFIG_PATH;
use crate::persist::load_or_create_config;
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .compact()
        .init();

    let config_path = config_path_from_env();
    let admin_token = generate_admin_token();
    let config = load_or_create_config(&config_path, admin_token).await?;
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    let state = AppState::new(config_path.clone(), config)?;
    let app = app_router(state.clone());
    let listener = TcpListener::bind(&bind_addr).await?;

    println!("========================================");
    println!("sgproxy");
    println!("listen: http://{bind_addr}");
    println!("config: {}", config_path.display());
    println!("admin_token: {}", state.admin_token().await);
    println!("========================================");
    info!("starting sgproxy");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .into_future()
        .await?;

    Ok(())
}

pub fn app_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(admin::index))
        .route("/usage", get(admin::usage_index))
        .route("/api/public/credentials", get(admin::public_credentials))
        .route("/api/config", get(admin::get_config).put(admin::put_config))
        .route(
            "/api/credentials",
            get(admin::list_credentials).post(admin::create_credential),
        )
        .route("/api/credentials/usage", get(admin::list_credential_usage))
        .route("/api/credentials/usage/{id}", get(admin::get_credential_usage))
        .route("/api/credentials/{id}", put(admin::update_credential))
        .route(
            "/api/credentials/{id}/enable",
            post(admin::enable_credential),
        )
        .route(
            "/api/credentials/{id}/disable",
            post(admin::disable_credential),
        )
        .route("/api/credentials/{id}", delete(admin::delete_credential))
        .route("/api/oauth/start", post(admin::oauth_start))
        .route("/api/oauth/callback", post(admin::oauth_callback))
        .route("/v1", any(proxy::handle_proxy))
        .route("/v1/{*tail}", any(proxy::handle_proxy))
        .with_state(state)
}

fn config_path_from_env() -> PathBuf {
    env::var("SGPROXY_CONFIG")
        .map(PathBuf::from)
        .or_else(|_| {
            env::args()
                .nth(1)
                .map(PathBuf::from)
                .ok_or(env::VarError::NotPresent)
        })
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn generate_admin_token() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    let mut token = String::with_capacity(bytes.len() * 2 + 4);
    token.push_str("sgp_");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut token, "{byte:02x}");
    }
    token
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;

    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use serial_test::serial;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use crate::app_router;
    use crate::config::{ConfigFile, ServerConfig, UpstreamConfig};
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

    async fn build_state(
        config_path: PathBuf,
        upstream_base_url: String,
    ) -> std::sync::Arc<AppState> {
        let config = ConfigFile {
            server: ServerConfig {
                admin_token: "admin-secret".to_string(),
                ..ServerConfig::default()
            },
            upstream: UpstreamConfig {
                base_url: upstream_base_url,
                ..UpstreamConfig::default()
            },
            credentials: Vec::new(),
        };
        AppState::new(config_path, config).expect("state")
    }

    #[tokio::test]
    #[serial]
    async fn admin_api_requires_token() {
        let dir = TempDir::new().expect("tempdir");
        let state = build_state(
            dir.path().join("sgproxy.toml"),
            "http://127.0.0.1:9".to_string(),
        )
        .await;
        let (addr, _handle) = spawn_server(app_router(state)).await;
        let response = reqwest::Client::new()
            .get(format!("http://{}/api/config", addr))
            .send()
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[serial]
    async fn oauth_callback_persists_credential() {
        async fn token() -> axum::Json<serde_json::Value> {
            axum::Json(serde_json::json!({
                "access_token": "oauth-access",
                "refresh_token": "oauth-refresh",
                "expires_in": 3600,
                "subscriptionType": "claude_max",
                "rateLimitTier": "max"
            }))
        }

        async fn profile() -> axum::Json<serde_json::Value> {
            axum::Json(serde_json::json!({
                "account": {
                    "email": "dev@example.com",
                    "has_claude_max": true,
                    "has_claude_pro": false
                },
                "organization": {
                    "uuid": "org-123",
                    "organization_type": "claude_max",
                    "rate_limit_tier": "max"
                }
            }))
        }

        let upstream = Router::new()
            .route("/v1/oauth/token", post(token))
            .route("/api/oauth/profile", get(profile));
        let (upstream_addr, _upstream_handle) = spawn_server(upstream).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let dir = TempDir::new().expect("tempdir");
        let config_path = dir.path().join("sgproxy.toml");
        let state = build_state(config_path.clone(), format!("http://{}", upstream_addr)).await;
        let (addr, _handle) = spawn_server(app_router(state.clone())).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let client = reqwest::Client::new();

        let start = client
            .post(format!("http://{}/api/oauth/start", addr))
            .header("authorization", "Bearer admin-secret")
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("oauth start");
        assert_eq!(start.status(), StatusCode::OK);
        let start_payload = start.json::<serde_json::Value>().await.expect("start json");
        let state_value = start_payload["state"].as_str().expect("oauth state");

        let callback = reqwest::Client::new()
            .post(format!("http://{}/api/oauth/callback", addr))
            .header("authorization", "Bearer admin-secret")
            .json(&serde_json::json!({
                "callback_url": format!("http://localhost/callback?code=test-code&state={state_value}")
            }))
            .send()
            .await
            .expect("oauth callback");
        assert_eq!(callback.status(), StatusCode::OK);

        let credentials = state.credentials().await;
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].access_token, "oauth-access");
        assert_eq!(credentials[0].refresh_token, "oauth-refresh");

        let saved = tokio::fs::read_to_string(config_path)
            .await
            .expect("read saved config");
        assert!(saved.contains("oauth-access"));
        assert!(saved.contains("oauth-refresh"));
    }

    #[tokio::test]
    #[serial]
    async fn credential_import_completes_missing_fields() {
        async fn token() -> axum::Json<serde_json::Value> {
            axum::Json(serde_json::json!({
                "access_token": "import-access",
                "refresh_token": "import-refresh",
                "expires_in": 3600,
                "subscriptionType": "claude_max",
                "rateLimitTier": "max"
            }))
        }

        async fn profile() -> axum::Json<serde_json::Value> {
            axum::Json(serde_json::json!({
                "account": {
                    "email": "import@example.com",
                    "has_claude_max": true,
                    "has_claude_pro": false
                },
                "organization": {
                    "uuid": "org-import",
                    "organization_type": "claude_max",
                    "rate_limit_tier": "max"
                }
            }))
        }

        let upstream = Router::new()
            .route("/v1/oauth/token", post(token))
            .route("/api/oauth/profile", get(profile));
        let (upstream_addr, _upstream_handle) = spawn_server(upstream).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let dir = TempDir::new().expect("tempdir");
        let state = build_state(
            dir.path().join("sgproxy.toml"),
            format!("http://{}", upstream_addr),
        )
        .await;
        let (addr, _handle) = spawn_server(app_router(state.clone())).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let response = reqwest::Client::new()
            .post(format!("http://{}/api/credentials", addr))
            .header("authorization", "Bearer admin-secret")
            .json(&serde_json::json!({
                "refresh_token": "manual-refresh"
            }))
            .send()
            .await
            .expect("import request");
        let status = response.status();
        let body = response.text().await.expect("import body");
        assert_eq!(status, StatusCode::OK, "{body}");

        let credentials = state.credentials().await;
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].access_token, "import-access");
        assert_eq!(credentials[0].refresh_token, "import-refresh");
        assert_eq!(credentials[0].user_email.as_deref(), Some("import@example.com"));
        assert_eq!(
            credentials[0].subscription_type.as_deref(),
            Some("claude_max")
        );
        assert_eq!(credentials[0].rate_limit_tier.as_deref(), Some("max"));
        assert_eq!(
            credentials[0].organization_uuid.as_deref(),
            Some("org-import")
        );
    }
}
