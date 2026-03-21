use std::sync::Arc;

use anyhow::Result;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use rust_embed::RustEmbed;

use crate::config::{CredentialUpsertInput, UpdateConfigInput};
use crate::oauth::{OAuthCallbackInput, OAuthStartInput};
use crate::state::AppState;

#[derive(RustEmbed)]
#[folder = "src/web/"]
struct WebAssets;

pub async fn index() -> Html<String> {
    Html(render_index("admin"))
}

pub async fn usage_index() -> Html<String> {
    Html(render_index("usage"))
}

pub async fn get_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<crate::config::AdminConfigView>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(Json(state.config_view().await))
}

pub async fn put_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<UpdateConfigInput>,
) -> Result<Json<crate::config::AdminConfigView>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(Json(state.update_config(payload).await?))
}

pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::config::CredentialConfig>>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(Json(state.credentials().await))
}

pub async fn list_credential_usage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::config::UsageCredentialView>>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(Json(state.credential_usage_views().await?))
}

pub async fn get_credential_usage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<crate::config::UsageCredentialView>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(Json(state.credential_usage_view(id.as_str()).await?))
}

pub async fn create_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CredentialUpsertInput>,
) -> Result<Json<crate::config::CredentialConfig>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(Json(state.add_or_create_credential(payload, None).await?))
}

pub async fn update_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CredentialUpsertInput>,
) -> Result<Json<crate::config::CredentialConfig>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(Json(
        state.add_or_update_credential(payload, Some(id)).await?,
    ))
}

pub async fn enable_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<crate::config::CredentialConfig>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(Json(state.set_enabled(id.as_str(), true).await?))
}

pub async fn disable_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<crate::config::CredentialConfig>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(Json(state.set_enabled(id.as_str(), false).await?))
}

pub async fn delete_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AdminError> {
    authorize(&state, &headers).await?;
    state.delete_credential(id.as_str()).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn oauth_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<OAuthStartInput>,
) -> Result<Json<crate::oauth::OAuthStartResponse>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(crate::oauth::oauth_start(&state, payload).await?)
}

pub async fn oauth_callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<OAuthCallbackInput>,
) -> Result<Json<serde_json::Value>, AdminError> {
    authorize(&state, &headers).await?;
    Ok(crate::oauth::oauth_callback(&state, payload).await?)
}

pub async fn public_credentials(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::config::UsageCredentialView>>, AdminError> {
    Ok(Json(state.public_usage_credentials().await?))
}

async fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), AdminError> {
    let Some(token) = extract_bearer_token(headers) else {
        return Err(AdminError::unauthorized());
    };
    if !state.verify_admin_token(token).await {
        return Err(AdminError::unauthorized());
    }
    Ok(())
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let header = headers.get("authorization")?.to_str().ok()?;
    let value = header.strip_prefix("Bearer ")?;
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn render_index(mode: &str) -> String {
    let asset = WebAssets::get("index.html").expect("embedded index.html");
    let text = std::str::from_utf8(asset.data.as_ref()).expect("utf8 index.html");
    text.replace("__SGPROXY_VIEW_MODE__", mode)
}

pub struct AdminError {
    status: StatusCode,
    message: String,
}

impl AdminError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".to_string(),
        }
    }
}

impl From<anyhow::Error> for AdminError {
    fn from(value: anyhow::Error) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: value.to_string(),
        }
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "error": self.message,
            })),
        )
            .into_response()
    }
}
