use std::convert::TryFrom;

use anyhow::{Result, anyhow};
use serde_json::json;
use web_sys::Request as WebRequest;
use worker::{Env, Headers, Method, Request, Response, State, durable_object};

use crate::config::{
    ChannelKind, CredentialConfig, CredentialStatus, CredentialUpsertInput,
    CredentialUsageSnapshot, DurableStateDoc,
};
use crate::oauth::{
    OAuthCallbackInput, OAuthStartInput, RefreshError, RefreshedCredential,
    exchange_claudecode_code_for_tokens, fetch_claudecode_usage, fetch_oauth_profile,
    maybe_refresh_access_token, oauth_start_claudecode, resolve_code_and_state,
};
use crate::proxy::proxy_request;
use crate::state::{
    apply_1m_probe_result, build_usage_view, delete_credential, first_usable, insert_oauth_state,
    load_doc, now_unix_ms, record_invalid_auth, record_rate_limited, record_success,
    record_transient, save_doc, set_enabled, take_oauth_state, upsert_credential,
};

const ACTIVE_CHANNEL: ChannelKind = ChannelKind::ClaudeCode;

#[durable_object]
pub struct SgproxyState {
    state: State,
    env: Env,
}

impl worker::DurableObject for SgproxyState {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> worker::Result<Response> {
        let method = req.method();
        let path = req.path();

        let response = match self.route(method, path.as_str(), req).await {
            Ok(response) => response,
            Err(err) => json_error(400, &err.to_string())?,
        };
        Ok(response)
    }
}

impl SgproxyState {
    async fn route(&self, method: Method, path: &str, mut req: Request) -> Result<Response> {
        if path == "/api/public/credentials" && method == Method::Get {
            return self.public_credentials().await;
        }
        if path == "/api/credentials/usage" && method == Method::Get {
            self.authorize(&req)?;
            return self.list_usage().await;
        }
        if let Some(id) = path.strip_prefix("/api/credentials/usage/") {
            self.authorize(&req)?;
            return self.get_usage(id).await;
        }
        if path == "/api/credentials" && method == Method::Get {
            self.authorize(&req)?;
            return self.list_credentials().await;
        }
        if path == "/api/credentials" && method == Method::Post {
            self.authorize(&req)?;
            let payload = req.json::<CredentialUpsertInput>().await?;
            return self.create_credential(payload).await;
        }
        if let Some(id) = path.strip_prefix("/api/credentials/") {
            if id.ends_with("/enable") && method == Method::Post {
                self.authorize(&req)?;
                return self.set_enabled(id.trim_end_matches("/enable"), true).await;
            }
            if id.ends_with("/disable") && method == Method::Post {
                self.authorize(&req)?;
                return self
                    .set_enabled(id.trim_end_matches("/disable"), false)
                    .await;
            }
            if !id.contains('/') && method == Method::Put {
                self.authorize(&req)?;
                let payload = req.json::<CredentialUpsertInput>().await?;
                return self.update_credential(id, payload).await;
            }
            if !id.contains('/') && method == Method::Delete {
                self.authorize(&req)?;
                return self.delete_credential(id).await;
            }
        }
        if path == "/api/oauth/start" && method == Method::Post {
            self.authorize(&req)?;
            let payload = req.json::<OAuthStartInput>().await?;
            return self.oauth_start(payload).await;
        }
        if path == "/api/oauth/callback" && method == Method::Post {
            self.authorize(&req)?;
            let payload = req.json::<OAuthCallbackInput>().await?;
            return self.oauth_callback(payload).await;
        }
        if path == "/v1" || path.starts_with("/v1/") {
            self.authorize(&req)?;
            return self.proxy(req).await;
        }

        json_error(404, "not found").map_err(Into::into)
    }

    fn authorize(&self, req: &Request) -> Result<()> {
        let expected = self
            .env
            .secret("ADMIN_TOKEN")
            .map(|value| value.to_string())
            .or_else(|_| self.env.var("ADMIN_TOKEN").map(|value| value.to_string()))
            .map_err(|_| anyhow!("missing ADMIN_TOKEN secret"))?;
        let provided = provided_api_token(req.headers()).ok_or_else(|| anyhow!("unauthorized"))?;
        if provided == expected {
            Ok(())
        } else {
            Err(anyhow!("unauthorized"))
        }
    }

    async fn public_credentials(&self) -> Result<Response> {
        let mut doc = load_doc(&self.state.storage()).await?;
        let response = self.build_usage_payload(&mut doc, None).await;
        save_doc(&self.state.storage(), &doc).await?;
        Ok(Response::from_json(&response)?)
    }

    async fn list_usage(&self) -> Result<Response> {
        let mut doc = load_doc(&self.state.storage()).await?;
        let response = self.build_usage_payload(&mut doc, None).await;
        save_doc(&self.state.storage(), &doc).await?;
        Ok(Response::from_json(&response)?)
    }

    async fn get_usage(&self, id: &str) -> Result<Response> {
        let mut doc = load_doc(&self.state.storage()).await?;
        if !doc
            .credentials
            .iter()
            .any(|item| item.channel == ACTIVE_CHANNEL && item.id == id)
        {
            return Err(anyhow!("credential not found: {id}"));
        }
        let mut items = self.build_usage_payload(&mut doc, Some(id)).await;
        save_doc(&self.state.storage(), &doc).await?;
        let view = items
            .pop()
            .ok_or_else(|| anyhow!("credential not found: {id}"))?;
        Ok(Response::from_json(&view)?)
    }

    async fn list_credentials(&self) -> Result<Response> {
        let mut doc = load_doc(&self.state.storage()).await?;
        doc.normalize(now_unix_ms());
        save_doc(&self.state.storage(), &doc).await?;
        let items = doc
            .credentials
            .into_iter()
            .filter(|item| item.channel == ACTIVE_CHANNEL)
            .collect::<Vec<_>>();
        Ok(Response::from_json(&items)?)
    }

    async fn create_credential(&self, payload: CredentialUpsertInput) -> Result<Response> {
        let mut doc = load_doc(&self.state.storage()).await?;
        let resolved = self.resolve_credential_input(payload, None, &doc).await?;
        let credential = upsert_credential(&mut doc, resolved, None, ACTIVE_CHANNEL);
        doc.normalize(now_unix_ms());
        save_doc(&self.state.storage(), &doc).await?;
        Ok(Response::from_json(&credential)?)
    }

    async fn update_credential(
        &self,
        id: &str,
        payload: CredentialUpsertInput,
    ) -> Result<Response> {
        let mut doc = load_doc(&self.state.storage()).await?;
        let existing = doc
            .credentials
            .iter()
            .find(|item| item.channel == ACTIVE_CHANNEL && item.id == id)
            .cloned();
        if existing.is_none() {
            return Err(anyhow!("credential not found: {id}"));
        }
        let resolved = self
            .resolve_credential_input(payload, Some(id), &doc)
            .await?;
        let credential = upsert_credential(&mut doc, resolved, Some(id), ACTIVE_CHANNEL);
        doc.normalize(now_unix_ms());
        save_doc(&self.state.storage(), &doc).await?;
        Ok(Response::from_json(&credential)?)
    }

    async fn set_enabled(&self, id: &str, enabled: bool) -> Result<Response> {
        let mut doc = load_doc(&self.state.storage()).await?;
        ensure_channel_credential(&doc, ACTIVE_CHANNEL, id)?;
        let credential = set_enabled(&mut doc, id, enabled)?;
        save_doc(&self.state.storage(), &doc).await?;
        Ok(Response::from_json(&credential)?)
    }

    async fn delete_credential(&self, id: &str) -> Result<Response> {
        let mut doc = load_doc(&self.state.storage()).await?;
        ensure_channel_credential(&doc, ACTIVE_CHANNEL, id)?;
        delete_credential(&mut doc, id)?;
        save_doc(&self.state.storage(), &doc).await?;
        Ok(Response::from_json(&json!({ "ok": true }))?)
    }

    async fn oauth_start(&self, payload: OAuthStartInput) -> Result<Response> {
        let started = oauth_start_claudecode(payload);
        let mut doc = load_doc(&self.state.storage()).await?;
        insert_oauth_state(&mut doc, started.stored_state);
        save_doc(&self.state.storage(), &doc).await?;
        Ok(Response::from_json(&started.response)?)
    }

    async fn oauth_callback(&self, payload: OAuthCallbackInput) -> Result<Response> {
        let (code, requested_state) = resolve_code_and_state(&payload)?;
        let mut doc = load_doc(&self.state.storage()).await?;
        let oauth_state = take_oauth_state(&mut doc, ACTIVE_CHANNEL, requested_state.as_deref())?;

        let token = exchange_claudecode_code_for_tokens(&oauth_state, &code).await?;
        let access_token = token
            .access_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("missing_access_token"))?
            .to_string();
        let refresh_token = token
            .refresh_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("missing_refresh_token"))?
            .to_string();
        let profile = fetch_oauth_profile(&access_token).await.ok();
        let credential = upsert_credential(
            &mut doc,
            CredentialUpsertInput {
                id: None,
                enabled: Some(true),
                order: None,
                access_token: Some(access_token),
                refresh_token: Some(refresh_token),
                expires_at_unix_ms: Some(
                    now_unix_ms()
                        .saturating_add(token.expires_in.unwrap_or(3600).saturating_mul(1000)),
                ),
                enable_sonnet_1m: None,
                enable_opus_1m: None,
                user_email: profile.as_ref().and_then(|item| item.email.clone()),
                account_uuid: profile.as_ref().and_then(|item| item.account_uuid.clone()),
                organization_uuid: token.organization_uuid.clone().or_else(|| {
                    profile
                        .as_ref()
                        .and_then(|item| item.organization_uuid.clone())
                }),
                subscription_type: token.subscription_type.clone().or_else(|| {
                    profile
                        .as_ref()
                        .and_then(|item| item.subscription_type.clone())
                }),
                rate_limit_tier: token.rate_limit_tier.clone().or_else(|| {
                    profile
                        .as_ref()
                        .and_then(|item| item.rate_limit_tier.clone())
                }),
            },
            None,
            ACTIVE_CHANNEL,
        );

        doc.normalize(now_unix_ms());
        save_doc(&self.state.storage(), &doc).await?;
        Ok(Response::from_json(&json!({ "credential": credential }))?)
    }

    async fn proxy(&self, req: Request) -> Result<Response> {
        let mut doc = load_doc(&self.state.storage()).await?;
        let mut selected = self.resolve_proxy_credential(&mut doc).await?;
        save_doc(&self.state.storage(), &doc).await?;

        let retry_req = clone_request(&req)?;
        let mut result = proxy_request(req, &selected).await;
        let now = now_unix_ms();
        let mut doc = load_doc(&self.state.storage()).await?;
        let mut handled_auth_failure = false;

        if matches!(
            result,
            Ok(ref outcome) if matches!(outcome.status_code, 401 | 403)
        ) {
            match self.refresh_credential(&mut doc, &selected, true).await {
                Ok(Some(refreshed)) => {
                    selected = refreshed;
                    result = proxy_request(retry_req, &selected).await;
                }
                Ok(None) => {}
                Err(RefreshError::InvalidCredential(message)) => {
                    record_invalid_auth(&mut doc, &selected.id, now, message);
                    handled_auth_failure = true;
                }
                Err(RefreshError::Transient(message)) => {
                    record_transient(&mut doc, &selected.id, now, message);
                    handled_auth_failure = true;
                }
            }
        }

        match result {
            Ok(outcome) => {
                apply_1m_probe_result(
                    &mut doc,
                    &selected.id,
                    outcome.disable_sonnet_1m,
                    outcome.disable_opus_1m,
                );
                match outcome.status_code {
                    200..=299 => record_success(&mut doc, &selected.id, now),
                    401 | 403 if !handled_auth_failure => {
                        record_invalid_auth(
                            &mut doc,
                            &selected.id,
                            now,
                            format!("upstream returned status {}", outcome.status_code),
                        );
                    }
                    429 => {
                        if let Some(usage) = outcome.rate_limit_usage.as_ref() {
                            record_rate_limited(&mut doc, &selected.id, now, Some(usage), None);
                        } else {
                            record_rate_limited(
                                &mut doc,
                                &selected.id,
                                now,
                                None,
                                Some("upstream returned status 429".to_string()),
                            );
                        }
                    }
                    status => {
                        record_transient(
                            &mut doc,
                            &selected.id,
                            now,
                            format!("upstream returned status {status}"),
                        );
                    }
                }
                save_doc(&self.state.storage(), &doc).await?;
                Ok(outcome.response)
            }
            Err(err) => {
                record_transient(&mut doc, &selected.id, now, err.to_string());
                save_doc(&self.state.storage(), &doc).await?;
                json_error(502, &err.to_string()).map_err(Into::into)
            }
        }
    }

    async fn resolve_proxy_credential(
        &self,
        doc: &mut DurableStateDoc,
    ) -> Result<CredentialConfig> {
        loop {
            doc.normalize(now_unix_ms());
            let selected = first_usable(&doc.credentials, ACTIVE_CHANNEL, now_unix_ms())
                .ok_or_else(|| anyhow!("no usable credential configured"))?;

            match self.refresh_credential(doc, &selected, false).await {
                Ok(Some(updated)) => return Ok(updated),
                Ok(None) => return Ok(selected),
                Err(RefreshError::InvalidCredential(message)) => {
                    record_invalid_auth(doc, &selected.id, now_unix_ms(), message);
                }
                Err(RefreshError::Transient(message)) => return Err(anyhow!(message)),
            }
        }
    }

    async fn resolve_credential_input(
        &self,
        input: CredentialUpsertInput,
        forced_id: Option<&str>,
        doc: &DurableStateDoc,
    ) -> Result<CredentialUpsertInput> {
        let existing = forced_id
            .and_then(|id| {
                doc.credentials
                    .iter()
                    .find(|item| item.channel == ACTIVE_CHANNEL && item.id == id)
            })
            .cloned()
            .or_else(|| {
                input.id.as_deref().and_then(|id| {
                    doc.credentials
                        .iter()
                        .find(|item| item.channel == ACTIVE_CHANNEL && item.id == id)
                        .cloned()
                })
            });

        let mut access_token = input
            .access_token
            .clone()
            .and_then(|value| crate::config::clean_opt_owned(Some(value)))
            .or_else(|| {
                existing
                    .as_ref()
                    .map(|item| item.access_token.clone())
                    .filter(|value| !value.is_empty())
            });
        let mut refresh_token = input
            .refresh_token
            .clone()
            .and_then(|value| crate::config::clean_opt_owned(Some(value)))
            .or_else(|| {
                existing
                    .as_ref()
                    .map(|item| item.refresh_token.clone())
                    .filter(|value| !value.is_empty())
            });
        let mut expires_at_unix_ms = input
            .expires_at_unix_ms
            .or_else(|| existing.as_ref().map(|item| item.expires_at_unix_ms));
        let enable_sonnet_1m = input
            .enable_sonnet_1m
            .or_else(|| existing.as_ref().map(|item| item.enable_sonnet_1m))
            .unwrap_or(true);
        let enable_opus_1m = input
            .enable_opus_1m
            .or_else(|| existing.as_ref().map(|item| item.enable_opus_1m))
            .unwrap_or(true);
        let mut user_email = input
            .user_email
            .clone()
            .and_then(|value| crate::config::clean_opt_owned(Some(value)))
            .or_else(|| existing.as_ref().and_then(|item| item.user_email.clone()));
        let mut account_uuid = input
            .account_uuid
            .clone()
            .and_then(|value| crate::config::clean_opt_owned(Some(value)))
            .or_else(|| existing.as_ref().and_then(|item| item.account_uuid.clone()));
        let mut organization_uuid = input
            .organization_uuid
            .clone()
            .and_then(|value| crate::config::clean_opt_owned(Some(value)))
            .or_else(|| {
                existing
                    .as_ref()
                    .and_then(|item| item.organization_uuid.clone())
            });
        let mut subscription_type = input
            .subscription_type
            .clone()
            .and_then(|value| crate::config::clean_opt_owned(Some(value)))
            .or_else(|| {
                existing
                    .as_ref()
                    .and_then(|item| item.subscription_type.clone())
            });
        let mut rate_limit_tier = input
            .rate_limit_tier
            .clone()
            .and_then(|value| crate::config::clean_opt_owned(Some(value)))
            .or_else(|| {
                existing
                    .as_ref()
                    .and_then(|item| item.rate_limit_tier.clone())
            });

        if access_token.is_none() && refresh_token.is_none() {
            return Err(anyhow!("missing access_token or refresh_token"));
        }

        if let Some(refresh) = refresh_token.clone()
            && (access_token.is_none() || expires_at_unix_ms.unwrap_or(0) <= now_unix_ms())
        {
            let refreshed = maybe_refresh_access_token(&CredentialConfig {
                id: existing
                    .as_ref()
                    .map(|item| item.id.clone())
                    .unwrap_or_else(|| "import".to_string()),
                channel: ACTIVE_CHANNEL,
                enabled: existing.as_ref().map(|item| item.enabled).unwrap_or(true),
                order: existing.as_ref().map(|item| item.order).unwrap_or(0),
                access_token: access_token.clone().unwrap_or_default(),
                refresh_token: refresh,
                expires_at_unix_ms: expires_at_unix_ms.unwrap_or(0),
                enable_sonnet_1m,
                enable_opus_1m,
                user_email: user_email.clone(),
                account_uuid: account_uuid.clone(),
                organization_uuid: organization_uuid.clone(),
                subscription_type: subscription_type.clone(),
                rate_limit_tier: rate_limit_tier.clone(),
                status: CredentialStatus::Healthy,
                cooldown_until_unix_ms: None,
                last_error: None,
                last_used_at_unix_ms: None,
            })
            .await
            .map_err(|err| match err {
                RefreshError::InvalidCredential(message) | RefreshError::Transient(message) => {
                    anyhow!(message)
                }
            })?;
            if let Some(refreshed) = refreshed {
                access_token = Some(refreshed.access_token);
                refresh_token = Some(refreshed.refresh_token);
                expires_at_unix_ms = Some(refreshed.expires_at_unix_ms);
                if user_email.is_none() {
                    user_email = refreshed.user_email;
                }
                if account_uuid.is_none() {
                    account_uuid = refreshed.account_uuid;
                }
                if organization_uuid.is_none() {
                    organization_uuid = refreshed.organization_uuid;
                }
                if subscription_type.is_none() {
                    subscription_type = refreshed.subscription_type;
                }
                if rate_limit_tier.is_none() {
                    rate_limit_tier = refreshed.rate_limit_tier;
                }
            }
        }

        let access_token = access_token.ok_or_else(|| anyhow!("missing access_token"))?;
        if user_email.is_none()
            || account_uuid.is_none()
            || organization_uuid.is_none()
            || subscription_type.is_none()
            || rate_limit_tier.is_none()
        {
            let profile = fetch_oauth_profile(&access_token).await?;
            if user_email.is_none() {
                user_email = profile.email;
            }
            if account_uuid.is_none() {
                account_uuid = profile.account_uuid;
            }
            if organization_uuid.is_none() {
                organization_uuid = profile.organization_uuid;
            }
            if subscription_type.is_none() {
                subscription_type = profile.subscription_type;
            }
            if rate_limit_tier.is_none() {
                rate_limit_tier = profile.rate_limit_tier;
            }
        }

        Ok(CredentialUpsertInput {
            id: input
                .id
                .clone()
                .or_else(|| existing.as_ref().map(|item| item.id.clone())),
            enabled: input
                .enabled
                .or_else(|| existing.as_ref().map(|item| item.enabled)),
            order: input
                .order
                .or_else(|| existing.as_ref().map(|item| item.order)),
            access_token: Some(access_token),
            refresh_token,
            expires_at_unix_ms: Some(expires_at_unix_ms.unwrap_or(0)),
            enable_sonnet_1m: Some(enable_sonnet_1m),
            enable_opus_1m: Some(enable_opus_1m),
            user_email,
            account_uuid,
            organization_uuid,
            subscription_type,
            rate_limit_tier,
        })
    }

    async fn refresh_credential(
        &self,
        doc: &mut DurableStateDoc,
        credential: &CredentialConfig,
        force: bool,
    ) -> Result<Option<CredentialConfig>, RefreshError> {
        let refresh_target = if force {
            let mut forced = credential.clone();
            forced.expires_at_unix_ms = 0;
            forced
        } else {
            credential.clone()
        };

        match maybe_refresh_access_token(&refresh_target).await {
            Ok(Some(refreshed)) => Ok(Some(apply_refreshed_credential(doc, credential, refreshed))),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }

    async fn fetch_usage_snapshot(
        &self,
        doc: &mut DurableStateDoc,
        credential: &CredentialConfig,
    ) -> (CredentialConfig, CredentialUsageSnapshot) {
        let now = now_unix_ms();
        let mut active = credential.clone();

        match self.refresh_credential(doc, credential, false).await {
            Ok(Some(updated)) => active = updated,
            Ok(None) => {}
            Err(RefreshError::InvalidCredential(message)) => {
                record_invalid_auth(doc, &credential.id, now, message.clone());
                return (
                    current_credential(doc, &credential.id).unwrap_or_else(|| credential.clone()),
                    CredentialUsageSnapshot {
                        last_error: Some(message),
                        ..CredentialUsageSnapshot::default()
                    },
                );
            }
            Err(RefreshError::Transient(message)) => {
                return (
                    current_credential(doc, &credential.id).unwrap_or_else(|| credential.clone()),
                    CredentialUsageSnapshot {
                        last_error: Some(message),
                        ..CredentialUsageSnapshot::default()
                    },
                );
            }
        }

        match fetch_claudecode_usage(&active.access_token).await {
            Ok(usage) => (active, usage),
            Err(err) => {
                let message = err.to_string();
                if !usage_auth_failed(&message) {
                    return (
                        active,
                        CredentialUsageSnapshot {
                            last_error: Some(message),
                            ..CredentialUsageSnapshot::default()
                        },
                    );
                }

                match self.refresh_credential(doc, &active, true).await {
                    Ok(Some(updated)) => {
                        active = updated;
                        match fetch_claudecode_usage(&active.access_token).await {
                            Ok(usage) => (active, usage),
                            Err(err) => {
                                let retry_message = err.to_string();
                                if usage_auth_failed(&retry_message) {
                                    record_invalid_auth(
                                        doc,
                                        &active.id,
                                        now_unix_ms(),
                                        retry_message.clone(),
                                    );
                                }
                                (
                                    current_credential(doc, &active.id).unwrap_or(active),
                                    CredentialUsageSnapshot {
                                        last_error: Some(retry_message),
                                        ..CredentialUsageSnapshot::default()
                                    },
                                )
                            }
                        }
                    }
                    Ok(None) => (
                        active,
                        CredentialUsageSnapshot {
                            last_error: Some(message),
                            ..CredentialUsageSnapshot::default()
                        },
                    ),
                    Err(RefreshError::InvalidCredential(refresh_message)) => {
                        record_invalid_auth(
                            doc,
                            &active.id,
                            now_unix_ms(),
                            refresh_message.clone(),
                        );
                        (
                            current_credential(doc, &active.id).unwrap_or(active),
                            CredentialUsageSnapshot {
                                last_error: Some(refresh_message),
                                ..CredentialUsageSnapshot::default()
                            },
                        )
                    }
                    Err(RefreshError::Transient(refresh_message)) => (
                        active,
                        CredentialUsageSnapshot {
                            last_error: Some(format!(
                                "{message}; refresh failed: {refresh_message}"
                            )),
                            ..CredentialUsageSnapshot::default()
                        },
                    ),
                }
            }
        }
    }

    async fn build_usage_payload(
        &self,
        doc: &mut DurableStateDoc,
        only_id: Option<&str>,
    ) -> Vec<serde_json::Value> {
        let now = now_unix_ms();
        let mut items = Vec::new();
        let credential_ids = doc
            .credentials
            .iter()
            .filter(|item| item.channel == ACTIVE_CHANNEL)
            .filter(|item| only_id.is_none_or(|id| item.id == id))
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        for credential_id in credential_ids {
            let Some(credential) = current_credential(doc, &credential_id) else {
                continue;
            };
            let (view_credential, usage) = self.fetch_usage_snapshot(doc, &credential).await;
            let view = build_usage_view(&view_credential, usage, now);
            items.push(json!({
                "id": view.id,
                "user_email": view.user_email,
                "enabled": view.enabled,
                "order": view.order,
                "status": view.status,
                "cooldown_until_unix_ms": view.cooldown_until_unix_ms,
                "last_error": view.last_error,
                "last_used_at_unix_ms": view.last_used_at_unix_ms,
                "usage": view.usage,
                "json": credential.json_view(),
            }));
        }
        items
    }
}

fn apply_refreshed_credential(
    doc: &mut DurableStateDoc,
    credential: &CredentialConfig,
    refreshed: RefreshedCredential,
) -> CredentialConfig {
    upsert_credential(
        doc,
        CredentialUpsertInput {
            id: Some(credential.id.clone()),
            enabled: Some(credential.enabled),
            order: Some(credential.order),
            access_token: Some(refreshed.access_token),
            refresh_token: Some(refreshed.refresh_token),
            expires_at_unix_ms: Some(refreshed.expires_at_unix_ms),
            enable_sonnet_1m: Some(credential.enable_sonnet_1m),
            enable_opus_1m: Some(credential.enable_opus_1m),
            user_email: refreshed.user_email.or(credential.user_email.clone()),
            account_uuid: refreshed.account_uuid.or(credential.account_uuid.clone()),
            organization_uuid: refreshed
                .organization_uuid
                .or(credential.organization_uuid.clone()),
            subscription_type: refreshed
                .subscription_type
                .or_else(|| credential.subscription_type.clone()),
            rate_limit_tier: refreshed
                .rate_limit_tier
                .or_else(|| credential.rate_limit_tier.clone()),
        },
        Some(&credential.id),
        ACTIVE_CHANNEL,
    )
}

fn current_credential(doc: &DurableStateDoc, id: &str) -> Option<CredentialConfig> {
    doc.credentials.iter().find(|item| item.id == id).cloned()
}

fn clone_request(req: &Request) -> Result<Request> {
    Ok(Request::from(WebRequest::try_from(req)?))
}

fn usage_auth_failed(message: &str) -> bool {
    message.starts_with("oauth_usage_failed: status=401")
        || message.starts_with("oauth_usage_failed: status=403")
}

fn ensure_channel_credential(doc: &DurableStateDoc, channel: ChannelKind, id: &str) -> Result<()> {
    if doc
        .credentials
        .iter()
        .any(|item| item.channel == channel && item.id == id)
    {
        Ok(())
    } else {
        Err(anyhow!("credential not found: {id}"))
    }
}

fn provided_api_token(headers: &Headers) -> Option<String> {
    if let Some(token) = bearer_token(headers) {
        return Some(token);
    }
    headers
        .get("x-api-key")
        .ok()
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bearer_token(headers: &Headers) -> Option<String> {
    let header = headers.get("authorization").ok().flatten()?;
    let value = header.strip_prefix("Bearer ")?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn json_error(status: u16, message: &str) -> worker::Result<Response> {
    Response::from_json(&json!({ "error": message })).map(|resp| resp.with_status(status))
}
