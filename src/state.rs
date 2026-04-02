use anyhow::{Result, anyhow};
use rand::Rng as _;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use worker::Storage;

#[cfg(target_arch = "wasm32")]
use js_sys::Date;

use crate::config::{
    ChannelKind, CredentialConfig, CredentialStatus, CredentialUpsertInput,
    CredentialUsageSnapshot, DurableStateDoc, FIVE_HOUR_WINDOW_MS, SEVEN_DAY_WINDOW_MS,
    STORAGE_KEY, StoredOAuthState, UsageCredentialView, clean_opt_owned,
};

pub async fn load_doc(storage: &Storage) -> Result<DurableStateDoc> {
    let mut doc = storage
        .get::<DurableStateDoc>(STORAGE_KEY)
        .await?
        .unwrap_or_default();
    doc.normalize(now_unix_ms());
    Ok(doc)
}

pub async fn save_doc(storage: &Storage, doc: &DurableStateDoc) -> Result<()> {
    storage.put(STORAGE_KEY, doc).await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn now_unix_ms() -> u64 {
    Date::now().max(0.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn generate_credential_id() -> String {
    let mut bytes = [0u8; 10];
    rand::rng().fill_bytes(&mut bytes);
    let mut out = String::from("cred_");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub fn next_order(credentials: &[CredentialConfig], channel: ChannelKind) -> u32 {
    credentials
        .iter()
        .filter(|item| item.channel == channel)
        .map(|item| item.order)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

pub fn first_usable(
    credentials: &[CredentialConfig],
    channel: ChannelKind,
    now: u64,
) -> Option<CredentialConfig> {
    credentials
        .iter()
        .filter(|item| item.channel == channel)
        .filter(|item| item.enabled)
        .filter(|item| !matches!(item.status, CredentialStatus::Dead))
        .filter(|item| item.cooldown_until_unix_ms.is_none_or(|until| until <= now))
        .min_by_key(|item| item.order)
        .cloned()
}

pub fn upsert_credential(
    doc: &mut DurableStateDoc,
    input: CredentialUpsertInput,
    forced_id: Option<&str>,
    forced_channel: ChannelKind,
) -> CredentialConfig {
    let id = forced_id
        .map(ToString::to_string)
        .or(input.id.clone())
        .unwrap_or_else(generate_credential_id);
    let order = input
        .order
        .unwrap_or_else(|| next_order(&doc.credentials, forced_channel));
    let current = doc.credentials.iter().find(|item| item.id == id).cloned();

    let mut credential = CredentialConfig {
        id: id.clone(),
        channel: forced_channel,
        enabled: input
            .enabled
            .unwrap_or(current.as_ref().map(|item| item.enabled).unwrap_or(true)),
        order,
        access_token: input.access_token.unwrap_or_default(),
        refresh_token: input.refresh_token.unwrap_or_default(),
        expires_at_unix_ms: input.expires_at_unix_ms.unwrap_or(0),
        enable_sonnet_1m: input.enable_sonnet_1m.unwrap_or(
            current
                .as_ref()
                .map(|item| item.enable_sonnet_1m)
                .unwrap_or(true),
        ),
        enable_opus_1m: input.enable_opus_1m.unwrap_or(
            current
                .as_ref()
                .map(|item| item.enable_opus_1m)
                .unwrap_or(true),
        ),
        user_email: clean_opt_owned(input.user_email),
        account_uuid: clean_opt_owned(input.account_uuid),
        organization_uuid: clean_opt_owned(input.organization_uuid),
        subscription_type: clean_opt_owned(input.subscription_type),
        rate_limit_tier: clean_opt_owned(input.rate_limit_tier),
        status: CredentialStatus::Healthy,
        cooldown_until_unix_ms: None,
        last_error: None,
        last_used_at_unix_ms: None,
    };

    if let Some(existing) = current {
        credential.status = existing.status;
        credential.cooldown_until_unix_ms = existing.cooldown_until_unix_ms;
        credential.last_error = existing.last_error;
        credential.last_used_at_unix_ms = existing.last_used_at_unix_ms;
        if let Some(item) = doc.credentials.iter_mut().find(|item| item.id == id) {
            *item = credential.clone();
        }
    } else {
        doc.credentials.push(credential.clone());
    }

    credential
}

pub fn delete_credential(doc: &mut DurableStateDoc, id: &str) -> Result<()> {
    let before = doc.credentials.len();
    doc.credentials.retain(|item| item.id != id);
    if before == doc.credentials.len() {
        return Err(anyhow!("credential not found: {id}"));
    }
    Ok(())
}

pub fn set_enabled(doc: &mut DurableStateDoc, id: &str, enabled: bool) -> Result<CredentialConfig> {
    let item = doc
        .credentials
        .iter_mut()
        .find(|item| item.id == id)
        .ok_or_else(|| anyhow!("credential not found: {id}"))?;
    item.enabled = enabled;
    Ok(item.clone())
}

pub fn apply_1m_probe_result(
    doc: &mut DurableStateDoc,
    id: &str,
    disable_sonnet_1m: bool,
    disable_opus_1m: bool,
) -> Option<CredentialConfig> {
    let item = doc.credentials.iter_mut().find(|item| item.id == id)?;
    if disable_sonnet_1m {
        item.enable_sonnet_1m = false;
    }
    if disable_opus_1m {
        item.enable_opus_1m = false;
    }
    Some(item.clone())
}

pub fn record_success(doc: &mut DurableStateDoc, id: &str, now: u64) {
    if let Some(item) = doc.credentials.iter_mut().find(|item| item.id == id) {
        item.last_used_at_unix_ms = Some(now);
        item.last_error = None;
        if item.status != CredentialStatus::Dead {
            item.status = CredentialStatus::Healthy;
            item.cooldown_until_unix_ms = None;
        }
    }
}

pub fn record_invalid_auth(doc: &mut DurableStateDoc, id: &str, now: u64, message: String) {
    if let Some(item) = doc.credentials.iter_mut().find(|item| item.id == id) {
        item.last_used_at_unix_ms = Some(now);
        item.status = CredentialStatus::Dead;
        item.cooldown_until_unix_ms = None;
        item.last_error = Some(message);
    }
}

pub fn record_transient(doc: &mut DurableStateDoc, id: &str, now: u64, message: String) {
    if let Some(item) = doc.credentials.iter_mut().find(|item| item.id == id) {
        item.last_used_at_unix_ms = Some(now);
        item.last_error = Some(message);
    }
}

pub fn record_rate_limited(
    doc: &mut DurableStateDoc,
    id: &str,
    now: u64,
    usage: Option<&CredentialUsageSnapshot>,
    usage_error: Option<String>,
) {
    if let Some(item) = doc.credentials.iter_mut().find(|item| item.id == id) {
        item.last_used_at_unix_ms = Some(now);
        item.last_error =
            Some(usage_error.unwrap_or_else(|| "upstream returned status 429".to_string()));
        let (status, cooldown_until_unix_ms) =
            derive_rate_limited_status(usage.unwrap_or(&CredentialUsageSnapshot::default()), now);
        item.status = status;
        item.cooldown_until_unix_ms = cooldown_until_unix_ms;
    }
}

pub fn merge_status_for_view(
    credential: &CredentialConfig,
    usage: &CredentialUsageSnapshot,
    now: u64,
) -> (CredentialStatus, Option<u64>, Option<String>) {
    if let Some((status, until)) = exact_usage_status(usage, now) {
        return (
            status,
            until,
            credential.last_error.clone().or(usage.last_error.clone()),
        );
    }
    (
        credential.status,
        credential.cooldown_until_unix_ms,
        credential.last_error.clone().or(usage.last_error.clone()),
    )
}

pub fn build_usage_view(
    credential: &CredentialConfig,
    usage: CredentialUsageSnapshot,
    now: u64,
) -> UsageCredentialView {
    let (status, cooldown_until_unix_ms, last_error) =
        merge_status_for_view(credential, &usage, now);
    UsageCredentialView {
        id: credential.id.clone(),
        user_email: credential.user_email.clone(),
        enabled: credential.enabled,
        order: credential.order,
        status,
        cooldown_until_unix_ms,
        last_error,
        last_used_at_unix_ms: credential.last_used_at_unix_ms,
        usage,
    }
}

pub fn insert_oauth_state(doc: &mut DurableStateDoc, state: StoredOAuthState) {
    doc.oauth_states
        .retain(|item| item.channel != state.channel);
    doc.oauth_states.push(state);
}

pub fn take_oauth_state(
    doc: &mut DurableStateDoc,
    channel: ChannelKind,
    requested_state: Option<&str>,
) -> Result<StoredOAuthState> {
    let now = now_unix_ms();
    doc.normalize(now);

    if let Some(state_id) = requested_state {
        let index = doc
            .oauth_states
            .iter()
            .position(|item| item.channel == channel && item.state_id == state_id)
            .ok_or_else(|| anyhow!("missing state"))?;
        return Ok(doc.oauth_states.remove(index));
    }

    let matching = doc
        .oauth_states
        .iter()
        .enumerate()
        .filter(|(_, item)| item.channel == channel)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Err(anyhow!("missing state"));
    }
    if matching.len() > 1 {
        return Err(anyhow!("ambiguous_state"));
    }
    Ok(doc.oauth_states.remove(matching[0]))
}

fn derive_rate_limited_status(
    usage: &CredentialUsageSnapshot,
    now: u64,
) -> (CredentialStatus, Option<u64>) {
    exact_usage_status(usage, now).unwrap_or((
        CredentialStatus::Cooldown5h,
        Some(now.saturating_add(FIVE_HOUR_WINDOW_MS)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_oauth_state(state_id: &str, channel: ChannelKind) -> StoredOAuthState {
        StoredOAuthState {
            channel,
            state_id: state_id.to_string(),
            code_verifier: format!("verifier_{state_id}"),
            redirect_uri: "https://platform.claude.com/oauth/code/callback".to_string(),
            created_at_unix_ms: now_unix_ms(),
        }
    }

    #[test]
    fn insert_oauth_state_replaces_existing_state_for_same_channel() {
        let mut doc = DurableStateDoc::default();
        insert_oauth_state(
            &mut doc,
            sample_oauth_state("old_state", ChannelKind::ClaudeCode),
        );
        insert_oauth_state(
            &mut doc,
            sample_oauth_state("new_state", ChannelKind::ClaudeCode),
        );

        assert_eq!(doc.oauth_states.len(), 1);
        assert_eq!(doc.oauth_states[0].state_id, "new_state");
    }

    #[test]
    fn take_oauth_state_without_requested_state_uses_latest_single_state() {
        let mut doc = DurableStateDoc::default();
        insert_oauth_state(
            &mut doc,
            sample_oauth_state("old_state", ChannelKind::ClaudeCode),
        );
        insert_oauth_state(
            &mut doc,
            sample_oauth_state("new_state", ChannelKind::ClaudeCode),
        );

        let state = take_oauth_state(&mut doc, ChannelKind::ClaudeCode, None).unwrap();

        assert_eq!(state.state_id, "new_state");
        assert!(doc.oauth_states.is_empty());
    }

    #[test]
    fn parse_unix_ms_supports_seconds_timestamps() {
        assert_eq!(parse_unix_ms(Some("1775116800")), Some(1_775_116_800_000));
    }
}

fn exact_usage_status(
    usage: &CredentialUsageSnapshot,
    now: u64,
) -> Option<(CredentialStatus, Option<u64>)> {
    if usage.seven_day.utilization_pct == Some(100) {
        return Some((
            CredentialStatus::Cooldown7d,
            bucket_reset_or(
                &usage.seven_day.resets_at,
                now.saturating_add(SEVEN_DAY_WINDOW_MS),
            ),
        ));
    }
    if usage.seven_day_sonnet.utilization_pct == Some(100) {
        return Some((
            CredentialStatus::Cooldown7d,
            bucket_reset_or(
                &usage.seven_day_sonnet.resets_at,
                now.saturating_add(SEVEN_DAY_WINDOW_MS),
            ),
        ));
    }
    if usage.five_hour.utilization_pct == Some(100) {
        return Some((
            CredentialStatus::Cooldown5h,
            bucket_reset_or(
                &usage.five_hour.resets_at,
                now.saturating_add(FIVE_HOUR_WINDOW_MS),
            ),
        ));
    }
    None
}

fn bucket_reset_or(resets_at: &Option<String>, fallback: u64) -> Option<u64> {
    parse_unix_ms(resets_at.as_deref()).or(Some(fallback))
}

fn parse_unix_ms(raw: Option<&str>) -> Option<u64> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(value) = raw.parse::<u64>() {
        return Some(if value < 1_000_000_000_000 {
            value.checked_mul(1000)?
        } else {
            value
        });
    }
    let value = OffsetDateTime::parse(raw, &Rfc3339).ok()?;
    let unix_ms = value.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(unix_ms).ok()
}
