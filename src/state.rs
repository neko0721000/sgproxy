use anyhow::{Result, anyhow};
use js_sys::Date;
use rand::Rng as _;
use worker::Storage;

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

pub fn now_unix_ms() -> u64 {
    Date::now().max(0.0) as u64
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
        .retain(|item| !(item.channel == state.channel && item.state_id == state.state_id));
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
            CredentialStatus::CooldownSonnet7d,
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
    let value = Date::parse(raw);
    (value.is_finite() && value >= 0.0).then_some(value as u64)
}
