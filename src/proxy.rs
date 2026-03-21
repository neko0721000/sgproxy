use anyhow::Result;
use url::Url;
use worker::{Fetch, Headers, Request, RequestInit, Response};

use crate::config::{
    CredentialConfig, DEFAULT_ANTHROPIC_VERSION, DEFAULT_BASE_URL, DEFAULT_REQUIRED_BETA,
    DEFAULT_USER_AGENT,
};

pub struct ProxyOutcome {
    pub response: Response,
    pub status_code: u16,
}

pub async fn proxy_request(req: Request, credential: &CredentialConfig) -> Result<ProxyOutcome> {
    let upstream_url = build_upstream_url(&req)?;
    let headers = build_upstream_headers(req.headers(), credential.access_token.as_str())?;

    let mut init = RequestInit::new();
    init.with_method(req.method()).with_headers(headers);
    if let Some(body) = req.inner().body() {
        init.with_body(Some(body.into()));
    }

    let upstream_req = Request::new_with_init(upstream_url.as_str(), &init)?;
    let upstream_resp = Fetch::Request(upstream_req).send().await?;
    let status_code = upstream_resp.status_code();
    let response_headers = filter_response_headers(upstream_resp.headers())?;
    let (_, body) = upstream_resp.into_parts();
    let response = Response::builder()
        .with_status(status_code)
        .with_headers(response_headers)
        .body(body);

    Ok(ProxyOutcome {
        response,
        status_code,
    })
}

fn build_upstream_url(req: &Request) -> Result<Url> {
    let source = req.url()?;
    let mut target = Url::parse(DEFAULT_BASE_URL)?;
    target.set_path(source.path());
    target.set_query(source.query());
    Ok(target)
}

fn build_upstream_headers(original: &Headers, access_token: &str) -> Result<Headers> {
    let headers = Headers::new();
    let mut seen_user_agent = false;
    let mut seen_anthropic_version = false;
    let mut beta_values = Vec::new();

    for (name, value) in original.entries() {
        let lower = name.to_ascii_lowercase();
        if is_hop_by_hop(&lower)
            || matches!(
                lower.as_str(),
                "host" | "content-length" | "authorization" | "cookie"
            )
        {
            continue;
        }
        if lower == "anthropic-beta" {
            collect_beta_values(&value, &mut beta_values);
            continue;
        }
        if lower == "user-agent" {
            seen_user_agent = true;
        }
        if lower == "anthropic-version" {
            seen_anthropic_version = true;
        }
        headers.append(&name, &value)?;
    }

    collect_beta_values(DEFAULT_REQUIRED_BETA, &mut beta_values);
    headers.set("authorization", &format!("Bearer {access_token}"))?;
    if !seen_user_agent {
        headers.set("user-agent", DEFAULT_USER_AGENT)?;
    }
    if !seen_anthropic_version {
        headers.set("anthropic-version", DEFAULT_ANTHROPIC_VERSION)?;
    }
    if !beta_values.is_empty() {
        headers.set("anthropic-beta", &beta_values.join(","))?;
    }
    Ok(headers)
}

fn filter_response_headers(original: &Headers) -> Result<Headers> {
    let headers = Headers::new();
    for (name, value) in original.entries() {
        if is_hop_by_hop(&name) {
            continue;
        }
        headers.append(&name, &value)?;
    }
    Ok(headers)
}

fn collect_beta_values(raw: &str, target: &mut Vec<String>) {
    for value in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !target.iter().any(|item| item == value) {
            target.push(value.to_string());
        }
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
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
