//! IAM-gated Clash profile page, short-lived link issuance, and public token download.

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::clash::{TokenError, PROFILE_FILENAME, SUBSCRIPTION_TTL_SECONDS};
use crate::error::AppError;
use crate::handlers::{app_css, esc, topbar};
use crate::{now_secs, AppState};

const PROFILE_HTML: &str = include_str!("../../templates/profile.html");
const SUBSCRIPTION_HTML: &str = include_str!("../../templates/subscription.html");
const DASHBOARD_JS: &str = include_str!("../../static/dashboard.js");

#[derive(Debug, Deserialize)]
pub struct SubscriptionForm {
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct SubscriptionQuery {
    #[serde(default)]
    pub token: String,
}

/// `GET /static/dashboard.js` — progressively reveals the VPN Profile card after Sluice confirms
/// the separate `vpn.profile.subscribe` permission on `/api/clash/capability`.
pub async fn dashboard_js() -> Response {
    let mut response = (StatusCode::OK, DASHBOARD_JS).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

/// `GET /api/clash/capability` — the body is intentionally empty. The enclosing Sluice route is
/// the actual PEP; a 204 means Verdict allowed `vpn.profile.subscribe` for this subject.
pub async fn capability(headers: HeaderMap) -> Result<Response, AppError> {
    auth::require_operator(&headers)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    no_store_headers(&mut response);
    Ok(response)
}

/// `GET /profiles` — the independent VPN Profile surface. It is routed by Sluice under
/// `vpn.profile.subscribe`, not the WireGuard console's `vpn.console.enter` permission.
pub async fn profile_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_subject, email) = auth::require_operator(&headers)?;
    if state.clash.is_none() {
        return Err(AppError::Unavailable(
            "Clash subscriptions are not configured".to_string(),
        ));
    }
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let page = PROFILE_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{TOPBAR}}", &topbar("VPN Profile", &email))
        .replace("{{CSRF}}", &esc(&csrf))
        .replace(
            "{{TTL_MINUTES}}",
            &(SUBSCRIPTION_TTL_SECONDS / 60).to_string(),
        );
    Ok(html_with_cookie(page, set_cookie))
}

/// `POST /api/clash/subscription-link` — issue an opaque bearer URL valid for exactly ten
/// minutes. Sluice performs the permission decision; the handler still requires a signed gateway
/// identity and double-submit CSRF before minting.
pub async fn issue_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SubscriptionForm>,
) -> Result<Response, AppError> {
    let (subject, email) = auth::require_operator(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;
    let clash = state.clash.as_ref().ok_or_else(|| {
        AppError::Unavailable("Clash subscriptions are not configured".to_string())
    })?;
    let (token, expires_at) = clash.mint(now_secs()).map_err(AppError::Internal)?;
    let url = clash.download_url(&token);

    let actor = if email.is_empty() { &subject } else { &email };
    state.audit.emit(AuditEvent::info(
        "mycelium.clash-subscription.issue",
        actor,
        "vpn-profile:clash",
        &format!("expires_at={expires_at}"),
    ));

    let page = SUBSCRIPTION_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{TOPBAR}}", &topbar("VPN Profile", &email))
        .replace("{{URL}}", &esc(&url))
        .replace("{{EXPIRES_AT}}", &expires_at.to_string())
        .replace(
            "{{TTL_MINUTES}}",
            &(SUBSCRIPTION_TTL_SECONDS / 60).to_string(),
        );
    let mut response = Html(page).into_response();
    no_store_headers(&mut response);
    Ok(response)
}

/// `GET /subscription/clash?token=...` — public-by-route because Clash cannot use the browser SSO
/// cookie. The HMAC token is the sole capability; invalid and expired tokens reveal no profile
/// bytes and all responses are non-cacheable.
pub async fn download(
    State(state): State<AppState>,
    Query(query): Query<SubscriptionQuery>,
) -> Response {
    let Some(clash) = state.clash.as_ref() else {
        return plain_error(StatusCode::NOT_FOUND, "not found");
    };
    match clash.verify(&query.token, now_secs()) {
        Ok(()) => {}
        Err(TokenError::Expired) => return plain_error(StatusCode::GONE, "subscription expired"),
        Err(TokenError::Invalid) => return plain_error(StatusCode::FORBIDDEN, "forbidden"),
    }

    let mut response = Response::new(Body::from(clash.profile().to_vec()));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/yaml; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{PROFILE_FILENAME}\""))
            .expect("static profile filename is a valid header"),
    );
    no_store_headers(&mut response);
    response
}

fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut response = Html(body).into_response();
    if let Some(cookie) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    no_store_headers(&mut response);
    response
}

fn plain_error(status: StatusCode, message: &'static str) -> Response {
    let mut response = (status, message).into_response();
    no_store_headers(&mut response);
    response
}

fn no_store_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("pragma", HeaderValue::from_static("no-cache"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}
