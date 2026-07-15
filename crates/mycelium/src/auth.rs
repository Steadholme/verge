//! Gateway-injected identity + double-submit CSRF.
//!
//! Mycelium does NO login of its own. It sits behind a Sluice `auth=sso` route, where the
//! gateway runs the OIDC browser login against Keystone, STRIPS any inbound `X-Auth-*`, and
//! injects the verified `X-Auth-Subject` / `X-Auth-Email` / `X-Auth-Scope`. Because Mycelium is
//! internal-only (never publicly reachable), it TRUSTS those headers as the authenticated mesh
//! operator — the device owner is ALWAYS taken from the gateway headers, never from a
//! client-supplied field.
//!
//! State-changing POSTs (enroll / revoke / add-ACL) are double-submit CSRF protected: a random
//! token lives in a `__Host-csrf` cookie AND in a hidden form field; the POST is accepted only
//! when the two match. The token is minted once and REUSED across page renders.

use axum::http::{header, HeaderMap};

use crate::error::AppError;

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";
pub const HEADER_SCOPE: &str = "x-auth-scope";

/// Double-submit CSRF cookie. `__Host-` prefix => Secure + Path=/ + no Domain, so the browser
/// only ever returns it over TLS to this exact host.
pub const CSRF_COOKIE: &str = "__Host-csrf";
/// CSRF cookie lifetime, seconds.
const CSRF_TTL: u64 = 3600;

/// The authenticated operator's subject (stable user id), if the gateway injected one.
pub fn subject(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_SUBJECT)
}

/// The authenticated operator's email, if the gateway injected one.
pub fn email(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_EMAIL)
}

/// The operator's email for display, falling back to a neutral label when unauthenticated.
pub fn display_email(headers: &HeaderMap) -> String {
    email(headers).unwrap_or_else(|| "—".to_string())
}

/// Require an authenticated operator. Returns `(subject, email)`, or `Unauthorized` when no SSO
/// identity is present — defense in depth behind the gateway.
pub fn require_operator(headers: &HeaderMap) -> Result<(String, String), AppError> {
    let sub = subject(headers).ok_or_else(|| {
        AppError::Unauthorized("no gateway SSO identity (X-Auth-Subject missing)".to_string())
    })?;
    let mail = email(headers).unwrap_or_default();
    Ok((sub, mail))
}

// ---------------------------------------------------------------------------
// Gateway identity signature (X-Auth-Sig) verification
// ---------------------------------------------------------------------------
//
// Mycelium sits behind a Sluice `auth=sso` route, which STRIPS inbound `X-Auth-*` and re-injects
// verified headers plus an HMAC `X-Auth-Sig` (when GATEWAY_HMAC_KEY is configured). A rogue peer
// reaching Mycelium's port directly (bypassing Sluice) could otherwise forge `X-Auth-Subject` to
// satisfy `require_operator` and enroll/revoke mesh peers. `require_gateway_sig` rejects any
// request whose injected identity is unsigned or invalid; the anonymous read-only dashboard and
// `/healthz` (no identity header) still pass.

pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC binding the injected identity to a 1-minute window (set by Sluice when GATEWAY_HMAC_KEY set).
pub const HEADER_SIG: &str = "x-auth-sig";

/// The shared gateway HMAC key, read once from `GATEWAY_HMAC_KEY`. Empty (unset) disables
/// verification — the pre-signature behavior, fully backward compatible (local dev / tests).
fn gateway_key() -> &'static str {
    use std::sync::OnceLock;
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| std::env::var("GATEWAY_HMAC_KEY").unwrap_or_default())
        .as_str()
}

/// Whether the gateway-injected identity is authentic. When `GATEWAY_HMAC_KEY` is set and ANY
/// identity header is present, a valid `X-Auth-Sig` — HMAC-SHA256 over `subject "\n" groups "\n"
/// minute` for the current OR previous minute — is required. `true` when the key is unset, or no
/// identity header is present, or the signature is valid; `false` when an identity is present but
/// the signature is missing/invalid.
pub fn gateway_identity_ok(headers: &HeaderMap) -> bool {
    gateway_identity_ok_with(gateway_key(), headers)
}

fn gateway_identity_ok_with(key: &str, headers: &HeaderMap) -> bool {
    if key.is_empty() {
        return true;
    }
    let subject = header_value(headers, HEADER_SUBJECT).unwrap_or_default();
    let groups = header_value(headers, HEADER_GROUPS).unwrap_or_default();
    let has_email = header_value(headers, HEADER_EMAIL).is_some();
    if subject.is_empty() && groups.is_empty() && !has_email {
        return true; // no injected identity to verify (anonymous dashboard / healthz / dev)
    }
    let Some(sig) = header_value(headers, HEADER_SIG) else {
        return false; // identity present but unsigned — reject
    };
    let win = crate::now_secs() / 60;
    [win, win - 1]
        .iter()
        .any(|&w| ct_eq(sig.as_bytes(), sign_identity(key, &subject, &groups, w).as_bytes()))
}

/// Middleware rejecting a forged gateway identity with 401. No-op when the key is unset or no
/// identity is present.
pub async fn require_gateway_sig(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if gateway_identity_ok(req.headers()) {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid or missing gateway identity signature",
        )
            .into_response()
    }
}

/// Recompute the gateway signature — byte-identical to Sluice's `auth.SignIdentity` (Go) and the
/// rest of the estate (portal/familiar/...). The cross-language contract is pinned by test.
fn sign_identity(key: &str, subject: &str, groups: &str, window: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key len");
    mac.update(subject.as_bytes());
    mac.update(b"\n");
    mac.update(groups.as_bytes());
    mac.update(b"\n");
    mac.update(window.to_string().as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

/// Read a single cookie value from the request's `Cookie` header(s).
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = hv.to_str() else { continue };
        for pair in raw.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// `Set-Cookie` value for the CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

// ---------------------------------------------------------------------------
// CSRF (double-submit)
// ---------------------------------------------------------------------------

/// Mint a fresh CSRF token: 32 CSPRNG bytes, hex-encoded.
pub fn new_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Resolve the CSRF token to embed in this render's forms. Reuses the existing cookie token when
/// present (so it is stable across pages/tabs); otherwise mints one and returns the matching
/// `Set-Cookie` to attach to the response.
pub fn ensure_csrf(headers: &HeaderMap) -> (String, Option<String>) {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(c) if !c.is_empty() => (c, None),
        _ => {
            let token = new_csrf_token();
            let set = csrf_cookie(&token);
            (token, Some(set))
        }
    }
}

/// Double-submit check: the `submitted` form token must equal the `__Host-csrf` cookie.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> Result<(), AppError> {
    let ok = match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() => ct_eq(cookie.as_bytes(), submitted.as_bytes()),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(AppError::Unauthorized("CSRF token mismatch".to_string()))
    }
}

/// Length-checked constant-time byte comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_token_is_random_and_hex() {
        let a = new_csrf_token();
        let b = new_csrf_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn csrf_double_submit_matches_and_rejects() {
        let token = new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        assert!(verify_csrf(&headers, &token).is_ok());
        assert!(verify_csrf(&headers, "not-the-token").is_err());
        assert!(verify_csrf(&HeaderMap::new(), &token).is_err());
    }

    #[test]
    fn require_operator_needs_subject() {
        assert!(require_operator(&HeaderMap::new()).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_SUBJECT, "u_123".parse().unwrap());
        headers.insert(HEADER_EMAIL, "a@steadholme.local".parse().unwrap());
        let (sub, mail) = require_operator(&headers).unwrap();
        assert_eq!(sub, "u_123");
        assert_eq!(mail, "a@steadholme.local");
    }

    #[test]
    fn sign_identity_matches_go_vector() {
        // MUST equal sluice/internal/auth/sig_test.go (and portal/familiar) — the cross-lang contract.
        assert_eq!(
            sign_identity("test-key", "usr_alice", "admins,devs", 1),
            "ddc77236dcfb03dd9f462f7c84e1b25e58f5fc380997695a689e6c3ac4bb3777"
        );
        assert_eq!(
            sign_identity("test-key", "usr_bob", "", 2),
            "930f82fb1224e69c9c5bc46e545c3b108b1eeb6c9078c7a33fc24f30c595f658"
        );
    }

    #[test]
    fn gateway_rejects_forged_identity() {
        // C4: key set + forged subject without sig => reject (would otherwise satisfy require_operator).
        let mut forged = HeaderMap::new();
        forged.insert(HEADER_SUBJECT, "usr_eve".parse().unwrap());
        assert!(!gateway_identity_ok_with("test-key", &forged));
        // Anonymous (no identity headers) => ok even with key set (read-only dashboard / healthz).
        assert!(gateway_identity_ok_with("test-key", &HeaderMap::new()));
        // Valid signature => accept.
        let win = crate::now_secs() / 60;
        let sig = sign_identity("test-key", "usr_alice", "", win);
        let mut ok = HeaderMap::new();
        ok.insert(HEADER_SUBJECT, "usr_alice".parse().unwrap());
        ok.insert(HEADER_SIG, sig.parse().unwrap());
        assert!(gateway_identity_ok_with("test-key", &ok));
    }
}
