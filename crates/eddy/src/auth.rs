//! Gateway-injected identity + double-submit CSRF.
//!
//! Eddy does NO login of its own. The console sits behind a Sluice `auth=sso` route, where the
//! gateway runs the OIDC browser login against Keystone, STRIPS any inbound `X-Auth-*`, and injects
//! the verified `X-Auth-Subject` / `X-Auth-Email`. Because Eddy is internal-only it TRUSTS those
//! headers as the operator identity (falling back to a dev identity only when none are present, so
//! it still runs DB-free locally and in tests).
//!
//! State-changing POSTs (add asset / purge) are double-submit CSRF protected: a random token lives
//! in a JS-readable `__Host-csrf` cookie AND in the submitted form; the POST is accepted only when
//! the two match.

use axum::http::{header, HeaderMap};

use crate::random_alnum;

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";

/// Dev/test fallback identity used ONLY when no gateway headers are present (local `cargo run` or
/// the DB-free test suite). In production every console request arrives with `X-Auth-*` injected.
pub const DEV_SUBJECT: &str = "dev-user";
pub const DEV_EMAIL: &str = "dev@eddy.local";

/// Double-submit CSRF cookie. `__Host-` prefix => Secure + Path=/ + no Domain, so the browser only
/// ever returns it over TLS to this exact host.
pub const CSRF_COOKIE: &str = "__Host-csrf";
/// CSRF cookie lifetime, seconds.
const CSRF_TTL: u64 = 3600;
/// CSRF token length (characters from the 62-symbol alphabet ~= 238 bits).
const CSRF_LEN: usize = 40;

/// The authenticated console operator. Subject is the stable id; email is display-only.
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
    pub email: String,
}

/// Resolve the current operator from the gateway-injected headers, falling back to the dev identity
/// when none are present. Behind a configured gateway the console routes are guarded by
/// [`require_console_identity`], so this dev fallback is only ever reached in local dev (no
/// `GATEWAY_HMAC_KEY`) — never by a rogue peer hitting Eddy directly in production.
pub fn identity(headers: &HeaderMap) -> Identity {
    Identity {
        subject: header_value(headers, HEADER_SUBJECT).unwrap_or_else(|| DEV_SUBJECT.to_string()),
        email: header_value(headers, HEADER_EMAIL).unwrap_or_else(|| DEV_EMAIL.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Gateway identity signature (X-Auth-Sig) verification
// ---------------------------------------------------------------------------
//
// Eddy's console/API sit behind a Sluice `auth=sso` route, which STRIPS inbound `X-Auth-*` and
// re-injects verified headers plus an HMAC `X-Auth-Sig` (when GATEWAY_HMAC_KEY is configured). A
// rogue peer that reaches Eddy's port directly (bypassing Sluice) could otherwise forge
// `X-Auth-Subject` — or send no identity at all and ride the dev fallback. `require_console_identity`
// rejects any console request that is unsigned, and (in production) any with no identity, so the
// dev fallback in `identity` is unreachable behind a configured gateway.

pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC binding the injected identity to a 1-minute window (set by Sluice when GATEWAY_HMAC_KEY
/// is configured).
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
/// identity header (`X-Auth-Subject` / `X-Auth-Groups` / `X-Auth-Email`) is present, a valid
/// `X-Auth-Sig` — HMAC-SHA256 over `subject "\n" groups "\n" minute` for the current OR previous
/// minute — is required. `true` when the key is unset, or no identity header is present, or the
/// signature is valid; `false` when an identity is present but the signature is missing/invalid.
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
        return true; // no injected identity to verify (public route / healthz / local dev)
    }
    let Some(sig) = header_value(headers, HEADER_SIG) else {
        return false; // identity present but unsigned — reject
    };
    let win = crate::now_secs() / 60;
    [win, win - 1]
        .iter()
        .any(|&w| ct_eq(sig.as_bytes(), sign_identity(key, &subject, &groups, w).as_bytes()))
}

/// Stricter gate for the SSO console + management API: in production (key set) the request MUST
/// carry a valid, signed `X-Auth-Subject`. This closes the dev-identity fallback for anyone who
/// reaches Eddy directly. In dev (key unset) it is a no-op so the DB-free console still runs.
fn gateway_console_ok_with(key: &str, headers: &HeaderMap) -> bool {
    if key.is_empty() {
        return true;
    }
    if header_value(headers, HEADER_SUBJECT).is_none() {
        return false; // production console demands a gateway identity — no dev fallback
    }
    gateway_identity_ok_with(key, headers)
}

/// Middleware guarding the console/API routes: 401 unless [`gateway_console_ok_with`] passes for
/// the process key. No-op in dev (key unset) and for public routes (which are not layered).
pub async fn require_console_identity(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if gateway_console_ok_with(gateway_key(), req.headers()) {
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
    hex::encode(mac.finalize().into_bytes())
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
// CSRF (double-submit)
// ---------------------------------------------------------------------------

/// Mint a fresh CSRF token (same value goes in the cookie and the form field).
pub fn new_csrf_token() -> String {
    random_alnum(CSRF_LEN)
}

/// `Set-Cookie` value for the (JS-readable) CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

/// Double-submit check: the `submitted` form token must equal the `__Host-csrf` cookie.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> bool {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() => ct_eq(cookie.as_bytes(), submitted.as_bytes()),
        _ => false,
    }
}

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

/// Length-checked constant-time byte comparison (no early return on the first differing byte).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
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
    use axum::http::HeaderValue;

    #[test]
    fn identity_falls_back_to_dev() {
        let id = identity(&HeaderMap::new());
        assert_eq!(id.subject, DEV_SUBJECT);
        assert_eq!(id.email, DEV_EMAIL);
    }

    #[test]
    fn identity_reads_gateway_headers() {
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("u_admin"));
        h.insert(HEADER_EMAIL, HeaderValue::from_static("a@w33d.xyz"));
        let id = identity(&h);
        assert_eq!(id.subject, "u_admin");
        assert_eq!(id.email, "a@w33d.xyz");
    }

    #[test]
    fn csrf_double_submit() {
        let token = new_csrf_token();
        assert_eq!(token.len(), CSRF_LEN);
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        assert!(verify_csrf(&h, &token));
        assert!(!verify_csrf(&h, "not-the-token"));
        assert!(!verify_csrf(&HeaderMap::new(), &token));
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
    fn console_rejects_forged_and_unsigned() {
        // C4: key set + forged subject, no sig => reject.
        let mut sub = HeaderMap::new();
        sub.insert(HEADER_SUBJECT, HeaderValue::from_static("usr_eve"));
        assert!(!gateway_console_ok_with("test-key", &sub));
        // key set + groups-only, no subject => reject (no dev fallback in prod).
        let mut grp = HeaderMap::new();
        grp.insert(HEADER_GROUPS, HeaderValue::from_static("admins"));
        assert!(!gateway_console_ok_with("test-key", &grp));
        // valid signature => accept.
        let win = crate::now_secs() / 60;
        let sig = sign_identity("test-key", "usr_alice", "", win);
        let mut ok = HeaderMap::new();
        ok.insert(HEADER_SUBJECT, HeaderValue::from_static("usr_alice"));
        ok.insert(HEADER_SIG, HeaderValue::from_str(&sig).unwrap());
        assert!(gateway_console_ok_with("test-key", &ok));
    }

    #[test]
    fn console_open_in_dev_without_key() {
        // key unset => dev fallback path stays open (DB-free local console/tests).
        assert!(gateway_console_ok_with("", &HeaderMap::new()));
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("dev"));
        assert!(gateway_console_ok_with("", &h));
    }
}
