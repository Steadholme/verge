//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `devices` carries the SSO-gated admin
//! dashboard and the enroll / revoke / ACL / config-render flow.
//!
//! Odyssey canonical CSS plus Mycelium service CSS are embedded and served as one versioned,
//! immutable stylesheet.

pub mod clash;
pub mod devices;
pub mod health;

use std::sync::OnceLock;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::IntoResponse;

/// Mycelium-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

/// Versioned stylesheet URL. Change the date whenever the embedded CSS changes.
pub const APP_CSS_PATH: &str = "/assets/mycelium-20260908.css";

static APP_CSS: OnceLock<String> = OnceLock::new();

/// Embedded design system, assembled once per process.
pub fn app_css() -> &'static str {
    APP_CSS
        .get_or_init(|| {
            let mut css = String::with_capacity(odyssey::APP_CSS.len() + SERVICE_CSS.len());
            css.push_str(odyssey::APP_CSS);
            css.push_str(SERVICE_CSS);
            css
        })
        .as_str()
}

/// Identity-independent stylesheet with an immutable one-year cache policy.
pub async fn app_css_asset() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
        ],
        app_css(),
    )
}

/// Cross-subdomain gateway logout (Mycelium lives at mesh.w33d.xyz; the IdP is at id.w33d.xyz).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// 24px stroke icons (Figma Icon/UI sheet).
pub const ICON_NETWORK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M5 16v-2a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v2"/></svg>"#;
pub const ICON_CLOUD: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.5 19H7a4 4 0 0 1-.7-7.9A5.5 5.5 0 0 1 17 9.5h.5a4.75 4.75 0 0 1 0 9.5Z"/></svg>"#;
pub const ICON_SHIELD: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.5 8.6 8 11 4.5-2.4 8-6 8-11V5l-8-3Z"/></svg>"#;
pub const ICON_GRID: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"#;
pub const ICON_PLUS: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>"#;
pub const ICON_KEY: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 9.2-9.2M15 8l3 3M18 5l2 2"/></svg>"#;
pub const ICON_CHECK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 5 5L20 7"/></svg>"#;
pub const ICON_CLOCK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7.6V12l3 1.8"/></svg>"#;
pub const ICON_ARROW: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg>"#;
pub const ICON_ARROW_LEFT: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 12H5M11 6l-6 6 6 6"/></svg>"#;
pub const ICON_DOWNLOAD: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>"#;
pub const ICON_LINK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></svg>"#;
pub const ICON_TIMER: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 2h4M12 14l3-3"/><circle cx="12" cy="14" r="8"/></svg>"#;
pub const ICON_REFRESH: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-2.6-6.4"/><path d="M21 3v6h-6"/></svg>"#;
pub const ICON_LAPTOP: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 17h18M5 5h14a1 1 0 0 1 1 1v9H4V6a1 1 0 0 1 1-1Z"/></svg>"#;
pub const ICON_LOCK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>"#;
pub const ICON_UNLOCK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.6"/></svg>"#;

/// Minimal HTML escaping for text/attribute interpolation (defense-in-depth on every field).
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Which Verge surface a page belongs to (drives the active SurfacePill).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Mesh,
    Vpn,
}

/// Fill the shell slots every page shares (theme, colour scheme, stylesheet, shared icons).
pub fn shell(template: &str, headers: &axum::http::HeaderMap) -> String {
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    let theme = odyssey::resolve_theme(cookie);
    template
        .replace("{{THEME_ATTR}}", odyssey::html_theme_attr(theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(theme))
        .replace("{{CSS_PATH}}", APP_CSS_PATH)
        .replace("{{ICON_PLUS}}", ICON_PLUS)
        .replace("{{ICON_KEY}}", ICON_KEY)
        .replace("{{ICON_CHECK}}", ICON_CHECK)
        .replace("{{ICON_CLOCK}}", ICON_CLOCK)
        .replace("{{ICON_ARROW_LEFT}}", ICON_ARROW_LEFT)
        .replace("{{ICON_ARROW}}", ICON_ARROW)
        .replace("{{ICON_DOWNLOAD}}", ICON_DOWNLOAD)
        .replace("{{ICON_LINK}}", ICON_LINK)
        .replace("{{ICON_TIMER}}", ICON_TIMER)
        .replace("{{ICON_REFRESH}}", ICON_REFRESH)
        .replace("{{ICON_SHIELD}}", ICON_SHIELD)
}

/// Render the shared suite bar: brand tile + Steadholme/Verge, the host, the three surface pills
/// (Mesh · Edge · VPN — the active one coloured), an "All apps" link back to the apex portal, the
/// signed-in user chip (avatar initial + email), and the gateway logout. A blank / placeholder
/// email (`""` or `"—"`) is treated as a no-session page: the user chip becomes a muted note.
pub fn topbar(page_title: &str, email: &str) -> String {
    let surface = if page_title.starts_with("VPN") || page_title.starts_with("Subscription") {
        Surface::Vpn
    } else {
        Surface::Mesh
    };
    suite_bar(surface, email)
}

pub fn suite_bar(surface: Surface, email: &str) -> String {
    let trimmed = email.trim();
    let chip = if trimmed.is_empty() || trimmed == "—" {
        r#"<span class="user-email user-email--none" title="Signed in as">— (no gateway session)</span>"#.to_string()
    } else {
        let initial = trimmed
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "W".to_string());
        format!(
            r#"<span class="userchip"><span class="userchip__avatar" aria-hidden="true">{initial}</span><span class="user-email" title="Signed in as">{email}</span></span>"#,
            initial = esc(&initial),
            email = esc(trimmed),
        )
    };
    let (host, mesh_active, vpn_active) = match surface {
        Surface::Mesh => ("mesh.w33d.xyz", " is-active", ""),
        Surface::Vpn => ("vpn.w33d.xyz", "", " is-active"),
    };
    format!(
        r#"<header class="suitebar">
  <a class="suitebar__brand" href="/" aria-label="Verge home"><span class="brand-tile" aria-hidden="true">{net}</span><span class="suitebar__name"><b>Steadholme</b><span>Verge</span></span></a>
  <span class="suitebar__host">{host}</span>
  <nav class="surfaces" aria-label="Surfaces">
    <a class="surf surf--mesh{mesh_active}" href="/">{net}Mesh</a>
    <a class="surf surf--edge" href="https://edge.w33d.xyz/">{cloud}Edge</a>
    <a class="surf surf--vpn{vpn_active}" href="/profiles">{shield}VPN</a>
  </nav>
  <span class="suitebar__spacer"></span>
  <div class="suitebar__right">
    <a class="allapps" href="https://w33d.xyz" title="All apps">{grid}<span>All apps</span></a>
    {chip}
    <a class="btn btn-ghost btn-sm" href="{logout}">Log out</a>
  </div>
</header>"#,
        net = ICON_NETWORK,
        cloud = ICON_CLOUD,
        shield = ICON_SHIELD,
        grid = ICON_GRID,
        chip = chip,
        logout = LOGOUT_URL,
    )
}

/// Format epoch seconds as a compact UTC date `Mon D, YYYY` (e.g. `Jun 29, 2026`). std `time`
/// only, no extra C deps. `0` (the `last_seen` default) renders as "never".
pub fn fmt_date(secs: i64) -> String {
    if secs <= 0 {
        return "never".to_string();
    }
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!("{} {}, {}", month_abbr(dt.month()), dt.day(), dt.year()),
        Err(_) => secs.to_string(),
    }
}

fn month_abbr(m: time::Month) -> &'static str {
    use time::Month::*;
    match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}

/// A small, branded HTML error page (used by [`crate::error::AppError`]).
pub fn error_page(status: StatusCode, message: &str) -> String {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{code} {reason} · Verge</title><link rel="stylesheet" href="{css_path}"></head>
<body class="page-v2">
{topbar}
<main class="v2-page v2-narrow">
  <div class="status-wrap">
    <section class="status-tile">
      <div class="status-tile__code">{code}</div>
      <h1 class="status-tile__heading">{reason}</h1>
      <p class="status-tile__detail">{msg}</p>
      <div><a class="btn btn-secondary" href="/">Back to the mesh</a></div>
    </section>
  </div>
</main>
</body></html>"#,
        css_path = APP_CSS_PATH,
        topbar = suite_bar(Surface::Mesh, "—"),
        code = code,
        reason = esc(reason),
        msg = esc(message),
    )
}
