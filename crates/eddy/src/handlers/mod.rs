//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`console`] — the SSO web console + management API: asset list, total cache size, add-asset
//!   form, exact purge.
//! - [`serve`] — the public content-addressed edge (`/a/{*path}`): ETag / Cache-Control / 304 /
//!   Range.
//!
//! Odyssey canonical CSS plus Eddy service CSS are embedded and served as one versioned,
//! immutable stylesheet. All producer-supplied text (asset paths, origin
//! URLs) is HTML-escaped on render — the console injects NO raw HTML.

pub mod console;
pub mod health;
pub mod serve;

use std::sync::OnceLock;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

/// Eddy-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

/// Versioned stylesheet URL. Change the date whenever the embedded CSS changes.
pub const APP_CSS_PATH: &str = "/assets/eddy-20260908.css";

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

/// 24px stroke icons (Figma Icon/UI sheet).
pub const ICON_NETWORK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M5 16v-2a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v2"/></svg>"#;
pub const ICON_CLOUD: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.5 19H7a4 4 0 0 1-.7-7.9A5.5 5.5 0 0 1 17 9.5h.5a4.75 4.75 0 0 1 0 9.5Z"/></svg>"#;
pub const ICON_SHIELD: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.5 8.6 8 11 4.5-2.4 8-6 8-11V5l-8-3Z"/></svg>"#;
pub const ICON_GRID: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"#;
pub const ICON_UPLOAD_CLOUD: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M16 16l-4-4-4 4M12 12v9"/><path d="M20.4 16.6A5 5 0 0 0 18 7h-1.3A8 8 0 1 0 3 15.3"/></svg>"#;
pub const ICON_IMAGE: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/></svg>"#;
pub const ICON_FILE_CODE: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M10 13l-2 2 2 2M14 13l2 2-2 2"/></svg>"#;
pub const ICON_FILE: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>"#;
pub const ICON_KEY: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 9.2-9.2M15 8l3 3M18 5l2 2"/></svg>"#;
pub const ICON_CHECK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 5 5L20 7"/></svg>"#;
pub const ICON_CLOCK: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7.6V12l3 1.8"/></svg>"#;
pub const ICON_TRASH: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6"/></svg>"#;
pub const ICON_PLUS: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>"#;
pub const ICON_REFRESH: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-2.6-6.4"/><path d="M21 3v6h-6"/></svg>"#;
pub const ICON_EXTERNAL: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 4h6v6M20 4l-9 9M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6"/></svg>"#;

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Branded page + error shells.
const PAGE_HTML: &str = include_str!("../../templates/console.html");
const ERROR_HTML: &str = include_str!("../../templates/error.html");

/// Format epoch seconds as a compact UTC timestamp `YYYY-MM-DD HH:MM:SSZ`.
pub fn fmt_ts(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => secs.to_string(),
    }
}

/// First `n` characters of a hash/id, for compact display.
pub fn short(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Human-readable byte size (`B`/`KB`/`MB`/`GB`, base-1024, 1 decimal above bytes).
pub fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Fill the shell slots every page shares (theme from the gateway cookie, stylesheet, suite bar).
pub fn page_with(headers: &axum::http::HeaderMap, title: &str, email: Option<&str>, body: &str) -> String {
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    let theme = odyssey::resolve_theme(cookie);
    PAGE_HTML
        .replace("{{THEME_ATTR}}", odyssey::html_theme_attr(theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(theme))
        .replace("{{CSS_PATH}}", APP_CSS_PATH)
        .replace("{{TITLE}}", &esc(title))
        .replace("{{TOPBAR}}", &suite_bar(email))
        .replace("{{BODY}}", body)
}

/// Render the shared HTML page shell (no request headers available → light theme).
pub fn page(title: &str, email: Option<&str>, body: &str) -> String {
    PAGE_HTML
        .replace("{{THEME_ATTR}}", "")
        .replace("{{COLOR_SCHEME}}", "light")
        .replace("{{CSS_PATH}}", APP_CSS_PATH)
        .replace("{{TITLE}}", &esc(title))
        .replace("{{TOPBAR}}", &suite_bar(email))
        .replace("{{BODY}}", body)
}

/// The Verge suite bar with the Edge pill active: brand tile + Steadholme/Verge, host, the three
/// surface pills, All apps, the signed-in identity chip, and the gateway logout.
pub fn suite_bar(email: Option<&str>) -> String {
    let chip = match email {
        Some(e) if !e.is_empty() => {
            let initial = e
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "W".to_string());
            format!(
                "<span class=\"userchip\"><span class=\"userchip__avatar\" aria-hidden=\"true\">{}</span><span class=\"user-email\" title=\"Signed in as\">{}</span></span>",
                esc(&initial),
                esc(e),
            )
        }
        _ => "<span class=\"user-email user-email--none\" title=\"Signed in as\">— (no gateway session)</span>".to_string(),
    };
    format!(
        concat!(
            "<header class=\"suitebar\">",
            "<a class=\"suitebar__brand\" href=\"/\" aria-label=\"Verge home\"><span class=\"brand-tile\" aria-hidden=\"true\">{net}</span><span class=\"suitebar__name\"><b>Steadholme</b><span>Verge</span></span></a>",
            "<span class=\"suitebar__host\">edge.w33d.xyz</span>",
            "<nav class=\"surfaces\" aria-label=\"Surfaces\">",
            "<a class=\"surf surf--mesh\" href=\"https://mesh.w33d.xyz/\">{net}Mesh</a>",
            "<a class=\"surf surf--edge is-active\" href=\"/\">{cloud}Edge</a>",
            "<a class=\"surf surf--vpn\" href=\"https://vpn-ui.w33d.xyz/profiles\">{shield}VPN</a>",
            "</nav><span class=\"suitebar__spacer\"></span><div class=\"suitebar__right\">",
            "<a class=\"allapps\" href=\"https://w33d.xyz\" title=\"All apps\">{grid}<span>All apps</span></a>",
            "{chip}",
            "<a class=\"btn btn-ghost btn-sm\" href=\"{logout}\">Log out</a>",
            "</div></header>",
        ),
        net = ICON_NETWORK,
        cloud = ICON_CLOUD,
        shield = ICON_SHIELD,
        grid = ICON_GRID,
        chip = chip,
        logout = LOGOUT_URL,
    )
}

/// Wrap a rendered page in an HTML response that also (re)sets the CSRF cookie.
pub fn html_with_csrf(status: StatusCode, body: String, csrf: &str) -> Response {
    (
        status,
        [(header::SET_COOKIE, crate::auth::csrf_cookie(csrf))],
        Html(body),
    )
        .into_response()
}

/// A `303 See Other` redirect (post/redirect/get).
pub fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// Render the branded error page (used by [`crate::error::AppError`]).
pub fn render_error(
    status: StatusCode,
    heading: &str,
    message: &str,
    email: Option<&str>,
) -> (StatusCode, Html<String>) {
    let body = ERROR_HTML
        .replace("{{THEME_ATTR}}", "")
        .replace("{{COLOR_SCHEME}}", "light")
        .replace("{{CSS_PATH}}", APP_CSS_PATH)
        .replace("{{TOPBAR}}", &suite_bar(email))
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(heading))
        .replace("{{MESSAGE}}", &esc(message));
    (status, Html(body))
}

/// Minimal HTML escaping for text/attribute interpolation.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(esc("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn human_size_scales() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1024 * 1024), "1.0 MB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GB");
    }
}
