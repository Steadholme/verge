//! Admin dashboard + the SSO-gated enroll / revoke / ACL / config-render flow.
//!
//! Mounted behind the gateway `auth=sso` route: the operator identity is ALWAYS taken from the
//! injected `X-Auth-Subject` / `X-Auth-Email` (never a client field), and every state-changing
//! POST is double-submit CSRF protected. Enrollment generates a real Curve25519 keypair
//! server-side, assigns a stable mesh IP, and returns the full `wg.conf` (with the private key)
//! exactly ONCE; the re-render endpoint never re-emits the private key.

use std::collections::HashMap;
use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::Config;
use crate::error::AppError;
use crate::handlers::{esc, fmt_date, topbar, APP_CSS};
use crate::store::{self, Acl, Device};
use crate::wg::{self, PeerView};
use crate::{now_nanos, now_secs, AppState};

const DASHBOARD_HTML: &str = include_str!("../../templates/dashboard.html");
const ENROLLED_HTML: &str = include_str!("../../templates/enrolled.html");

/// Enroll form: device name + optional free-form tags. Identity is NEVER taken from the form.
#[derive(Debug, Deserialize)]
pub struct EnrollForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub tags: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// Revoke form: just the CSRF token (the device id is in the path).
#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// Add-ACL form: a `src_tag -> dst_tag` rule on `ports`.
#[derive(Debug, Deserialize)]
pub struct AclForm {
    #[serde(default)]
    pub src_tag: String,
    #[serde(default)]
    pub dst_tag: String,
    #[serde(default)]
    pub ports: String,
    #[serde(default)]
    pub csrf_token: String,
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

/// `GET /` — the mesh admin dashboard: device list, enroll form, ACL table + add-ACL form, and
/// the trust / CIDR summary.
pub async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let devices = state.store.list_devices().await;
    let acls = state.store.list_acls().await;
    let tmap = store::tag_map(state.store.all_tags().await);

    let enabled_count = devices.iter().filter(|d| d.enabled).count();
    let posture = if acls.is_empty() {
        "default-allow (no ACLs — full mesh)"
    } else {
        "default-deny (ACL-gated)"
    };

    let device_rows = render_device_rows(&devices, &tmap, &csrf);
    let acl_rows = render_acl_rows(&acls);

    let page = DASHBOARD_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Mesh control plane", &email))
        .replace("{{CIDR}}", &esc(&state.config.cidr.to_text()))
        .replace("{{DNS}}", &esc(&state.config.dns))
        .replace("{{GATEWAY}}", &esc(&state.config.cidr.gateway_string()))
        .replace(
            "{{ENDPOINT_DOMAIN}}",
            &esc(if state.config.endpoint_domain.is_empty() {
                "(none)"
            } else {
                &state.config.endpoint_domain
            }),
        )
        .replace("{{DEVICE_COUNT}}", &format!("{enabled_count} / {}", devices.len()))
        .replace("{{ACL_COUNT}}", &acls.len().to_string())
        .replace("{{POSTURE}}", posture)
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{DEVICE_ROWS}}", &device_rows)
        .replace("{{ACL_ROWS}}", &acl_rows);

    html_with_cookie(page, set_cookie)
}

// ---------------------------------------------------------------------------
// Enroll
// ---------------------------------------------------------------------------

/// `POST /api/devices` — enroll a device. The server generates the Curve25519 keypair, assigns
/// the lowest free mesh IP, persists the public key (NEVER the private key), and returns the
/// full ready-to-use `wg.conf` ONCE (the only time the private key is shown).
pub async fn enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<EnrollForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_operator(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let name = form.name.trim();
    if name.is_empty() {
        return Err(AppError::InvalidRequest("device name is required".to_string()));
    }
    if name.chars().count() > 120 {
        return Err(AppError::InvalidRequest(
            "device name too long (max 120 chars)".to_string(),
        ));
    }
    let tags = wg::parse_tags(&form.tags);

    // Serialize allocation + insert so two concurrent enrollments cannot pick the same IP.
    let guard = state.enroll_lock.lock().await;
    let existing = state.store.list_devices().await;
    let mut taken: HashSet<u32> = HashSet::new();
    for d in &existing {
        if let Some(ip) = wg::ip_from_string(&d.mesh_ip) {
            taken.insert(ip);
        }
    }
    let ip_u32 = state.config.cidr.allocate(&taken).ok_or_else(|| {
        AppError::Conflict(format!(
            "mesh address pool {} is exhausted",
            state.config.cidr.to_text()
        ))
    })?;
    let mesh_ip = wg::ip_to_string(ip_u32);
    let keypair = wg::generate_keypair();
    let now = now_secs();
    let device = Device {
        id: format!("dev_{}", now_nanos()),
        name: name.to_string(),
        owner_sub: sub,
        public_key: keypair.public_b64.clone(),
        mesh_ip: mesh_ip.clone(),
        enrolled_at: now,
        last_seen: 0,
        enabled: true,
    };
    state.store.create_device(&device, &tags).await?;
    drop(guard);

    // The client conf is hub-and-spoke: [Interface] + the single hub [Peer]. The full-mesh peer
    // list is NOT shipped to the client (the host reconciler manages server-side peers). We still
    // compute the reachable-peer count under the ACLs for the operator's confirmation page.
    let mut all = existing;
    all.push(device.clone());
    let tmap = store::tag_map(state.store.all_tags().await);
    let acl_pairs = acl_pairs(&state).await;
    let peers = compute_peers(&device, &all, &tmap, &acl_pairs, &state.config);
    let conf = wg::render_conf(
        Some(&keypair.private_b64),
        &device.mesh_ip,
        &state.config.dns,
        &state.config.hub_peer(),
    );

    // Audit records WHO enrolled WHICH device WHERE — never the private key.
    state.audit.emit(AuditEvent::info(
        "mycelium.enroll",
        &email,
        &device.id,
        &format!("ip={} name={}", device.mesh_ip, device.name),
    ));
    tracing::info!(device = %device.id, ip = %device.mesh_ip, "device enrolled");

    let page = ENROLLED_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Device enrolled", &email))
        .replace("{{NAME}}", &esc(&device.name))
        .replace("{{MESH_IP}}", &esc(&device.mesh_ip))
        .replace("{{PUBKEY}}", &esc(&device.public_key))
        .replace("{{PEER_COUNT}}", &peers.len().to_string())
        .replace("{{CONF}}", &esc(&conf));

    Ok(no_store(Html(page).into_response()))
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

/// `POST /api/devices/{id}/revoke` — revoke a device (disable it; its mesh IP stays reserved so
/// it is never silently reissued), then bounce to the dashboard.
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<RevokeForm>,
) -> Result<Response, AppError> {
    let (_sub, email) = auth::require_operator(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let device = state
        .store
        .get_device(&id)
        .await
        .ok_or_else(|| AppError::NotFound("no such device".to_string()))?;

    let matched = state.store.revoke_device(&id).await?;
    if !matched {
        return Err(AppError::NotFound("no such device".to_string()));
    }

    state.audit.emit(AuditEvent::warning(
        "mycelium.revoke",
        &email,
        &device.id,
        &format!("ip={} name={}", device.mesh_ip, device.name),
    ));
    tracing::info!(device = %device.id, "device revoked");

    Ok(redirect("/"))
}

// ---------------------------------------------------------------------------
// ACLs
// ---------------------------------------------------------------------------

/// `POST /api/acls` — add an ACL rule (`src_tag -> dst_tag` on `ports`), then bounce to the
/// dashboard. Empty tags normalize to the `*` wildcard; empty ports normalize to `*`.
pub async fn add_acl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AclForm>,
) -> Result<Response, AppError> {
    let (_sub, _email) = auth::require_operator(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let acl = Acl {
        id: format!("acl_{}", now_nanos()),
        src_tag: normalize_tag(&form.src_tag),
        dst_tag: normalize_tag(&form.dst_tag),
        ports: normalize_ports(&form.ports),
        created_at: now_secs(),
    };
    state.store.create_acl(&acl).await?;
    tracing::info!(acl = %acl.id, src = %acl.src_tag, dst = %acl.dst_tag, "acl added");

    Ok(redirect("/"))
}

// ---------------------------------------------------------------------------
// Config re-render
// ---------------------------------------------------------------------------

/// `GET /api/config/{id}` — re-render a device's hub-and-spoke `wg.conf` WITHOUT the private key,
/// served as a downloadable text file. Lets an operator re-fetch a device's config (hub `[Peer]`)
/// without ever re-exposing key material.
pub async fn config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    auth::require_operator(&headers)?;

    let device = state
        .store
        .get_device(&id)
        .await
        .ok_or_else(|| AppError::NotFound("no such device".to_string()))?;

    // Re-render is hub-and-spoke too: [Interface] (no private key) + the single hub [Peer].
    let conf = wg::render_conf(None, &device.mesh_ip, &state.config.dns, &state.config.hub_peer());

    let filename = format!("{}.conf", wg::slugify(&device.name));
    let mut resp = (StatusCode::OK, conf).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(cd) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        h.insert(header::CONTENT_DISPOSITION, cd);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Peer computation
// ---------------------------------------------------------------------------

/// Fetch the ACL `(src_tag, dst_tag)` pairs for link evaluation.
async fn acl_pairs(state: &AppState) -> Vec<(String, String)> {
    state
        .store
        .list_acls()
        .await
        .into_iter()
        .map(|a| (a.src_tag, a.dst_tag))
        .collect()
}

/// The peers `target` should be configured with: every OTHER enabled device it may reach under
/// the ACLs, sorted by mesh IP for stable output.
fn compute_peers(
    target: &Device,
    all: &[Device],
    tags: &HashMap<String, Vec<String>>,
    acl_pairs: &[(String, String)],
    cfg: &Config,
) -> Vec<PeerView> {
    let empty: Vec<String> = Vec::new();
    let target_tags = tags.get(&target.id).unwrap_or(&empty);
    let mut peers: Vec<PeerView> = Vec::new();
    for d in all {
        if d.id == target.id || !d.enabled {
            continue;
        }
        let d_tags = tags.get(&d.id).unwrap_or(&empty);
        if !wg::link_allowed(acl_pairs, target_tags, d_tags) {
            continue;
        }
        peers.push(PeerView {
            name: d.name.clone(),
            public_key: d.public_key.clone(),
            mesh_ip: d.mesh_ip.clone(),
            endpoint: wg::endpoint_for(&d.name, &cfg.endpoint_domain, cfg.listen_port),
        });
    }
    peers.sort_by(|a, b| {
        wg::ip_from_string(&a.mesh_ip)
            .unwrap_or(0)
            .cmp(&wg::ip_from_string(&b.mesh_ip).unwrap_or(0))
    });
    peers
}

// ---------------------------------------------------------------------------
// Row rendering
// ---------------------------------------------------------------------------

fn render_device_rows(
    devices: &[Device],
    tags: &HashMap<String, Vec<String>>,
    csrf: &str,
) -> String {
    if devices.is_empty() {
        return r#"<tr><td colspan="7" class="dtable__empty">No devices enrolled yet. Enroll your first node below.</td></tr>"#.to_string();
    }
    let empty: Vec<String> = Vec::new();
    let mut out = String::new();
    for d in devices {
        let dtags = tags.get(&d.id).unwrap_or(&empty);
        let tag_html = if dtags.is_empty() {
            r#"<span class="muted">—</span>"#.to_string()
        } else {
            dtags
                .iter()
                .map(|t| format!(r#"<span class="tag">{}</span>"#, esc(t)))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let status = if d.enabled {
            r#"<span class="badge badge-ok">Active</span>"#
        } else {
            r#"<span class="badge badge-revoked">Revoked</span>"#
        };
        let action = if d.enabled {
            format!(
                r#"<form class="inline-form" method="post" action="/api/devices/{id}/revoke" onsubmit="return confirm('Revoke this device? It will be removed from every peer config.');">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <button class="btn btn-danger btn-sm" type="submit">Revoke</button>
</form>"#,
                id = esc(&d.id),
                csrf = esc(csrf),
            )
        } else {
            String::new()
        };
        out.push_str(&format!(
            r#"<tr>
  <td><span class="dev-name">{name}</span></td>
  <td><code class="mono">{ip}</code></td>
  <td><code class="mono" title="{pubkey}">{fp}</code></td>
  <td>{tags}</td>
  <td class="muted">{seen}</td>
  <td>{status}</td>
  <td class="dtable__actions"><a class="btn btn-secondary btn-sm" href="/api/config/{id}">Config</a>{action}</td>
</tr>"#,
            name = esc(&d.name),
            ip = esc(&d.mesh_ip),
            pubkey = esc(&d.public_key),
            fp = esc(&wg::fingerprint(&d.public_key)),
            tags = tag_html,
            seen = esc(&fmt_date(d.last_seen)),
            status = status,
            id = esc(&d.id),
            action = action,
        ));
    }
    out
}

fn render_acl_rows(acls: &[Acl]) -> String {
    if acls.is_empty() {
        return r#"<tr><td colspan="3" class="dtable__empty">No ACL rules — the mesh is currently full-allow. Add a rule to switch to default-deny.</td></tr>"#.to_string();
    }
    let mut out = String::new();
    for a in acls {
        out.push_str(&format!(
            r#"<tr>
  <td><span class="tag">{src}</span></td>
  <td><span class="tag">{dst}</span></td>
  <td><code class="mono">{ports}</code></td>
</tr>"#,
            src = esc(&a.src_tag),
            dst = esc(&a.dst_tag),
            ports = esc(&a.ports),
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Normalize an ACL tag: trim, lowercase, single token; empty -> `*` wildcard.
fn normalize_tag(raw: &str) -> String {
    let t = raw.trim().split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    if t.is_empty() {
        "*".to_string()
    } else {
        t
    }
}

/// Normalize a ports spec: trim; empty -> `*`. Kept as free text (`*`, `443`, `80,443`, …).
fn normalize_ports(raw: &str) -> String {
    let p = raw.trim();
    if p.is_empty() {
        "*".to_string()
    } else {
        p.to_string()
    }
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, HeaderValue::from_str(location).expect("valid location"))],
    )
        .into_response()
}

/// Attach `Cache-Control: no-store` so a response carrying secret material is never cached.
fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}
