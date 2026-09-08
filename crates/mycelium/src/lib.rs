//! Mycelium — zero-trust WireGuard mesh CONTROL PLANE for the Steadholme stack.
//!
//! Mycelium is a self-hosted coordination server (think Tailscale's control plane): it enrolls
//! devices, manages peers + ACLs, and GENERATES valid WireGuard configs. It does NOT bring up a
//! live kernel tunnel on this host — a real data plane needs `NET_ADMIN` + the `wireguard`
//! kernel module on a dedicated privileged node, which is intentionally OUT OF SCOPE so it can
//! never destabilize the shared host. See the README "Deferred" section.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store, audit disabled) and [`build_state_from_env`]
//! (env-selected store + Watchtower audit). Integration tests consume [`app`] directly via
//! `tower::oneshot`.
//!
//! Mycelium sits behind a Sluice `auth=sso` route at the subdomain ROOT (`mesh.w33d.xyz`); the
//! gateway forwards the path UNMODIFIED, so the routes below are the real paths.
//!
//! Endpoints:
//! - `GET  /healthz`                  liveness (public, no auth)
//! - `GET  /`                         admin dashboard: device list, enroll form, ACL table, summary
//! - `POST /api/devices`              enroll a device (server keygen + IP assign) -> conf shown ONCE
//! - `POST /api/devices/{id}/revoke`  revoke a device (disable it)
//! - `POST /api/acls`                 add an ACL rule
//! - `GET  /api/config/{id}`          re-render a device's wg.conf WITHOUT the private key

pub mod audit;
pub mod auth;
pub mod clash;
pub mod config;
pub mod error;
pub mod handlers;
pub mod store;
pub mod wg;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;
use tokio::sync::Mutex;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub audit: AuditSink,
    /// Optional short-lived Clash subscription service. Production loads profile bytes and the
    /// independent signing key from read-only runtime files; dev stays disabled by default.
    pub clash: Option<Arc<clash::ClashSubscription>>,
    /// Serializes the read-then-write IP allocation during enroll so two concurrent enrollments
    /// can never pick the same mesh IP. The DB UNIQUE(mesh_ip) constraint is the backstop.
    pub enroll_lock: Arc<Mutex<()>>,
}

/// Build the router wiring all endpoints onto `state`. Routes are explicit (no fallback): the
/// service owns its subdomain, so Sluice forwards these exact paths.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route(handlers::APP_CSS_PATH, get(handlers::app_css_asset))
        .route("/", get(handlers::devices::dashboard))
        .route("/profiles", get(handlers::clash::profile_page))
        .route("/static/dashboard.js", get(handlers::clash::dashboard_js))
        .route("/api/clash/capability", get(handlers::clash::capability))
        .route(
            "/api/clash/subscription-link",
            post(handlers::clash::issue_subscription),
        )
        .route("/subscription/clash", get(handlers::clash::download))
        .route("/api/devices", post(handlers::devices::enroll))
        .route("/api/devices/{id}/revoke", post(handlers::devices::revoke))
        .route("/api/acls", post(handlers::devices::add_acl))
        .route("/api/config/{id}", get(handlers::devices::config))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer that
        // bypasses Sluice): when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid
        // X-Auth-Sig. No-op for the anonymous dashboard / healthz (no identity) and in local dev.
        .layer(axum::middleware::from_fn(auth::require_gateway_sig))
        .with_state(state)
}

/// Construct dev state: dev [`Config`], an empty [`InMemoryStore`], and a disabled audit sink.
/// Used by `main`'s memory mode and the integration tests, so they need no database/network.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        audit: AuditSink::disabled(),
        clash: None,
        enroll_lock: Arc::new(Mutex::new(())),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `MYCELIUM_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `MYCELIUM_DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`.
/// Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = env_nonempty("MYCELIUM_STORE").unwrap_or_else(|| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("MYCELIUM_DATABASE_URL").ok_or_else(|| {
                "MYCELIUM_STORE=postgres requires MYCELIUM_DATABASE_URL".to_string()
            })?;
            tracing::info!("MYCELIUM_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => {
            return Err(format!(
                "unknown MYCELIUM_STORE={other} (use memory|postgres)"
            ))
        }
    };

    let audit = AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        audit,
        clash: clash::from_env()?,
        enroll_lock: Arc::new(Mutex::new(())),
    })
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive).
fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "on" | "true" | "1" | "yes"
    )
}

/// Current wall-clock time in epoch seconds (`enrolled_at` / `created_at` granularity).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Monotonic-ish nanosecond counter for device/ACL ids.
pub fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos()
}
