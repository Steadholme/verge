//! Eddy — sovereign static-asset edge cache / mini-CDN for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store + blobs, audit off) and [`build_state_from_env`]
//! (env-selected store + blob backend + Watchtower audit). Integration tests consume [`app`]
//! directly via `tower::oneshot`, exactly like the rest of the estate.
//!
//! Eddy serves TWO surfaces on one subdomain (`edge.w33d.xyz`), split at the Sluice gateway (the
//! relay/aperture precedent):
//!
//! - The WEB console at `/` is `auth=sso` (gateway-injected `X-Auth-*`): manage cached assets —
//!   add (upload or fetch-from-origin), list with sizes + hit counts + total cache size, and
//!   exact-purge. Eddy is internal-only and trusts the injected identity headers; every POST is
//!   double-submit CSRF protected.
//! - The public edge under `/a/` is `auth=public` at the gateway — a browser `<img>`/`<script>`
//!   cannot speak the SSO cookie — so it has NO SSO: it serves a cached asset by path with a strong
//!   ETag, `Cache-Control`, conditional `304`, and `Range` support. User IPs + assets stay private
//!   (the origin is fetched once, server-side). When an `EDDY_SIGNING_KEY` is configured, `/a/`
//!   additionally requires a valid HMAC `?exp=&sig=`.
//!
//! Endpoints (served at the subdomain ROOT — Sluice forwards the path unmodified):
//! - `GET  /healthz`     liveness (public)
//! - `GET  /`            console: asset list + total cache size + add-asset form [SSO]
//! - `POST /api/assets`  add an asset (multipart upload OR `{origin_url}`) -> the public `/a/` URL [SSO, CSRF]
//! - `POST /api/purge`   exact purge by `path` or `hash` [SSO, CSRF]
//! - `GET  /a/{*path}`   serve a cached asset (ETag / Cache-Control / 304 / Range) [PUBLIC `/a/` prefix]

pub mod audit;
pub mod auth;
pub mod blobs;
pub mod config;
pub mod error;
pub mod handlers;
pub mod media;
pub mod sign;
pub mod store;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::audit::AuditSink;
use crate::blobs::{Blobs, FsBlobs, MemoryBlobs};
use crate::config::{env_nonempty, Config};
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / cloneable handles).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub blobs: Arc<dyn Blobs>,
    pub http: reqwest::Client,
    pub audit: AuditSink,
}

/// Build the router wiring all endpoints onto `state`.
///
/// The console + management API sit at the service root (Sluice forwards them under `auth=sso`); the
/// `/a/*` subtree is the public edge (Sluice marks the `/a/` prefix `auth=public`). The body limit
/// is sized to the configured `max_asset` plus a small multipart-envelope headroom.
pub fn app(state: AppState) -> Router {
    let body_limit = state.config.max_asset.saturating_add(1024 * 1024);
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        // --- SSO web console + management API ---
        .route("/", get(handlers::console::index))
        .route("/api/assets", post(handlers::console::create_asset))
        .route("/api/purge", post(handlers::console::purge))
        // --- public content-addressed edge ---
        .route("/a/{*path}", get(handlers::serve::serve))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}

/// Construct dev state: dev [`Config`] + empty in-memory metadata + in-memory blobs + a disabled
/// audit sink. Used by `main`'s memory mode and by the integration tests, so they need NO database
/// and NO volume.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        blobs: Arc::new(MemoryBlobs::new()),
        http: build_http_client(),
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The metadata store is selected by `EDDY_STORE`
/// (`memory` default | `postgres`); the blob backend by `EDDY_BLOBS` (`memory` default | `fs`).
/// The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`. Returns
/// an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = env_nonempty("EDDY_STORE").unwrap_or_else(|| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("EDDY_DATABASE_URL")
                .or_else(|| env_nonempty("DATABASE_URL"))
                .ok_or_else(|| "EDDY_STORE=postgres requires EDDY_DATABASE_URL".to_string())?;
            tracing::info!("EDDY_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres metadata store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => return Err(format!("unknown EDDY_STORE={other} (use memory|postgres)")),
    };

    let blobs_kind = env_nonempty("EDDY_BLOBS").unwrap_or_else(|| "memory".to_string());
    let blobs: Arc<dyn Blobs> = match blobs_kind.as_str() {
        "fs" => {
            tracing::info!(root = config.blobs_root(), "EDDY_BLOBS=fs — content-addressed on volume");
            Arc::new(
                FsBlobs::open(&config.blobs_root())
                    .await
                    .map_err(|e| format!("open fs blobs: {e}"))?,
            )
        }
        "memory" => Arc::new(MemoryBlobs::new()),
        other => return Err(format!("unknown EDDY_BLOBS={other} (use memory|fs)")),
    };

    let audit = AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    if config.signing_enabled() {
        tracing::info!("EDDY_SIGNING_KEY set — /a/ URLs require a valid HMAC signature");
    }

    Ok(AppState {
        config: Arc::new(config),
        store,
        blobs,
        http: build_http_client(),
        audit,
    })
}

/// The shared reqwest client used to fetch assets from an origin (rustls; bounded timeouts so a
/// slow origin cannot hang a request indefinitely). Public so integration tests can assemble a
/// custom [`AppState`] without re-deriving the client config.
pub fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build reqwest client")
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

/// Current wall-clock time in epoch seconds (`created_at` granularity + signed-URL expiry base).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Lowercase-hex SHA-256 of `bytes` — the content address used as the blob key + ETag validator.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Generate a random URL-safe alphanumeric string of `len` characters from a 62-symbol alphabet,
/// via the OS CSPRNG. Used for asset ids and the CSRF token. The modulo over 62 introduces a
/// negligible bias that is irrelevant for ids/tokens of this size.
pub fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}
