//! Verge — one container hosting the HOLDFAST edge surfaces (static edge cache / WireGuard mesh
//! control plane).
//!
//! Each surface is its OWN library crate (Eddy/Mycelium), reused verbatim: same schema, same
//! routes, same templates, same OWN database, same subdomain, same port. This binary only adds a
//! **Host-based vhost demux** on a **DUAL listener** so the estate runs ONE deployable instead of
//! two. The gateway points `edge.w33d.xyz` and `mesh.w33d.xyz` at this container; each request is
//! dispatched to the matching surface's router by its `Host` header.
//!
//! Both surfaces historically listened on different ports (Eddy :9220, Mycelium :9290) and the
//! BEACON estate probes hit those ports directly (`eddy:9220` / `mycelium:9290`). To keep BOTH
//! probes working unchanged, Verge binds the SAME demux router on BOTH ports: the host-agnostic
//! top-level `GET /healthz` answers for every alias on either listener, and a caller reaching
//! `mesh.w33d.xyz` (or the bare `mycelium`/`mesh` label) on either port is dispatched to Mycelium,
//! `edge.w33d.xyz`/`eddy`/`edge` to Eddy.
//!
//! Mycelium is the WireGuard CONTROL PLANE only (enroll/peers/ACLs/config generation) — it brings
//! up NO kernel tunnel on this host, so it is pure HTTP and safe to co-host behind the demux.
//!
//! Each surface's `AppState` is built EXPLICITLY (not via `build_state_from_env`, which would read
//! the bare `DATABASE_URL` and collide in-process): Eddy connects+migrates `EDDY_DATABASE_URL` and
//! Mycelium `MYCELIUM_DATABASE_URL`, each reusing that crate's own store/blob/audit construction.
//!
//! `healthcheck` subcommand: a dependency-free loopback `GET /healthz` (host-agnostic) used as the
//! container HEALTHCHECK, so the image needs no curl.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Default address for the PRIMARY (edge) listener — Eddy's historical port.
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9220";
/// Default address for the SECONDARY (mesh) listener — Mycelium's historical port. Bound in
/// addition to the primary so the BEACON `mycelium:9290` probe keeps working.
const DEFAULT_MESH_BIND_ADDR: &str = "0.0.0.0:9290";

/// The two composed per-surface routers, dispatched by Host. Cheap to clone (each `Router` is
/// `Arc`-backed internally).
#[derive(Clone)]
struct Vhosts {
    edge: Router,
    mesh: Router,
}

#[tokio::main]
async fn main() {
    // Container HEALTHCHECK path — handled before any setup, exits the process.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(run_healthcheck());
    }

    tracing_subscriber::fmt::init();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let mesh_bind_addr =
        std::env::var("MESH_BIND_ADDR").unwrap_or_else(|_| DEFAULT_MESH_BIND_ADDR.to_string());

    // Each surface connects to its OWN database and migrates idempotently — exactly what the
    // standalone service did. A failure here is fatal (the surface cannot serve without its DB).
    let edge = build_edge().await.unwrap_or_else(|e| fatal("edge (eddy)", e));
    let mesh = build_mesh().await.unwrap_or_else(|e| fatal("mesh (mycelium)", e));

    let app = Router::new()
        // Host-agnostic liveness for the container HEALTHCHECK + estate probes (both listeners).
        .route("/healthz", get(|| async { "ok" }))
        .fallback(dispatch)
        .with_state(Vhosts { edge, mesh });

    let primary: SocketAddr = bind_addr.parse().expect("invalid BIND_ADDR");
    let secondary: SocketAddr = mesh_bind_addr.parse().expect("invalid MESH_BIND_ADDR");

    let l_primary = tokio::net::TcpListener::bind(primary)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {primary}: {e}"));
    let l_secondary = tokio::net::TcpListener::bind(secondary)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {secondary}: {e}"));

    tracing::info!(%primary, %secondary, "Verge listening (edge/mesh vhost demux, dual listener)");

    // Serve the SAME demux router on BOTH listeners concurrently. If either serve loop returns the
    // process is in an unrecoverable state, so we exit.
    let app_secondary = app.clone();
    let serve_primary = tokio::spawn(async move {
        axum::serve(l_primary, app)
            .await
            .expect("primary server error");
    });
    let serve_secondary = tokio::spawn(async move {
        axum::serve(l_secondary, app_secondary)
            .await
            .expect("secondary server error");
    });

    let _ = tokio::try_join!(serve_primary, serve_secondary);
}

/// Dispatch one request to the surface matching its `Host` header. An unknown host is a 404 — we
/// never silently serve one surface under another's vhost. The full request (headers + body) is
/// forwarded, so each surface's own auth (gateway-injected SSO, CSRF, HMAC `/a/` gate) still
/// applies exactly as it did standalone.
async fn dispatch(State(v): State<Vhosts>, req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // Match on the leading label, ignoring any port. We accept BOTH the gateway subdomain label
    // (`edge`/`mesh`) AND the bare service-name label (`eddy`/`mycelium`) a caller may use when
    // POSTing to `http://<name>:<port>` inside the estate (e.g. the BEACON probes).
    let label = host
        .split(':')
        .next()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    let router = match label {
        "edge" | "eddy" => v.edge,
        "mesh" | "mycelium" => v.mesh,
        _ => return (StatusCode::NOT_FOUND, "unknown edge host").into_response(),
    };
    // `Router` is a tower `Service` (the exact `app(state).oneshot(req)` path the surfaces' own
    // tests use); its error type is `Infallible`.
    match router.oneshot(req).await {
        Ok(resp) => resp,
        Err(e) => match e {},
    }
}

/// Build the edge (Eddy) surface router against `EDDY_DATABASE_URL`.
///
/// State is built EXPLICITLY (not via `eddy::build_state_from_env`, which would read the bare
/// `DATABASE_URL` and collide with Mycelium in-process): connect + migrate Eddy's OWN database,
/// then assemble the rest of Eddy's state exactly as its own `build_state_from_env` does — the blob
/// backend selected by `EDDY_BLOBS` (`memory` default | `fs` on the `/data` volume), the shared
/// rustls reqwest client for origin fetches, and the Watchtower audit emitter. `Config::from_env()`
/// still resolves `PUBLIC_BASE_URL`, `EDDY_SIGNING_KEY`, cache/asset limits, etc.
async fn build_edge() -> Result<Router, String> {
    let dsn = require_env("EDDY_DATABASE_URL")?;
    let pg = eddy::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("edge (eddy) store ready");

    let config = eddy::config::Config::from_env();

    // Blob backend — mirror Eddy's own `EDDY_BLOBS` selection (default memory | fs on the volume).
    let blobs_kind =
        eddy::config::env_nonempty("EDDY_BLOBS").unwrap_or_else(|| "memory".to_string());
    let blobs: Arc<dyn eddy::blobs::Blobs> = match blobs_kind.as_str() {
        "fs" => {
            tracing::info!(root = config.blobs_root(), "EDDY_BLOBS=fs — content-addressed on volume");
            Arc::new(
                eddy::blobs::FsBlobs::open(&config.blobs_root())
                    .await
                    .map_err(|e| format!("open fs blobs: {e}"))?,
            )
        }
        "memory" => Arc::new(eddy::blobs::MemoryBlobs::new()),
        other => return Err(format!("unknown EDDY_BLOBS={other} (use memory|fs)")),
    };

    let audit = eddy::audit::AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &eddy::config::env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        eddy::config::env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    if config.signing_enabled() {
        tracing::info!("EDDY_SIGNING_KEY set — /a/ URLs require a valid HMAC signature");
    }

    let state = eddy::AppState {
        config: Arc::new(config),
        store: Arc::new(pg),
        blobs,
        http: eddy::build_http_client(),
        audit,
    };
    Ok(eddy::app(state))
}

/// Build the mesh (Mycelium) surface router against `MYCELIUM_DATABASE_URL`.
///
/// State is built EXPLICITLY for the same reason as [`build_edge`]: connect + migrate Mycelium's
/// OWN database, start its Watchtower audit emitter, and create the enroll mutex that serializes IP
/// allocation — exactly as Mycelium's own `build_state_from_env` does. Mycelium is control-plane
/// only, so there is no kernel tunnel / background task to preserve.
async fn build_mesh() -> Result<Router, String> {
    let dsn = require_env("MYCELIUM_DATABASE_URL")?;
    let pg = mycelium::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("mesh (mycelium) store ready");

    let audit = mycelium::audit::AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &mycelium::config::env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        mycelium::config::env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    let state = mycelium::AppState {
        config: Arc::new(mycelium::config::Config::from_env()),
        store: Arc::new(pg),
        audit,
        enroll_lock: Arc::new(Mutex::new(())),
    };
    Ok(mycelium::app(state))
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive). Mirrors the
/// private `env_truthy` each surface uses in its own `build_state_from_env`, so audit is gated
/// identically.
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

/// Read a required env var, returning a descriptive error when unset/empty.
fn require_env(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{key} is required")),
    }
}

/// Log a fatal startup error for one surface and exit.
fn fatal(surface: &str, err: String) -> ! {
    tracing::error!(surface, error = %err, "failed to build edge surface");
    std::process::exit(1);
}

/// GET `/healthz` over a raw TCP socket on the loopback. Returns the process exit code. Probes the
/// PRIMARY listener (`BIND_ADDR`); both listeners answer the same host-agnostic `/healthz`.
fn run_healthcheck() -> i32 {
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let port = bind_addr.rsplit(':').next().unwrap_or("9220");
    let target = format!("127.0.0.1:{port}");
    match healthcheck_once(&target) {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("healthcheck: {target} did not return 200");
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {target} error: {e}");
            1
        }
    }
}

fn healthcheck_once(target: &str) -> std::io::Result<bool> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf.lines().next().unwrap_or("").contains("200"))
}
