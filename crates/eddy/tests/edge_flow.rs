//! End-to-end tests driving the real router in-process via `tower::oneshot` (no port bind), the
//! same way the rest of the estate tests its services. Covers: health, the multipart upload ->
//! content-addressed serve path, conditional `304` + `Range` semantics, CSRF enforcement, exact
//! purge, and the HMAC signed-URL gate.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use eddy::audit::AuditSink;
use eddy::blobs::{Blobs, MemoryBlobs};
use eddy::config::Config;
use eddy::store::{InMemoryStore, Store};
use eddy::{app, build_dev_state, build_http_client, AppState};
use tower::ServiceExt;

const CSRF: &str = "testcsrftoken000000000000000000000000000";
const BOUNDARY: &str = "EDDYTESTBOUNDARY";

/// Build an `AppState` with a specific config (in-memory store + blobs, audit off).
fn state_with(config: Config) -> AppState {
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let blobs: Arc<dyn Blobs> = Arc::new(MemoryBlobs::new());
    AppState {
        config: Arc::new(config),
        store,
        blobs,
        http: build_http_client(),
        audit: AuditSink::disabled(),
    }
}

/// A `multipart/form-data` body with a `csrf_token`, a `path`, and a `file` part.
fn multipart_upload(path: &str, filename: &str, ctype: &str, content: &[u8]) -> Vec<u8> {
    let head = format!(
        "--{BOUNDARY}\r\n\
         Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n{CSRF}\r\n\
         --{BOUNDARY}\r\n\
         Content-Disposition: form-data; name=\"path\"\r\n\r\n{path}\r\n\
         --{BOUNDARY}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: {ctype}\r\n\r\n"
    );
    let mut body = Vec::new();
    body.extend_from_slice(head.as_bytes());
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn upload_request(path: &str, filename: &str, ctype: &str, content: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/assets")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .body(Body::from(multipart_upload(path, filename, ctype, content)))
        .unwrap()
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn healthz_is_ok() {
    let app = app(build_dev_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, b"ok");
}

#[tokio::test]
async fn stylesheet_is_versioned_and_immutable() {
    let resp = app(build_dev_state())
        .oneshot(
            Request::builder()
                .uri("/assets/eddy-20260908.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/css; charset=utf-8"
    );
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=31536000, immutable"
    );
    assert!(body_bytes(resp).await.len() > 100_000);
}

#[tokio::test]
async fn console_links_the_shared_stylesheet_without_inlining_it() {
    let resp = app(build_dev_state())
        .oneshot(
            Request::builder()
                .uri("/")
                .header("x-auth-subject", "u_admin")
                .header("x-auth-email", "admin@w33d.xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(html.contains(r#"<link rel="stylesheet" href="/assets/eddy-20260908.css">"#));
    assert!(!html.contains("<style>"));
}

#[tokio::test]
async fn upload_then_serve_with_validators_and_range() {
    let app = app(build_dev_state());
    let content = b"body{color:rebeccapurple}";

    // Upload via multipart.
    let resp = app
        .clone()
        .oneshot(upload_request(
            "css/app.css",
            "app.css",
            "text/css",
            content,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "upload renders the dashboard"
    );

    // Serve the cached asset.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/a/css/app.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        etag.starts_with('"') && etag.len() == 66,
        "strong sha256 ETag"
    );
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/css; charset=utf-8"
    );
    assert!(resp
        .headers()
        .get(header::CACHE_CONTROL)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("max-age="));
    assert_eq!(resp.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");
    assert_eq!(body_bytes(resp).await, content);

    // Conditional revalidation: If-None-Match -> 304, empty body.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/a/css/app.css")
                .header(header::IF_NONE_MATCH, &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert!(body_bytes(resp).await.is_empty());

    // Range -> 206 partial with Content-Range.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/a/css/app.css")
                .header(header::RANGE, "bytes=0-3")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers().get(header::CONTENT_RANGE).unwrap(),
        &format!("bytes 0-3/{}", content.len())
    );
    assert_eq!(body_bytes(resp).await, &content[0..=3]);

    // Unknown path -> 404.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/a/missing.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn upload_without_csrf_is_rejected() {
    let app = app(build_dev_state());
    // Same multipart body but NO cookie -> the double-submit check fails.
    let req = Request::builder()
        .method("POST")
        .uri("/api/assets")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(multipart_upload(
            "x.css", "x.css", "text/css", b"a",
        )))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn purge_by_path_removes_the_asset() {
    let app = app(build_dev_state());
    app.clone()
        .oneshot(upload_request(
            "logo.png",
            "logo.png",
            "image/png",
            b"\x89PNGxx",
        ))
        .await
        .unwrap();

    // Purge it (urlencoded form + matching CSRF cookie).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/purge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
                .body(Body::from(format!("csrf_token={CSRF}&path=logo.png")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Gone from the edge.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/a/logo.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signed_url_is_required_when_key_set() {
    let mut config = Config::dev();
    config.signing_key = Some("edge-signing-key".to_string());
    let app = app(state_with(config));

    // Upload (signing does not affect the SSO management path).
    app.clone()
        .oneshot(upload_request(
            "js/app.js",
            "app.js",
            "text/javascript",
            b"console.log(1)",
        ))
        .await
        .unwrap();

    // No signature -> 403.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/a/js/app.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Valid signature (no expiry) -> 200.
    let sig = eddy::sign::sign(b"edge-signing-key", "js/app.js", 0);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/a/js/app.js?exp=0&sig={sig}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
