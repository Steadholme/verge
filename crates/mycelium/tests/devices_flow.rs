//! End-to-end HTTP flow over the in-memory store (NO database).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate.
//! Covers: health, empty dashboard, the SSO/CSRF guards on enrollment, real enroll (server
//! keygen + IP assignment + one-time conf), hub-and-spoke conf generation, the no-private-key re-render,
//! revoke, and ACL add (posture flip).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use mycelium::clash::ClashSubscription;
use mycelium::{app, build_dev_state};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn stylesheet_is_versioned_and_immutable() {
    let resp = app(build_dev_state())
        .oneshot(get("/assets/mycelium-20260908.css"))
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
    let (_, css) = read(resp).await;
    assert!(css.len() > 100_000);
}

#[tokio::test]
async fn full_mesh_flow_in_memory() {
    let state = build_dev_state();

    // --- health ------------------------------------------------------------
    let (status, _) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);

    // --- empty dashboard sets a CSRF cookie + shows the empty state --------
    let resp = app(state.clone()).oneshot(get("/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        set_cookie.contains("__Host-csrf="),
        "GET / mints CSRF cookie"
    );
    let (_, body) = read(resp).await;
    assert!(body.contains("No devices enrolled yet"));
    assert!(body.contains("10.77.0.0/24"), "CIDR summary shown");
    assert!(body.contains(r#"<link rel="stylesheet" href="/assets/mycelium-20260908.css">"#));
    assert!(!body.contains("<style>"));

    // --- enroll without identity -> 401 ------------------------------------
    let b = form(&[("name", "nope"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/devices", &b, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no X-Auth -> 401");

    // --- enroll with bad CSRF -> 401 ---------------------------------------
    let b = form(&[("name", "nope"), ("csrf_token", "WRONG")]);
    let (status, _) = call(
        &state,
        post_csrf("/api/devices", &b, Some(("u_admin", "admin@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "CSRF mismatch -> 401");

    // --- enroll device #1: alice-laptop ------------------------------------
    let b = form(&[
        ("name", "alice-laptop"),
        ("tags", "web"),
        ("csrf_token", CSRF),
    ]);
    let (status, body) = call(
        &state,
        post_csrf("/api/devices", &b, Some(("u_admin", "admin@hf"))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "enroll returns the one-time conf page"
    );
    assert!(body.contains("PrivateKey = "), "private key shown once");
    assert!(body.contains("Address = 10.77.0.2/32"), "first host is .2");
    assert!(body.contains("DNS = 10.77.0.1"), "DNS is the gateway slot");

    // --- enroll device #2: db ----------------------------------------------
    let b = form(&[("name", "db"), ("tags", "db"), ("csrf_token", CSRF)]);
    let (status, body) = call(
        &state,
        post_csrf("/api/devices", &b, Some(("u_admin", "admin@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Address = 10.77.0.3/32"), "second host is .3");
    // Hub-and-spoke: the client conf carries ONLY the hub peer, never a per-device mesh list.
    assert!(body.contains("[Peer]"), "hub peer block present");
    assert!(
        body.contains("Endpoint = vpn.w33d.xyz:51820"),
        "dials the hub endpoint"
    );
    assert!(
        body.contains("AllowedIPs = 10.77.0.0/24"),
        "routes the whole mesh via the hub"
    );
    assert!(
        body.contains("PersistentKeepalive = 25"),
        "keepalive for NAT traversal"
    );
    assert!(
        !body.contains("AllowedIPs = 10.77.0.2/32"),
        "no per-spoke /32 peer in client conf"
    );

    // --- dashboard now lists both ------------------------------------------
    let (_, dash) = call(&state, get_auth("/", "u_admin", "admin@hf")).await;
    assert!(dash.contains("alice-laptop"));
    assert!(dash.contains("db"));
    assert!(dash.contains("10.77.0.2"));
    assert!(dash.contains("10.77.0.3"));
    assert!(dash.contains("Active"), "active badge");
    assert!(dash.contains("2 / 2"), "device count summary");

    // --- re-render the first-listed device's config WITHOUT the private key.
    // The dashboard lists newest-enrolled first, so this is `db` (10.77.0.3); its peer is the hub.
    let first_id = extract_first_device_id(&dash).expect("a device id in the dashboard");
    let (status, conf) = call(
        &state,
        get_auth(&format!("/api/config/{first_id}"), "u_admin", "admin@hf"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        conf.contains("# PrivateKey ="),
        "re-render omits the real private key"
    );
    assert!(
        !conf.contains("\nPrivateKey ="),
        "no uncommented private key line on re-render"
    );
    assert!(
        conf.contains("Address = 10.77.0.3/32"),
        "re-render keeps the device's own address"
    );
    assert!(
        conf.contains("Endpoint = vpn.w33d.xyz:51820"),
        "re-render dials the hub"
    );
    assert!(
        conf.contains("AllowedIPs = 10.77.0.0/24"),
        "re-render routes the mesh via the hub"
    );

    // --- config for an unknown device -> 404 -------------------------------
    let (status, _) = call(
        &state,
        get_auth("/api/config/dev_missing", "u_admin", "admin@hf"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // --- revoke the first-listed device ------------------------------------
    let b = form(&[("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf(
            &format!("/api/devices/{first_id}/revoke"),
            &b,
            Some(("u_admin", "admin@hf")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "revoke redirects");
    let (_, dash) = call(&state, get_auth("/", "u_admin", "admin@hf")).await;
    assert!(dash.contains("Revoked"), "revoked badge after revoke");
    assert!(dash.contains("1 / 2"), "one active of two total");

    // --- add an ACL: flips posture to default-deny -------------------------
    let b = form(&[
        ("src_tag", "web"),
        ("dst_tag", "db"),
        ("ports", "443"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/api/acls", &b, Some(("u_admin", "admin@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, dash) = call(&state, get_auth("/", "u_admin", "admin@hf")).await;
    assert!(
        dash.contains("default-deny"),
        "posture flips after first ACL"
    );
    assert!(
        dash.contains(">web<") || dash.contains("web"),
        "src tag shown"
    );
}

#[tokio::test]
async fn clash_profile_link_is_authenticated_csrf_protected_and_publicly_downloadable() {
    let mut state = build_dev_state();
    state.clash = Some(Arc::new(
        ClashSubscription::new(
            b"proxies:\n  - name: DMIT-HK\n".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
            "https://vpn.example.test",
        )
        .unwrap(),
    ));

    let (status, _) = call(&state, get("/profiles")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, page) = call(&state, get_auth("/profiles", "u_admin", "admin@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Generate online subscription"));
    assert!(page.contains("independent from WireGuard"));

    let (status, _) = call(
        &state,
        get_auth("/api/clash/capability", "u_admin", "admin@hf"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let body = form(&[("csrf_token", CSRF)]);
    let response = app(state.clone())
        .oneshot(post_csrf(
            "/api/clash/subscription-link",
            &body,
            Some(("u_admin", "admin@hf")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let (_, link_page) = read(response).await;
    let token = extract_subscription_token(&link_page).expect("subscription token in link page");
    assert!(!token.contains("u_admin"));

    let response = app(state.clone())
        .oneshot(get(&format!("/subscription/clash?token={token}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/yaml; charset=utf-8")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let (_, profile) = read(response).await;
    assert_eq!(profile, "proxies:\n  - name: DMIT-HK\n");

    let (status, _) = call(&state, get(&format!("/subscription/clash?token={token}x"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Pull the first `dev_...` id out of a `/api/config/<id>` link in the dashboard HTML.
fn extract_first_device_id(html: &str) -> Option<String> {
    let marker = "/api/config/";
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_subscription_token(html: &str) -> Option<String> {
    let marker = "/subscription/clash?token=";
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest.find(['\"', '&', '<'])?;
    Some(rest[..end].to_string())
}

async fn call(state: &mycelium::AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    read(resp).await
}

async fn read(resp: axum::response::Response) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_auth(uri: &str, sub: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
}

/// Build a urlencoded POST carrying the test CSRF cookie + (optionally) gateway identity.
fn post_csrf(uri: &str, body: &str, ident: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    if let Some((sub, email)) = ident {
        b = b
            .header("x-auth-subject", sub)
            .header("x-auth-email", email);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Minimal application/x-www-form-urlencoded value encoder.
fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}
