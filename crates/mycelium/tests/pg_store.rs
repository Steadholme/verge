//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the
//! test prints a note and returns early — it never fails the default `cargo test` run, which
//! stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=mycelium \
//!   -p 127.0.0.1:55490:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55490/mycelium \
//!   cargo test --test pg_store -- --nocapture
//! ```

use mycelium::now_secs;
use mycelium::store::{Acl, Device, PgStore, Store, StoreError};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test \
             (needs external Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url)
        .await
        .expect("connect TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    let now = now_secs();
    let suffix = now_nanos_suffix();

    // --- create a device with tags -----------------------------------------
    let dev1 = Device {
        id: format!("dev_pg_a_{suffix}"),
        name: "pg-laptop".to_string(),
        owner_sub: "u_alice".to_string(),
        public_key: format!("PUBKEY_A_{suffix}"),
        mesh_ip: format!("10.99.{}.2", suffix % 200),
        enrolled_at: now - 100,
        last_seen: 0,
        enabled: true,
    };
    pg.create_device(&dev1, &["web".to_string(), "prod".to_string()])
        .await
        .expect("create dev1");

    // Duplicate public key -> Conflict (the UNIQUE(public_key) guard).
    let dup = Device {
        id: format!("dev_pg_dup_{suffix}"),
        mesh_ip: format!("10.99.{}.9", suffix % 200),
        ..dev1.clone()
    };
    assert!(
        matches!(
            pg.create_device(&dup, &[]).await,
            Err(StoreError::Conflict(_))
        ),
        "duplicate public key rejected"
    );

    // --- second device -----------------------------------------------------
    let dev2 = Device {
        id: format!("dev_pg_b_{suffix}"),
        name: "pg-db".to_string(),
        owner_sub: "u_alice".to_string(),
        public_key: format!("PUBKEY_B_{suffix}"),
        mesh_ip: format!("10.99.{}.3", suffix % 200),
        enrolled_at: now,
        last_seen: 0,
        enabled: true,
    };
    pg.create_device(&dev2, &["db".to_string()])
        .await
        .expect("create dev2");

    // --- list / get --------------------------------------------------------
    let fetched = pg.get_device(&dev1.id).await.expect("get dev1");
    assert_eq!(fetched.name, "pg-laptop");
    assert!(fetched.enabled);

    let tags = pg.tags_for(&dev1.id).await;
    assert!(tags.contains(&"web".to_string()) && tags.contains(&"prod".to_string()));

    let all_tags = pg.all_tags().await;
    assert!(all_tags.iter().any(|(d, t)| d == &dev2.id && t == "db"));

    // --- revoke ------------------------------------------------------------
    assert!(pg.revoke_device(&dev1.id).await.expect("revoke"));
    assert!(!pg
        .revoke_device("dev_does_not_exist")
        .await
        .expect("revoke missing"));
    let after = pg.get_device(&dev1.id).await.expect("refetch");
    assert!(!after.enabled, "revoked device disabled");

    // --- ACLs --------------------------------------------------------------
    let acl = Acl {
        id: format!("acl_pg_{suffix}"),
        src_tag: "web".to_string(),
        dst_tag: "db".to_string(),
        ports: "443".to_string(),
        created_at: now,
    };
    pg.create_acl(&acl).await.expect("create acl");
    let acls = pg.list_acls().await;
    assert!(acls.iter().any(|a| a.id == acl.id && a.ports == "443"));

    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + device create/conflict/list/get/tags + \
         revoke + acl round-trip against real Postgres"
    );
}

/// A small unique suffix so reruns against the same DB do not collide on PKs.
fn now_nanos_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
