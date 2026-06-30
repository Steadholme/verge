//! Mesh coordination storage: devices, ACLs, and tags.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the keystone/keyward/inkwell seam: handlers depend only on the trait, so a FusionDB-backed
//! store can drop in later. The PostgreSQL layer uses ONLY portable standard SQL
//! (TEXT/BIGINT/BOOLEAN, PK/UNIQUE/NOT NULL/DEFAULT, parameterized queries, `INSERT .. ON
//! CONFLICT`, `CREATE INDEX`) and runtime queries (no compile-time macros), so the build needs
//! NO database and the same statements later run unchanged on FusionDB over pgwire.
//!
//! The methods are `async`: the axum handlers `.await` them directly on the serving runtime,
//! and `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async
//! bridge, so a DB round-trip never blocks a worker thread. IP allocation (a read-then-write)
//! is serialized at the handler layer with a `tokio::sync::Mutex`; the DB UNIQUE constraints on
//! `public_key` / `mesh_ip` are the backstop.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::LIST_LIMIT;

/// An enrolled device (maps 1:1 to a `devices` row). The private key is NEVER stored — only the
/// public key, derived mesh IP, and lifecycle metadata.
#[derive(Clone, Debug)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub owner_sub: String,
    pub public_key: String,
    pub mesh_ip: String,
    pub enrolled_at: i64,
    pub last_seen: i64,
    pub enabled: bool,
}

/// An ACL rule (maps 1:1 to an `acls` row): traffic from `src_tag` to `dst_tag` on `ports`.
#[derive(Clone, Debug)]
pub struct Acl {
    pub id: String,
    pub src_tag: String,
    pub dst_tag: String,
    pub ports: String,
    pub created_at: i64,
}

/// Storage failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A device with this public key or mesh IP already exists (the UNIQUE guards).
    #[error("conflict: {0}")]
    Conflict(String),
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable mesh store.
#[async_trait]
pub trait Store: Send + Sync {
    /// All devices, newest-enrolled-first, capped at [`LIST_LIMIT`].
    async fn list_devices(&self) -> Vec<Device>;
    /// One device by id.
    async fn get_device(&self, id: &str) -> Option<Device>;
    /// Enroll a device plus its tags atomically. Errors with [`StoreError::Conflict`] on a
    /// public-key / mesh-IP clash.
    async fn create_device(&self, device: &Device, tags: &[String]) -> Result<(), StoreError>;
    /// Revoke a device (set `enabled = false`). Returns `true` when a row matched.
    async fn revoke_device(&self, id: &str) -> Result<bool, StoreError>;
    /// All ACL rules, newest-first.
    async fn list_acls(&self) -> Vec<Acl>;
    /// Insert an ACL rule.
    async fn create_acl(&self, acl: &Acl) -> Result<(), StoreError>;
    /// Every `(device_id, tag)` pair, for building the per-device tag map used in ACL eval.
    async fn all_tags(&self) -> Vec<(String, String)>;
    /// Tags for a single device.
    async fn tags_for(&self, device_id: &str) -> Vec<String>;
}

/// Collapse the flat `(device_id, tag)` pairs into a per-device tag map.
pub fn tag_map(pairs: Vec<(String, String)>) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for (device_id, tag) in pairs {
        map.entry(device_id).or_default().push(tag);
    }
    map
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
struct MemData {
    devices: Vec<Device>,
    acls: Vec<Acl>,
    tags: Vec<(String, String)>,
}

#[derive(Default)]
pub struct InMemoryStore {
    data: Mutex<MemData>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no
    // `.await` inside), so a guard is never held across a yield point.
    async fn list_devices(&self) -> Vec<Device> {
        let data = self.data.lock().expect("mem lock poisoned");
        let mut v: Vec<Device> = data.devices.clone();
        v.sort_by(|a, b| {
            b.enrolled_at
                .cmp(&a.enrolled_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        v.truncate(LIST_LIMIT);
        v
    }

    async fn get_device(&self, id: &str) -> Option<Device> {
        self.data
            .lock()
            .expect("mem lock poisoned")
            .devices
            .iter()
            .find(|d| d.id == id)
            .cloned()
    }

    async fn create_device(&self, device: &Device, tags: &[String]) -> Result<(), StoreError> {
        let mut data = self.data.lock().expect("mem lock poisoned");
        if data.devices.iter().any(|d| d.public_key == device.public_key) {
            return Err(StoreError::Conflict(format!(
                "public key already enrolled: {}",
                device.public_key
            )));
        }
        if data.devices.iter().any(|d| d.mesh_ip == device.mesh_ip) {
            return Err(StoreError::Conflict(format!(
                "mesh IP already assigned: {}",
                device.mesh_ip
            )));
        }
        data.devices.push(device.clone());
        for t in tags {
            // PRIMARY KEY(device_id, tag) dedupe.
            if !data
                .tags
                .iter()
                .any(|(d, tag)| d == &device.id && tag == t)
            {
                data.tags.push((device.id.clone(), t.clone()));
            }
        }
        Ok(())
    }

    async fn revoke_device(&self, id: &str) -> Result<bool, StoreError> {
        let mut data = self.data.lock().expect("mem lock poisoned");
        match data.devices.iter_mut().find(|d| d.id == id) {
            Some(d) => {
                d.enabled = false;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn list_acls(&self) -> Vec<Acl> {
        let data = self.data.lock().expect("mem lock poisoned");
        let mut v: Vec<Acl> = data.acls.clone();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
        v
    }

    async fn create_acl(&self, acl: &Acl) -> Result<(), StoreError> {
        self.data
            .lock()
            .expect("mem lock poisoned")
            .acls
            .push(acl.clone());
        Ok(())
    }

    async fn all_tags(&self) -> Vec<(String, String)> {
        self.data.lock().expect("mem lock poisoned").tags.clone()
    }

    async fn tags_for(&self, device_id: &str) -> Vec<String> {
        self.data
            .lock()
            .expect("mem lock poisoned")
            .tags
            .iter()
            .filter(|(d, _)| d == device_id)
            .map(|(_, t)| t.clone())
            .collect()
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `MYCELIUM_STORE=postgres`. Each method drives sqlx natively and the
// handlers `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. The DB
// enforces the public_key / mesh_ip UNIQUE constraints, so a racing enroll cannot double-assign.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS devices (\
                 id TEXT PRIMARY KEY, \
                 name TEXT NOT NULL, \
                 owner_sub TEXT NOT NULL, \
                 public_key TEXT NOT NULL UNIQUE, \
                 mesh_ip TEXT NOT NULL UNIQUE, \
                 enrolled_at BIGINT, \
                 last_seen BIGINT NOT NULL DEFAULT 0, \
                 enabled BOOLEAN NOT NULL DEFAULT TRUE\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS acls (\
                 id TEXT PRIMARY KEY, \
                 src_tag TEXT NOT NULL, \
                 dst_tag TEXT NOT NULL, \
                 ports TEXT NOT NULL DEFAULT '*', \
                 created_at BIGINT\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tags (\
                 device_id TEXT NOT NULL, \
                 tag TEXT NOT NULL, \
                 PRIMARY KEY (device_id, tag)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_devices_enrolled_at ON devices (enrolled_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tags_device_id ON tags (device_id)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn device_from_row(row: &sqlx::postgres::PgRow) -> Result<Device, sqlx::Error> {
        Ok(Device {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            owner_sub: row.try_get("owner_sub")?,
            public_key: row.try_get("public_key")?,
            mesh_ip: row.try_get("mesh_ip")?,
            enrolled_at: row.try_get("enrolled_at")?,
            last_seen: row.try_get("last_seen")?,
            enabled: row.try_get("enabled")?,
        })
    }

    async fn list_devices_async(&self) -> Result<Vec<Device>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, name, owner_sub, public_key, mesh_ip, enrolled_at, last_seen, enabled \
             FROM devices ORDER BY enrolled_at DESC, id DESC LIMIT $1",
        )
        .bind(LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::device_from_row).collect()
    }

    async fn get_device_async(&self, id: &str) -> Result<Option<Device>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, name, owner_sub, public_key, mesh_ip, enrolled_at, last_seen, enabled \
             FROM devices WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Self::device_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn create_device_async(&self, d: &Device, tags: &[String]) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO devices \
                 (id, name, owner_sub, public_key, mesh_ip, enrolled_at, last_seen, enabled) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&d.id)
        .bind(&d.name)
        .bind(&d.owner_sub)
        .bind(&d.public_key)
        .bind(&d.mesh_ip)
        .bind(d.enrolled_at)
        .bind(d.last_seen)
        .bind(d.enabled)
        .execute(&self.pool)
        .await?;
        for t in tags {
            sqlx::query(
                "INSERT INTO tags (device_id, tag) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(&d.id)
            .bind(t)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn revoke_device_async(&self, id: &str) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("UPDATE devices SET enabled = FALSE WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_acls_async(&self) -> Result<Vec<Acl>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, src_tag, dst_tag, ports, created_at \
             FROM acls ORDER BY created_at DESC, id DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Acl {
                    id: r.try_get("id")?,
                    src_tag: r.try_get("src_tag")?,
                    dst_tag: r.try_get("dst_tag")?,
                    ports: r.try_get("ports")?,
                    created_at: r.try_get("created_at")?,
                })
            })
            .collect()
    }

    async fn create_acl_async(&self, a: &Acl) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO acls (id, src_tag, dst_tag, ports, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&a.id)
        .bind(&a.src_tag)
        .bind(&a.dst_tag)
        .bind(&a.ports)
        .bind(a.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn all_tags_async(&self) -> Result<Vec<(String, String)>, sqlx::Error> {
        let rows = sqlx::query("SELECT device_id, tag FROM tags")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("device_id")?, r.try_get("tag")?)))
            .collect()
    }

    async fn tags_for_async(&self, device_id: &str) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query("SELECT tag FROM tags WHERE device_id = $1 ORDER BY tag")
            .bind(device_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|r| r.try_get("tag")).collect()
    }
}

/// True when a sqlx error is a UNIQUE/PK violation (Postgres SQLSTATE 23505).
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

#[async_trait]
impl Store for PgStore {
    async fn list_devices(&self) -> Vec<Device> {
        self.list_devices_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_devices failed");
            Vec::new()
        })
    }

    async fn get_device(&self, id: &str) -> Option<Device> {
        self.get_device_async(id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_device failed");
            None
        })
    }

    async fn create_device(&self, device: &Device, tags: &[String]) -> Result<(), StoreError> {
        self.create_device_async(device, tags).await.map_err(|e| {
            if is_unique_violation(&e) {
                StoreError::Conflict("public key or mesh IP already in use".to_string())
            } else {
                StoreError::Backend(e.to_string())
            }
        })
    }

    async fn revoke_device(&self, id: &str) -> Result<bool, StoreError> {
        self.revoke_device_async(id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_acls(&self) -> Vec<Acl> {
        self.list_acls_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_acls failed");
            Vec::new()
        })
    }

    async fn create_acl(&self, acl: &Acl) -> Result<(), StoreError> {
        self.create_acl_async(acl)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn all_tags(&self) -> Vec<(String, String)> {
        self.all_tags_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg all_tags failed");
            Vec::new()
        })
    }

    async fn tags_for(&self, device_id: &str) -> Vec<String> {
        self.tags_for_async(device_id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg tags_for failed");
            Vec::new()
        })
    }
}
