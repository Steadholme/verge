//! Asset metadata storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring the
//! relay/aperture seam: handlers depend only on the trait. The PostgreSQL layer uses ONLY portable
//! standard SQL (TEXT/BIGINT, PK/UNIQUE/NOT NULL/DEFAULT, INSERT..ON CONFLICT, an aggregate, a
//! CREATE INDEX) and runtime queries (no compile-time macros), so the build needs NO database and
//! the same statements later run unchanged on FusionDB over pgwire.
//!
//! The methods are `async`: the axum handlers `.await` them directly on the serving runtime, and
//! `PgStore` drives sqlx natively — NO `block_in_place`, NO sync-over-async bridge.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::LIST_LIMIT;

/// A cached asset (maps 1:1 to an `assets` row). The bytes themselves live in the blob store, keyed
/// by `content_hash`; this row is just the metadata + edge stats.
#[derive(Clone, Debug)]
pub struct Asset {
    pub id: String,
    pub path: String,
    pub content_hash: String,
    pub content_type: String,
    pub bytes: i64,
    pub origin_url: String,
    pub created_at: i64,
    pub hits: i64,
}

/// Aggregate cache stats for the console summary.
#[derive(Clone, Debug, Default)]
pub struct CacheStats {
    /// Number of asset rows.
    pub count: i64,
    /// Sum of asset byte sizes.
    pub total_bytes: i64,
    /// Sum of edge hits served.
    pub total_hits: i64,
    /// Distinct content hashes (the number of physical blobs after de-dup).
    pub distinct_blobs: i64,
}

/// Storage failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable asset-metadata store.
#[async_trait]
pub trait Store: Send + Sync {
    /// All assets, newest-first (`created_at` DESC), capped at [`LIST_LIMIT`].
    async fn list_assets(&self) -> Vec<Asset>;
    /// One asset by its unique path.
    async fn get_by_path(&self, path: &str) -> Option<Asset>;
    /// Insert-or-replace an asset by path: a fresh `path` inserts; an existing one updates its
    /// content fields (hash/type/bytes/origin) while preserving `created_at` + `hits`.
    async fn upsert_asset(&self, asset: &Asset) -> Result<(), StoreError>;
    /// Increment the edge hit counter for `path` (best-effort; never fails a served request).
    async fn bump_hits(&self, path: &str);
    /// Delete the asset at `path`. Returns `true` when a row existed.
    async fn delete_by_path(&self, path: &str) -> Result<bool, StoreError>;
    /// Delete every asset whose `content_hash` equals `hash`. Returns the number of rows removed.
    async fn delete_by_hash(&self, hash: &str) -> Result<u64, StoreError>;
    /// How many asset rows still reference `hash` (used to garbage-collect an unreferenced blob).
    async fn count_by_hash(&self, hash: &str) -> Result<i64, StoreError>;
    /// Aggregate cache stats for the console.
    async fn stats(&self) -> CacheStats;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    assets: Mutex<Vec<Asset>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no `.await`
    // inside), so a guard is never held across a yield point.
    async fn list_assets(&self) -> Vec<Asset> {
        let assets = self.assets.lock().expect("assets lock poisoned");
        let mut v: Vec<Asset> = assets.clone();
        // Newest-first; ties broken by id so output is stable.
        v.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        v.truncate(LIST_LIMIT);
        v
    }

    async fn get_by_path(&self, path: &str) -> Option<Asset> {
        self.assets
            .lock()
            .expect("assets lock poisoned")
            .iter()
            .find(|a| a.path == path)
            .cloned()
    }

    async fn upsert_asset(&self, asset: &Asset) -> Result<(), StoreError> {
        let mut assets = self.assets.lock().expect("assets lock poisoned");
        match assets.iter_mut().find(|a| a.path == asset.path) {
            Some(existing) => {
                // Preserve created_at + hits; replace only the content fields.
                existing.content_hash = asset.content_hash.clone();
                existing.content_type = asset.content_type.clone();
                existing.bytes = asset.bytes;
                existing.origin_url = asset.origin_url.clone();
            }
            None => assets.push(asset.clone()),
        }
        Ok(())
    }

    async fn bump_hits(&self, path: &str) {
        let mut assets = self.assets.lock().expect("assets lock poisoned");
        if let Some(a) = assets.iter_mut().find(|a| a.path == path) {
            a.hits += 1;
        }
    }

    async fn delete_by_path(&self, path: &str) -> Result<bool, StoreError> {
        let mut assets = self.assets.lock().expect("assets lock poisoned");
        let before = assets.len();
        assets.retain(|a| a.path != path);
        Ok(assets.len() != before)
    }

    async fn delete_by_hash(&self, hash: &str) -> Result<u64, StoreError> {
        let mut assets = self.assets.lock().expect("assets lock poisoned");
        let before = assets.len();
        assets.retain(|a| a.content_hash != hash);
        Ok((before - assets.len()) as u64)
    }

    async fn count_by_hash(&self, hash: &str) -> Result<i64, StoreError> {
        let assets = self.assets.lock().expect("assets lock poisoned");
        Ok(assets.iter().filter(|a| a.content_hash == hash).count() as i64)
    }

    async fn stats(&self) -> CacheStats {
        let assets = self.assets.lock().expect("assets lock poisoned");
        let mut hashes: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut s = CacheStats::default();
        for a in assets.iter() {
            s.count += 1;
            s.total_bytes += a.bytes;
            s.total_hits += a.hits;
            hashes.insert(a.content_hash.as_str());
        }
        s.distinct_blobs = hashes.len() as i64;
        s
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `EDDY_STORE=postgres`. Each method drives sqlx natively and the handlers
// `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. The DB enforces the
// path UNIQUE constraint, so the upsert is a single atomic `INSERT .. ON CONFLICT`.

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
            "CREATE TABLE IF NOT EXISTS assets (\
                 id TEXT PRIMARY KEY, \
                 path TEXT UNIQUE NOT NULL, \
                 content_hash TEXT NOT NULL, \
                 content_type TEXT NOT NULL DEFAULT 'application/octet-stream', \
                 bytes BIGINT NOT NULL DEFAULT 0, \
                 origin_url TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT, \
                 hits BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs purge-by-hash + the unreferenced-blob garbage collection lookup.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_assets_content_hash ON assets (content_hash)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn asset_from_row(row: &sqlx::postgres::PgRow) -> Result<Asset, sqlx::Error> {
        Ok(Asset {
            id: row.try_get("id")?,
            path: row.try_get("path")?,
            content_hash: row.try_get("content_hash")?,
            content_type: row.try_get("content_type")?,
            bytes: row.try_get("bytes")?,
            origin_url: row.try_get("origin_url")?,
            // created_at is nullable in the schema; default a missing value to 0.
            created_at: row.try_get::<Option<i64>, _>("created_at")?.unwrap_or(0),
            hits: row.try_get("hits")?,
        })
    }

    const COLS: &'static str =
        "id, path, content_hash, content_type, bytes, origin_url, created_at, hits";

    async fn list_assets_async(&self) -> Result<Vec<Asset>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {} FROM assets ORDER BY created_at DESC, id DESC LIMIT $1",
            Self::COLS
        ))
        .bind(LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::asset_from_row).collect()
    }

    async fn get_by_path_async(&self, path: &str) -> Result<Option<Asset>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {} FROM assets WHERE path = $1",
            Self::COLS
        ))
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Self::asset_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn upsert_async(&self, a: &Asset) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO assets \
                 (id, path, content_hash, content_type, bytes, origin_url, created_at, hits) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (path) DO UPDATE SET \
                 content_hash = EXCLUDED.content_hash, \
                 content_type = EXCLUDED.content_type, \
                 bytes = EXCLUDED.bytes, \
                 origin_url = EXCLUDED.origin_url",
        )
        .bind(&a.id)
        .bind(&a.path)
        .bind(&a.content_hash)
        .bind(&a.content_type)
        .bind(a.bytes)
        .bind(&a.origin_url)
        .bind(a.created_at)
        .bind(a.hits)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Store for PgStore {
    async fn list_assets(&self) -> Vec<Asset> {
        self.list_assets_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_assets failed");
            Vec::new()
        })
    }

    async fn get_by_path(&self, path: &str) -> Option<Asset> {
        self.get_by_path_async(path).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_by_path failed");
            None
        })
    }

    async fn upsert_asset(&self, asset: &Asset) -> Result<(), StoreError> {
        self.upsert_async(asset)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn bump_hits(&self, path: &str) {
        if let Err(e) = sqlx::query("UPDATE assets SET hits = hits + 1 WHERE path = $1")
            .bind(path)
            .execute(&self.pool)
            .await
        {
            tracing::warn!(error = %e, "pg bump_hits failed (asset still served)");
        }
    }

    async fn delete_by_path(&self, path: &str) -> Result<bool, StoreError> {
        let res = sqlx::query("DELETE FROM assets WHERE path = $1")
            .bind(path)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_by_hash(&self, hash: &str) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM assets WHERE content_hash = $1")
            .bind(hash)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(res.rows_affected())
    }

    async fn count_by_hash(&self, hash: &str) -> Result<i64, StoreError> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM assets WHERE content_hash = $1")
            .bind(hash)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.try_get("n")
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn stats(&self) -> CacheStats {
        let row = sqlx::query(
            "SELECT COUNT(*) AS n, \
                    CAST(COALESCE(SUM(bytes), 0) AS BIGINT) AS b, \
                    CAST(COALESCE(SUM(hits), 0) AS BIGINT) AS h, \
                    COUNT(DISTINCT content_hash) AS d \
             FROM assets",
        )
        .fetch_one(&self.pool)
        .await;
        match row {
            Ok(r) => CacheStats {
                count: r.try_get("n").unwrap_or(0),
                total_bytes: r.try_get("b").unwrap_or(0),
                total_hits: r.try_get("h").unwrap_or(0),
                distinct_blobs: r.try_get("d").unwrap_or(0),
            },
            Err(e) => {
                tracing::error!(error = %e, "pg stats failed");
                CacheStats::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(path: &str, hash: &str, bytes: i64) -> Asset {
        Asset {
            id: format!("as_{path}"),
            path: path.to_string(),
            content_hash: hash.to_string(),
            content_type: "text/css".to_string(),
            bytes,
            origin_url: String::new(),
            created_at: 100,
            hits: 0,
        }
    }

    #[tokio::test]
    async fn upsert_preserves_hits_and_replaces_content() {
        let s = InMemoryStore::new();
        s.upsert_asset(&asset("a.css", "h1", 10)).await.unwrap();
        s.bump_hits("a.css").await;
        s.bump_hits("a.css").await;
        // Re-upsert same path with new content: hits preserved, content replaced.
        s.upsert_asset(&asset("a.css", "h2", 20)).await.unwrap();
        let got = s.get_by_path("a.css").await.unwrap();
        assert_eq!(got.content_hash, "h2");
        assert_eq!(got.bytes, 20);
        assert_eq!(got.hits, 2);
    }

    #[tokio::test]
    async fn purge_and_refcount() {
        let s = InMemoryStore::new();
        // Two paths sharing one content hash (de-dup).
        s.upsert_asset(&asset("a.css", "shared", 10)).await.unwrap();
        s.upsert_asset(&asset("b.css", "shared", 10)).await.unwrap();
        assert_eq!(s.count_by_hash("shared").await.unwrap(), 2);
        assert!(s.delete_by_path("a.css").await.unwrap());
        assert_eq!(s.count_by_hash("shared").await.unwrap(), 1);
        // Purge by hash removes the remaining one.
        assert_eq!(s.delete_by_hash("shared").await.unwrap(), 1);
        assert_eq!(s.count_by_hash("shared").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn stats_aggregate() {
        let s = InMemoryStore::new();
        s.upsert_asset(&asset("a.css", "shared", 10)).await.unwrap();
        s.upsert_asset(&asset("b.css", "shared", 10)).await.unwrap();
        s.upsert_asset(&asset("c.js", "other", 5)).await.unwrap();
        s.bump_hits("a.css").await;
        let st = s.stats().await;
        assert_eq!(st.count, 3);
        assert_eq!(st.total_bytes, 25);
        assert_eq!(st.total_hits, 1);
        assert_eq!(st.distinct_blobs, 2);
    }
}
