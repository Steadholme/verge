//! Content-addressed blob storage.
//!
//! `Blobs` is a small async trait with two implementations, mirroring the metadata [`crate::store`]
//! seam: handlers depend only on the trait, so the DB-free test suite needs no volume.
//!
//! - [`MemoryBlobs`] — an in-process map; the default for dev + tests.
//! - [`FsBlobs`] — bytes on the mounted `EDDY_DATA` volume, content-addressed at `<root>/<sha256>`
//!   (a flat directory; the filename IS the digest). Publishing is atomic (write a temp file then
//!   rename), so a crash never leaves a torn blob at its content address, and identical bytes across
//!   assets collapse to one file (free de-dup).
//!
//! Keys are the lowercase-hex SHA-256 of the bytes; both backends reject a non-hex key, so a crafted
//! key can never escape the blobs directory.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

/// Blob failure surfaced to the handler layer. A missing object is distinguished so the edge can map
/// it to a 404 rather than a 500.
#[derive(Debug, Error)]
pub enum BlobError {
    #[error("blob not found")]
    NotFound,
    #[error("invalid blob key")]
    InvalidKey,
    #[error("blob store error: {0}")]
    Backend(String),
}

/// Pluggable content-addressed blob store. Keys are a 64-char lowercase-hex SHA-256. Bodies are
/// buffered whole (assets are size-capped well under memory limits), which keeps the trait trivial
/// and identical on both backends.
#[async_trait]
pub trait Blobs: Send + Sync {
    /// A short label for the backend (shown on the console; self-describing).
    fn backend(&self) -> &str;

    /// Store `bytes` under content-address `key` (idempotent: identical bytes already present is a
    /// no-op success).
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), BlobError>;

    /// Fetch the whole object at `key`. `NotFound` when it does not exist.
    async fn get(&self, key: &str) -> Result<Vec<u8>, BlobError>;

    /// Remove the object at `key`. Deleting a missing object is a no-op (Ok).
    async fn delete(&self, key: &str) -> Result<(), BlobError>;
}

/// A valid content-address key is exactly 64 lowercase hex chars (a SHA-256 digest).
fn valid_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

// --------------------------------------------------------------------------------------
// In-memory blobs (the default; keeps the whole service volume-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Blobs`. The `Mutex<HashMap<_>>` critical sections are fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct MemoryBlobs {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryBlobs {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Blobs for MemoryBlobs {
    fn backend(&self) -> &str {
        "memory"
    }

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), BlobError> {
        if !valid_key(key) {
            return Err(BlobError::InvalidKey);
        }
        self.objects
            .lock()
            .expect("objects lock poisoned")
            .entry(key.to_string())
            .or_insert(bytes);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, BlobError> {
        if !valid_key(key) {
            return Err(BlobError::InvalidKey);
        }
        self.objects
            .lock()
            .expect("objects lock poisoned")
            .get(key)
            .cloned()
            .ok_or(BlobError::NotFound)
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        if !valid_key(key) {
            return Err(BlobError::InvalidKey);
        }
        self.objects
            .lock()
            .expect("objects lock poisoned")
            .remove(key);
        Ok(())
    }
}

// --------------------------------------------------------------------------------------
// Filesystem blobs (content-addressed files on the EDDY_DATA volume).
// --------------------------------------------------------------------------------------

/// Filesystem-backed `Blobs`. Blobs live flat at `<root>/<sha256>`; publishing is atomic (write a
/// temp file then rename).
pub struct FsBlobs {
    root: PathBuf,
}

impl FsBlobs {
    /// Open the store rooted at `blobs_root`, creating it as needed.
    pub async fn open(blobs_root: &str) -> Result<Self, BlobError> {
        let root = PathBuf::from(blobs_root);
        tokio::fs::create_dir_all(&root)
            .await
            .map_err(|e| BlobError::Backend(format!("create {}: {e}", root.display())))?;
        Ok(Self { root })
    }

    fn blob_path(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }
}

#[async_trait]
impl Blobs for FsBlobs {
    fn backend(&self) -> &str {
        "fs"
    }

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), BlobError> {
        if !valid_key(key) {
            return Err(BlobError::InvalidKey);
        }
        let final_path = self.blob_path(key);
        // Idempotent: identical bytes are already published at this content address.
        if tokio::fs::try_exists(&final_path).await.unwrap_or(false) {
            return Ok(());
        }
        let tmp = self.root.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            crate::random_alnum(16)
        ));
        tokio::fs::write(&tmp, &bytes)
            .await
            .map_err(|e| BlobError::Backend(format!("write temp blob: {e}")))?;
        match tokio::fs::rename(&tmp, &final_path).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                if tokio::fs::try_exists(&final_path).await.unwrap_or(false) {
                    Ok(()) // lost a publish race — fine, same bytes
                } else {
                    Err(BlobError::Backend(format!("publish blob: {e}")))
                }
            }
        }
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, BlobError> {
        if !valid_key(key) {
            return Err(BlobError::InvalidKey);
        }
        match tokio::fs::read(self.blob_path(key)).await {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(BlobError::NotFound),
            Err(e) => Err(BlobError::Backend(format!("read blob: {e}"))),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        if !valid_key(key) {
            return Err(BlobError::InvalidKey);
        }
        match tokio::fs::remove_file(self.blob_path(key)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(BlobError::Backend(format!("delete blob: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_hex;

    async fn round_trip(store: &dyn Blobs) {
        let payload = b"a tiny css file".to_vec();
        let key = sha256_hex(&payload);
        assert!(matches!(store.get(&key).await, Err(BlobError::NotFound)));
        store.put(&key, payload.clone()).await.unwrap();
        assert_eq!(store.get(&key).await.unwrap(), payload);
        // Idempotent re-put.
        store.put(&key, payload.clone()).await.unwrap();
        store.delete(&key).await.unwrap();
        assert!(matches!(store.get(&key).await, Err(BlobError::NotFound)));
        // Deleting a missing key is a no-op.
        store.delete(&key).await.unwrap();
    }

    #[tokio::test]
    async fn memory_round_trip() {
        round_trip(&MemoryBlobs::new()).await;
    }

    #[tokio::test]
    async fn fs_round_trip() {
        let dir = std::env::temp_dir().join(format!("eddy-test-{}", crate::random_alnum(12)));
        let store = FsBlobs::open(dir.to_str().unwrap()).await.unwrap();
        round_trip(&store).await;
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn rejects_non_hex_key() {
        let store = MemoryBlobs::new();
        assert!(matches!(store.get("../escape").await, Err(BlobError::InvalidKey)));
        assert!(matches!(store.put("short", vec![1]).await, Err(BlobError::InvalidKey)));
    }
}
