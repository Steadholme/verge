//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration, NO database, and NO volume — exactly like
//! relay/aperture/cellar. Production overrides each via the environment. The HMAC signing key is
//! resolved here but never logged.

/// Default listen address (all interfaces, internal-only port 9220).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9220";

/// Default on-disk data root (`EDDY_DATA`). Content-addressed bytes live under `<data>/blobs/<sha256>`.
pub const DEFAULT_DATA_DIR: &str = "/data";

/// Public base URL of this edge (used to render the `/a/` URLs on the console).
pub const DEFAULT_PUBLIC_BASE_URL: &str = "https://edge.w33d.xyz";

/// Default `Cache-Control: public, max-age=<n>` for served assets (1 day).
pub const DEFAULT_CACHE_MAX_AGE: u64 = 86_400;

/// Default validity window for a freshly minted HMAC-signed `/a/` URL (1 hour).
pub const DEFAULT_SIGNED_TTL: i64 = 3_600;

/// Default hard cap on a single cached asset's byte length (25 MiB).
pub const DEFAULT_MAX_ASSET: usize = 25 * 1024 * 1024;

/// Hard cap on how many assets the console list renders (keeps an unbounded list bounded).
pub const LIST_LIMIT: usize = 500;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// On-disk data root (`EDDY_DATA`); content-addressed blobs live under `<data>/blobs`.
    pub data_dir: String,
    /// Public base URL (`PUBLIC_BASE_URL`) used to render `/a/` URLs.
    pub public_base_url: String,
    /// `Cache-Control` max-age in seconds (`EDDY_CACHE_MAX_AGE`).
    pub cache_max_age: u64,
    /// Signed-URL validity window in seconds (`EDDY_SIGNED_TTL`).
    pub signed_ttl: i64,
    /// Per-asset byte cap (`EDDY_MAX_ASSET`).
    pub max_asset: usize,
    /// Optional HMAC signing key (`EDDY_SIGNING_KEY`). When set, every `/a/` request must carry a
    /// valid `?exp=&sig=`; when unset, `/a/` is open (still public, no IP leak to the origin).
    pub signing_key: Option<String>,
}

impl Config {
    /// Default development configuration (in-memory store + blobs, no database, no signing).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            data_dir: DEFAULT_DATA_DIR.to_string(),
            public_base_url: DEFAULT_PUBLIC_BASE_URL.to_string(),
            cache_max_age: DEFAULT_CACHE_MAX_AGE,
            signed_ttl: DEFAULT_SIGNED_TTL,
            max_asset: DEFAULT_MAX_ASSET,
            signing_key: None,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("EDDY_DATA") {
            config.data_dir = v;
        }
        if let Some(v) = env_nonempty("PUBLIC_BASE_URL") {
            config.public_base_url = v.trim_end_matches('/').to_string();
        }
        if let Some(v) = env_nonempty("EDDY_CACHE_MAX_AGE").and_then(|v| v.parse::<u64>().ok()) {
            config.cache_max_age = v;
        }
        if let Some(v) = env_nonempty("EDDY_SIGNED_TTL").and_then(|v| v.parse::<i64>().ok()) {
            if v > 0 {
                config.signed_ttl = v;
            }
        }
        if let Some(v) = env_nonempty("EDDY_MAX_ASSET").and_then(|v| v.parse::<usize>().ok()) {
            if v > 0 {
                config.max_asset = v;
            }
        }
        config.signing_key = env_nonempty("EDDY_SIGNING_KEY");
        config
    }

    /// True when HMAC signing is enabled (a key is configured).
    pub fn signing_enabled(&self) -> bool {
        self.signing_key.is_some()
    }

    /// The signing key bytes, if signing is enabled.
    pub fn signing_key_bytes(&self) -> Option<&[u8]> {
        self.signing_key.as_deref().map(str::as_bytes)
    }

    /// Filesystem root holding the content-addressed blobs (`<data>/blobs`).
    pub fn blobs_root(&self) -> String {
        format!("{}/blobs", self.data_dir.trim_end_matches('/'))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
