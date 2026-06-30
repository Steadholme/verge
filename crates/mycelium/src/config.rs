//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! keystone/keyward/inkwell. Production overrides each via the environment.

use crate::wg::Cidr;

/// Default listen address (all interfaces, internal-only port 9290).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9290";
/// Default mesh address space. Hosts are assigned from here, lowest-free-first.
pub const DEFAULT_MESH_CIDR: &str = "10.77.0.0/24";
/// Default DNS hostname template suffix used to build a peer `Endpoint` line. Empty disables
/// `Endpoint` emission (peers then rely on the other side dialing + `PersistentKeepalive`).
pub const DEFAULT_ENDPOINT_DOMAIN: &str = "mesh.w33d.xyz";
/// Default WireGuard listen port baked into a peer `Endpoint`.
pub const DEFAULT_LISTEN_PORT: u16 = 51820;
/// Hard cap on how many devices the dashboard renders (keeps an unbounded list bounded).
pub const LIST_LIMIT: usize = 500;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// The mesh address space (`MESH_CIDR`). Mesh IPs are assigned from this range.
    pub cidr: Cidr,
    /// The DNS server advertised in every generated `[Interface]` (`MESH_DNS`). Defaults to the
    /// CIDR's first usable host (the gateway slot).
    pub dns: String,
    /// Hostname suffix for peer `Endpoint` lines (`MESH_ENDPOINT_DOMAIN`). Empty => no `Endpoint`.
    pub endpoint_domain: String,
    /// WireGuard listen port baked into peer `Endpoint`s (`MESH_LISTEN_PORT`).
    pub listen_port: u16,
}

impl Config {
    /// Default development configuration (in-memory friendly, no database).
    pub fn dev() -> Self {
        let cidr = Cidr::parse(DEFAULT_MESH_CIDR).expect("default CIDR is valid");
        let dns = cidr.gateway_string();
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            cidr,
            dns,
            endpoint_domain: DEFAULT_ENDPOINT_DOMAIN.to_string(),
            listen_port: DEFAULT_LISTEN_PORT,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("MESH_CIDR") {
            match Cidr::parse(&v) {
                Ok(c) => {
                    // The DNS default tracks the CIDR's gateway slot unless overridden below.
                    config.dns = c.gateway_string();
                    config.cidr = c;
                }
                Err(e) => tracing::warn!(cidr = %v, error = %e, "invalid MESH_CIDR — keeping default"),
            }
        }
        if let Some(v) = env_nonempty("MESH_DNS") {
            config.dns = v;
        }
        if let Some(v) = env_nonempty("MESH_ENDPOINT_DOMAIN") {
            // An explicit empty-after-trim value disables endpoint emission.
            config.endpoint_domain = v.trim().trim_matches('.').to_string();
        }
        if let Some(v) = env_nonempty("MESH_LISTEN_PORT") {
            match v.parse::<u16>() {
                Ok(p) if p > 0 => config.listen_port = p,
                _ => tracing::warn!(port = %v, "invalid MESH_LISTEN_PORT — keeping default"),
            }
        }
        config
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
