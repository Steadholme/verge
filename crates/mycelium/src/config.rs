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

/// Default HUB `Endpoint` a spoke client dials (`HUB_ENDPOINT`). The estate runs a real
/// hub-and-spoke WireGuard: every generated client config points at this single gateway.
pub const DEFAULT_HUB_ENDPOINT: &str = "vpn.w33d.xyz:51820";
/// Default `AllowedIPs` a spoke routes through the hub (`HUB_ALLOWED_IPS`): the whole mesh.
pub const DEFAULT_HUB_ALLOWED_IPS: &str = "10.77.0.0/24";
/// Dev-only placeholder hub public key. NOT a real key — the production hub key is injected via
/// `HUB_PUBKEY` (never hardcoded). Keeps the no-config dev/test path rendering a valid `[Peer]`.
pub const DEV_HUB_PUBKEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

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
    /// Retained for the ACL/reachability model + dashboard; irrelevant to the hub-and-spoke
    /// CLIENT conf, which always dials the single hub below.
    pub endpoint_domain: String,
    /// WireGuard listen port baked into peer `Endpoint`s (`MESH_LISTEN_PORT`).
    pub listen_port: u16,
    /// The hub's WireGuard public key (`HUB_PUBKEY`). Rendered as the single `[Peer]` in every
    /// client conf. NEVER hardcoded to the real key — dev/test uses [`DEV_HUB_PUBKEY`].
    pub hub_pubkey: String,
    /// The hub `Endpoint` a spoke dials (`HUB_ENDPOINT`), e.g. `vpn.w33d.xyz:51820`.
    pub hub_endpoint: String,
    /// The `AllowedIPs` a spoke routes through the hub (`HUB_ALLOWED_IPS`), e.g. `10.77.0.0/24`.
    pub hub_allowed_ips: String,
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
            hub_pubkey: DEV_HUB_PUBKEY.to_string(),
            hub_endpoint: DEFAULT_HUB_ENDPOINT.to_string(),
            hub_allowed_ips: DEFAULT_HUB_ALLOWED_IPS.to_string(),
        }
    }

    /// The single hub `[Peer]` every spoke client dials (hub-and-spoke topology).
    pub fn hub_peer(&self) -> crate::wg::HubPeer {
        crate::wg::HubPeer {
            public_key: self.hub_pubkey.clone(),
            endpoint: self.hub_endpoint.clone(),
            allowed_ips: self.hub_allowed_ips.clone(),
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
                Err(e) => {
                    tracing::warn!(cidr = %v, error = %e, "invalid MESH_CIDR — keeping default")
                }
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
        // Hub-and-spoke: the single gateway every client conf points at. HUB_PUBKEY must be set in
        // production (the dev placeholder is not a real key); HUB_DNS overrides the client DNS.
        if let Some(v) = env_nonempty("HUB_PUBKEY") {
            config.hub_pubkey = v.trim().to_string();
        }
        if let Some(v) = env_nonempty("HUB_ENDPOINT") {
            config.hub_endpoint = v.trim().to_string();
        }
        if let Some(v) = env_nonempty("HUB_DNS") {
            config.dns = v.trim().to_string();
        }
        if let Some(v) = env_nonempty("HUB_ALLOWED_IPS") {
            config.hub_allowed_ips = v.trim().to_string();
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
