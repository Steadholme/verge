//! WireGuard primitives: Curve25519 key generation, IPv4 CIDR allocation, peer-list
//! computation from ACLs, and `wg.conf` rendering.
//!
//! CRYPTO: keys are real Curve25519, generated with the pure-Rust `x25519-dalek` crate (NO
//! OpenSSL). A private key is 32 CSPRNG bytes with the standard WireGuard clamping applied
//! (matching `wg genkey`); the public key is `X25519(private, basepoint)`. Both are encoded
//! with standard base64 (the `wg`-native 44-char form).
//!
//! NOTE — control plane only. This module GENERATES configs; it never brings up a kernel
//! tunnel. A live data plane needs `NET_ADMIN` + the `wireguard` kernel module on a dedicated
//! privileged node, which is intentionally out of scope (see the crate docs / README).

use std::collections::HashSet;
use std::net::Ipv4Addr;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

/// A freshly generated WireGuard keypair, base64-encoded (`wg`-compatible).
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// 32-byte clamped private scalar, base64. Shown to the operator ONCE on enrollment.
    pub private_b64: String,
    /// Derived Curve25519 public key, base64. Stored server-side and shared with peers.
    pub public_b64: String,
}

/// Generate a real Curve25519 keypair the way `wg genkey | wg pubkey` does.
///
/// 32 CSPRNG bytes, clamped (clear the low 3 bits of byte 0; clear bit 255 and set bit 254 of
/// byte 31), then the public key is the X25519 of that scalar against the curve basepoint.
pub fn generate_keypair() -> KeyPair {
    let mut sk = [0u8; 32];
    getrandom::getrandom(&mut sk).expect("OS CSPRNG unavailable");
    // WireGuard clamping — identical to `wg genkey`.
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
    KeyPair {
        private_b64: B64.encode(sk),
        public_b64: B64.encode(pk),
    }
}

/// A short, display-only fingerprint of a base64 public key: first 8 + `…` + last 6 chars. The
/// full key is still rendered into configs; this is only for the dashboard table.
pub fn fingerprint(public_b64: &str) -> String {
    let chars: Vec<char> = public_b64.chars().collect();
    if chars.len() <= 16 {
        return public_b64.to_string();
    }
    let head: String = chars[..8].iter().collect();
    let tail: String = chars[chars.len() - 6..].iter().collect();
    format!("{head}…{tail}")
}

// --------------------------------------------------------------------------------------
// IPv4 CIDR allocation
// --------------------------------------------------------------------------------------

/// An IPv4 CIDR block. Mesh IPs are assigned from the host range, lowest-free-first, reserving
/// the network address, the gateway slot (network+1, also the DNS), and the broadcast address.
#[derive(Clone, Debug)]
pub struct Cidr {
    /// Network address as a host-order `u32`.
    pub network: u32,
    /// Prefix length (0..=32).
    pub prefix: u8,
}

impl Cidr {
    /// Parse `a.b.c.d/prefix`. The address is masked down to its network address, so
    /// `10.77.0.5/24` and `10.77.0.0/24` parse to the same block.
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let (ip, pfx) = s
            .split_once('/')
            .ok_or_else(|| "CIDR must be a.b.c.d/prefix".to_string())?;
        let prefix: u8 = pfx
            .trim()
            .parse()
            .map_err(|_| format!("bad prefix '{pfx}'"))?;
        if prefix > 32 {
            return Err(format!("prefix {prefix} > 32"));
        }
        let addr: Ipv4Addr = ip
            .trim()
            .parse()
            .map_err(|_| format!("bad IPv4 address '{ip}'"))?;
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = u32::from(addr) & mask;
        Ok(Cidr { network, prefix })
    }

    /// Total addresses in the block (including network + broadcast).
    pub fn size(&self) -> u64 {
        1u64 << (32 - self.prefix)
    }

    /// The gateway / DNS slot: the first usable host (network+1).
    pub fn gateway(&self) -> u32 {
        self.network.wrapping_add(1)
    }

    /// The broadcast address (last in the block). For tiny blocks this may equal the network.
    pub fn broadcast(&self) -> u32 {
        self.network.wrapping_add((self.size() - 1) as u32)
    }

    /// Allocate the lowest free host IP, skipping the network, the gateway slot, and the
    /// broadcast address. Returns `None` when the pool is exhausted (or too small to hold any
    /// device — e.g. a `/31` or `/32`).
    pub fn allocate(&self, taken: &HashSet<u32>) -> Option<u32> {
        // Assignable range is (network+2)..=(broadcast-1).
        let start = self.network.checked_add(2)?;
        let broadcast = self.broadcast();
        if broadcast < start {
            return None;
        }
        let mut ip = start;
        while ip < broadcast {
            if !taken.contains(&ip) {
                return Some(ip);
            }
            ip = ip.checked_add(1)?;
        }
        None
    }

    /// `a.b.c.d/prefix` text for the trust summary.
    pub fn to_text(&self) -> String {
        format!("{}/{}", ip_to_string(self.network), self.prefix)
    }

    /// The gateway/DNS host as a dotted string.
    pub fn gateway_string(&self) -> String {
        ip_to_string(self.gateway())
    }
}

/// Host-order `u32` -> dotted-quad string.
pub fn ip_to_string(ip: u32) -> String {
    Ipv4Addr::from(ip).to_string()
}

/// Parse a dotted-quad string -> host-order `u32` (used to seed the "taken" set from stored
/// mesh IPs). Returns `None` for anything unparseable.
pub fn ip_from_string(s: &str) -> Option<u32> {
    s.trim().parse::<Ipv4Addr>().ok().map(u32::from)
}

// --------------------------------------------------------------------------------------
// ACL evaluation + peer list
// --------------------------------------------------------------------------------------

/// One peer entry rendered into a `[Peer]` block.
#[derive(Clone, Debug)]
pub struct PeerView {
    pub name: String,
    pub public_key: String,
    pub mesh_ip: String,
    /// `Some` when an endpoint hostname could be derived; `None` otherwise.
    pub endpoint: Option<String>,
}

/// Does an ACL tag (`*` = any) match a device's tag set?
pub fn tag_matches(acl_tag: &str, device_tags: &[String]) -> bool {
    acl_tag == "*" || device_tags.iter().any(|t| t == acl_tag)
}

/// May traffic flow from a device with `src_tags` to a device with `dst_tags` under `acls`?
///
/// Zero-trust posture: any rule that matches both endpoints grants the link. To keep a fresh
/// install usable with no policy at all, an EMPTY ACL set is treated as a default-allow full
/// mesh (the operator tightens it by adding the first rule).
pub fn link_allowed(acls: &[(String, String)], src_tags: &[String], dst_tags: &[String]) -> bool {
    if acls.is_empty() {
        return true;
    }
    acls.iter()
        .any(|(src, dst)| tag_matches(src, src_tags) && tag_matches(dst, dst_tags))
}

/// The single hub `[Peer]` a spoke client dials in a hub-and-spoke topology. The estate runs a
/// real hub-and-spoke WireGuard (host `wg0` gateway), so a client conf lists ONLY the hub — the
/// server side (per-spoke peers) is reconciled on the host, not shipped in the client conf.
#[derive(Clone, Debug)]
pub struct HubPeer {
    /// The hub's base64 WireGuard public key.
    pub public_key: String,
    /// The hub `Endpoint`, e.g. `vpn.w33d.xyz:51820`.
    pub endpoint: String,
    /// The routes a spoke sends through the hub, e.g. `10.77.0.0/24` (the whole mesh).
    pub allowed_ips: String,
}

/// Render a hub-and-spoke `wg.conf`: an `[Interface]` plus the single hub `[Peer]`. `private_key`
/// is `Some` only on the one-time enrollment render; the re-issued config (GET /api/config/{id})
/// passes `None`, so the secret never leaves twice.
pub fn render_conf(private_key: Option<&str>, address: &str, dns: &str, hub: &HubPeer) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    match private_key {
        Some(pk) => out.push_str(&format!("PrivateKey = {pk}\n")),
        None => {
            out.push_str("# PrivateKey = <kept only on the device; re-issued config omits it>\n")
        }
    }
    out.push_str(&format!("Address = {address}/32\n"));
    out.push_str(&format!("DNS = {dns}\n"));

    out.push('\n');
    out.push_str("# hub — HOLDFAST WireGuard gateway (hub-and-spoke)\n");
    out.push_str("[Peer]\n");
    out.push_str(&format!("PublicKey = {}\n", hub.public_key));
    out.push_str(&format!("Endpoint = {}\n", hub.endpoint));
    out.push_str(&format!("AllowedIPs = {}\n", hub.allowed_ips));
    out.push_str("PersistentKeepalive = 25\n");
    out
}

/// Build a peer `Endpoint` hostname from a device name + the configured domain. Returns `None`
/// when the domain is empty (endpoints disabled).
pub fn endpoint_for(name: &str, domain: &str, port: u16) -> Option<String> {
    if domain.is_empty() {
        return None;
    }
    let host = slugify(name);
    Some(format!("{host}.{domain}:{port}"))
}

/// Lowercase, hyphen-joined slug of a device name for endpoint hostnames. Non-alphanumeric runs
/// collapse to a single `-`; an empty result falls back to `node`.
pub fn slugify(name: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "node".to_string()
    } else {
        trimmed
    }
}

/// Parse a free-form tag string (comma- and/or whitespace-separated) into a normalized, deduped
/// list. Tags are lowercased; `*` and empties are dropped (the wildcard is ACL-only).
pub fn parse_tags(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for piece in raw.split([',', ' ', '\t', '\n']) {
        let t = piece.trim().to_ascii_lowercase();
        if t.is_empty() || t == "*" {
            continue;
        }
        if seen.insert(t.clone()) {
            out.push(t);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_is_valid_wireguard_shape() {
        let kp = generate_keypair();
        // 32 bytes base64 (standard, padded) is 44 chars.
        assert_eq!(kp.private_b64.len(), 44);
        assert_eq!(kp.public_b64.len(), 44);
        let sk = B64.decode(&kp.private_b64).unwrap();
        let pk = B64.decode(&kp.public_b64).unwrap();
        assert_eq!(sk.len(), 32);
        assert_eq!(pk.len(), 32);
        // Clamping invariants.
        assert_eq!(sk[0] & 0b111, 0, "low 3 bits cleared");
        assert_eq!(sk[31] & 0b1000_0000, 0, "bit 255 cleared");
        assert_eq!(sk[31] & 0b0100_0000, 0b0100_0000, "bit 254 set");
        // Public key reproducibly derives from the private scalar.
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&sk);
        let derived = x25519_dalek::x25519(arr, x25519_dalek::X25519_BASEPOINT_BYTES);
        assert_eq!(B64.encode(derived), kp.public_b64);
        // Two keypairs differ.
        assert_ne!(generate_keypair().private_b64, kp.private_b64);
    }

    #[test]
    fn cidr_allocates_low_to_high_skipping_reserved() {
        let cidr = Cidr::parse("10.77.0.0/24").unwrap();
        assert_eq!(cidr.gateway_string(), "10.77.0.1");
        assert_eq!(cidr.to_text(), "10.77.0.0/24");

        let mut taken = HashSet::new();
        // First allocation skips .0 (network) and .1 (gateway) -> .2
        let a = cidr.allocate(&taken).unwrap();
        assert_eq!(ip_to_string(a), "10.77.0.2");
        taken.insert(a);
        let b = cidr.allocate(&taken).unwrap();
        assert_eq!(ip_to_string(b), "10.77.0.3");
        // Broadcast (.255) is never handed out.
        for ip in (cidr.network + 2)..cidr.broadcast() {
            taken.insert(ip);
        }
        assert!(
            cidr.allocate(&taken).is_none(),
            "pool exhausted before broadcast"
        );
    }

    #[test]
    fn cidr_masks_to_network() {
        let c = Cidr::parse("10.77.0.37/24").unwrap();
        assert_eq!(c.to_text(), "10.77.0.0/24");
        // A /30 has exactly 2 usable hosts but we also reserve the gateway -> only .2 wait:
        // /30 = .0 network, .1 gateway, .2 host, .3 broadcast => one assignable.
        let c30 = Cidr::parse("192.168.5.0/30").unwrap();
        let mut taken = HashSet::new();
        let first = c30.allocate(&taken).unwrap();
        assert_eq!(ip_to_string(first), "192.168.5.2");
        taken.insert(first);
        assert!(c30.allocate(&taken).is_none());
        // /32 holds nothing.
        assert!(Cidr::parse("10.0.0.9/32")
            .unwrap()
            .allocate(&HashSet::new())
            .is_none());
    }

    #[test]
    fn acl_matching_and_default_allow() {
        let web = vec!["web".to_string()];
        let db = vec!["db".to_string()];
        // No policy -> full mesh.
        assert!(link_allowed(&[], &web, &db));
        // Specific rule web->db.
        let acls = vec![("web".to_string(), "db".to_string())];
        assert!(link_allowed(&acls, &web, &db));
        assert!(!link_allowed(&acls, &db, &web), "reverse not granted");
        // Wildcard source.
        let any = vec![("*".to_string(), "db".to_string())];
        assert!(link_allowed(&any, &web, &db));
        assert!(link_allowed(&any, &db, &db));
        assert!(!link_allowed(&any, &web, &web));
    }

    #[test]
    fn conf_render_is_hub_and_spoke() {
        let hub = HubPeer {
            public_key: "HUBPUBKEYAAAA".to_string(),
            endpoint: "vpn.w33d.xyz:51820".to_string(),
            allowed_ips: "10.77.0.0/24".to_string(),
        };
        let with = render_conf(Some("PRIVKEY"), "10.77.0.2", "10.77.0.1", &hub);
        assert!(with.contains("PrivateKey = PRIVKEY"));
        assert!(with.contains("Address = 10.77.0.2/32"));
        assert!(with.contains("DNS = 10.77.0.1"));
        // Exactly one peer — the hub — and no per-spoke /32 peer lines.
        assert_eq!(with.matches("[Peer]").count(), 1, "single hub peer only");
        assert!(with.contains("PublicKey = HUBPUBKEYAAAA"));
        assert!(with.contains("Endpoint = vpn.w33d.xyz:51820"));
        assert!(with.contains("AllowedIPs = 10.77.0.0/24"));
        assert!(with.contains("PersistentKeepalive = 25"));

        let without = render_conf(None, "10.77.0.2", "10.77.0.1", &hub);
        assert!(!without.contains("PrivateKey = PRIVKEY"));
        assert!(without.contains("# PrivateKey ="));
    }

    #[test]
    fn slug_and_endpoint() {
        assert_eq!(slugify("Alice's Laptop #2"), "alice-s-laptop-2");
        assert_eq!(slugify("***"), "node");
        assert_eq!(
            endpoint_for("DB Primary", "mesh.w33d.xyz", 51820),
            Some("db-primary.mesh.w33d.xyz:51820".to_string())
        );
        assert_eq!(endpoint_for("x", "", 51820), None);
    }

    #[test]
    fn parse_tags_normalizes() {
        assert_eq!(parse_tags("Web, DB  prod"), vec!["web", "db", "prod"]);
        assert_eq!(parse_tags(" * , , web,web"), vec!["web"]);
        assert!(parse_tags("").is_empty());
    }
}
