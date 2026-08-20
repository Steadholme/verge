//! Short-lived Clash profile subscriptions.
//!
//! A profile is loaded once from a read-only runtime file. Public download URLs carry a compact
//! opaque token containing only a version, expiry, and random nonce; HMAC-SHA256 authenticates the
//! complete payload. User identity and node credentials never appear in the URL.

use std::path::Path;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::env_nonempty;

pub const SUBSCRIPTION_TTL_SECONDS: i64 = 10 * 60;
pub const PROFILE_FILENAME: &str = "MESL-DMIT-HK-US.yaml";
const DEFAULT_PUBLIC_BASE_URL: &str = "https://vpn.w33d.xyz";
const MAX_PROFILE_BYTES: usize = 2 * 1024 * 1024;
const TOKEN_VERSION: u8 = 1;
const TOKEN_NONCE_BYTES: usize = 16;
const TOKEN_PAYLOAD_BYTES: usize = 1 + 8 + TOKEN_NONCE_BYTES;
const TOKEN_MAC_BYTES: usize = 32;
const TOKEN_BYTES: usize = TOKEN_PAYLOAD_BYTES + TOKEN_MAC_BYTES;
const TOKEN_AUDIENCE: &[u8] = b"mycelium-clash-subscription-v1\n";

type HmacSha256 = Hmac<Sha256>;

pub struct ClashSubscription {
    profile: Arc<[u8]>,
    signing_key: Vec<u8>,
    public_base_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenError {
    Invalid,
    Expired,
}

impl ClashSubscription {
    pub fn new(
        profile: Vec<u8>,
        signing_key: Vec<u8>,
        public_base_url: &str,
    ) -> Result<Self, String> {
        if profile.is_empty() || profile.len() > MAX_PROFILE_BYTES {
            return Err(format!(
                "Clash profile must contain 1..={MAX_PROFILE_BYTES} bytes"
            ));
        }
        std::str::from_utf8(&profile)
            .map_err(|_| "Clash profile must be valid UTF-8 YAML".to_string())?;
        validate_signing_key(&signing_key)?;

        let base = public_base_url.trim().trim_end_matches('/');
        if !base.starts_with("https://") || base.len() <= "https://".len() {
            return Err("CLASH_PUBLIC_BASE_URL must be an absolute https:// URL".to_string());
        }

        Ok(Self {
            profile: Arc::from(profile),
            signing_key,
            public_base_url: base.to_string(),
        })
    }

    pub fn mint(&self, now: i64) -> Result<(String, i64), String> {
        if now < 0 {
            return Err("system clock is before the Unix epoch".to_string());
        }
        let expiry = now
            .checked_add(SUBSCRIPTION_TTL_SECONDS)
            .ok_or_else(|| "subscription expiry overflow".to_string())?;
        let mut nonce = [0u8; TOKEN_NONCE_BYTES];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| "OS CSPRNG unavailable for subscription token".to_string())?;

        let mut payload = [0u8; TOKEN_PAYLOAD_BYTES];
        payload[0] = TOKEN_VERSION;
        payload[1..9].copy_from_slice(&(expiry as u64).to_be_bytes());
        payload[9..].copy_from_slice(&nonce);

        let mac = sign(&self.signing_key, &payload);
        let mut token = Vec::with_capacity(TOKEN_BYTES);
        token.extend_from_slice(&payload);
        token.extend_from_slice(&mac);
        Ok((URL_SAFE_NO_PAD.encode(token), expiry))
    }

    pub fn verify(&self, token: &str, now: i64) -> Result<(), TokenError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .map_err(|_| TokenError::Invalid)?;
        if bytes.len() != TOKEN_BYTES || bytes[0] != TOKEN_VERSION {
            return Err(TokenError::Invalid);
        }
        let (payload, presented_mac) = bytes.split_at(TOKEN_PAYLOAD_BYTES);
        let mut verifier =
            HmacSha256::new_from_slice(&self.signing_key).expect("HMAC accepts any key length");
        verifier.update(TOKEN_AUDIENCE);
        verifier.update(payload);
        verifier
            .verify_slice(presented_mac)
            .map_err(|_| TokenError::Invalid)?;

        let expiry = u64::from_be_bytes(payload[1..9].try_into().map_err(|_| TokenError::Invalid)?);
        if expiry > i64::MAX as u64 {
            return Err(TokenError::Invalid);
        }
        if now > expiry as i64 {
            return Err(TokenError::Expired);
        }
        Ok(())
    }

    pub fn download_url(&self, token: &str) -> String {
        format!("{}/subscription/clash?token={token}", self.public_base_url)
    }

    pub fn profile(&self) -> &[u8] {
        &self.profile
    }
}

pub fn from_env() -> Result<Option<Arc<ClashSubscription>>, String> {
    let profile_path = env_nonempty("CLASH_SUBSCRIPTION_FILE");
    let key_path = env_nonempty("CLASH_SUBSCRIPTION_SIGNING_KEY_FILE");
    match (profile_path, key_path) {
        (None, None) => Ok(None),
        (Some(_), None) => {
            Err("CLASH_SUBSCRIPTION_FILE requires CLASH_SUBSCRIPTION_SIGNING_KEY_FILE".to_string())
        }
        (None, Some(_)) => {
            Err("CLASH_SUBSCRIPTION_SIGNING_KEY_FILE requires CLASH_SUBSCRIPTION_FILE".to_string())
        }
        (Some(profile_path), Some(key_path)) => {
            let profile = read_regular_file(&profile_path, "Clash profile")?;
            let key_raw = read_regular_file(&key_path, "Clash signing key")?;
            let key_text = std::str::from_utf8(&key_raw)
                .map_err(|_| "Clash signing key must be visible ASCII".to_string())?;
            let signing_key = key_text.trim().as_bytes().to_vec();
            let public_base_url = env_nonempty("CLASH_PUBLIC_BASE_URL")
                .unwrap_or_else(|| DEFAULT_PUBLIC_BASE_URL.to_string());
            ClashSubscription::new(profile, signing_key, &public_base_url)
                .map(|value| Some(Arc::new(value)))
        }
    }
}

fn read_regular_file(path: &str, label: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(path);
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("read {label} metadata at {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    std::fs::read(path).map_err(|e| format!("read {label} at {}: {e}", path.display()))
}

fn validate_signing_key(key: &[u8]) -> Result<(), String> {
    if !(32..=512).contains(&key.len()) || key.iter().any(|byte| !(b'!'..=b'~').contains(byte)) {
        return Err("Clash signing key must contain 32..=512 visible ASCII bytes".to_string());
    }
    Ok(())
}

fn sign(key: &[u8], payload: &[u8]) -> [u8; TOKEN_MAC_BYTES] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(TOKEN_AUDIENCE);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription() -> ClashSubscription {
        ClashSubscription::new(
            b"proxies: []\n".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
            "https://vpn.example.test/",
        )
        .unwrap()
    }

    #[test]
    fn token_round_trip_is_opaque_and_valid_for_ten_minutes() {
        let value = subscription();
        let (token, expiry) = value.mint(1_000).unwrap();
        assert_eq!(expiry, 1_600);
        assert!(!token.contains("user:"));
        assert_eq!(value.verify(&token, 1_600), Ok(()));
        assert_eq!(value.verify(&token, 1_601), Err(TokenError::Expired));
        assert_eq!(
            value.download_url(&token),
            format!("https://vpn.example.test/subscription/clash?token={token}")
        );
    }

    #[test]
    fn token_rejects_tampering_and_wrong_key() {
        let value = subscription();
        let (token, _) = value.mint(1_000).unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(token.as_bytes()).unwrap();
        bytes[10] ^= 1;
        let tampered = URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(value.verify(&tampered, 1_001), Err(TokenError::Invalid));

        let other = ClashSubscription::new(
            b"proxies: []\n".to_vec(),
            b"abcdef0123456789abcdef0123456789".to_vec(),
            "https://vpn.example.test",
        )
        .unwrap();
        assert_eq!(other.verify(&token, 1_001), Err(TokenError::Invalid));
    }

    #[test]
    fn configuration_rejects_short_keys_and_insecure_urls() {
        assert!(ClashSubscription::new(
            b"proxies: []\n".to_vec(),
            b"short".to_vec(),
            "https://vpn.example.test"
        )
        .is_err());
        assert!(ClashSubscription::new(
            b"proxies: []\n".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
            "http://vpn.example.test"
        )
        .is_err());
    }
}
