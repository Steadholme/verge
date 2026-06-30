//! HMAC-signed `/a/` URLs (pure Rust — `hmac` + `sha2`, NO OpenSSL).
//!
//! When `EDDY_SIGNING_KEY` is configured every public `/a/{path}` request must carry an `?exp=&sig=`
//! pair: `sig = hex(HMAC-SHA256(key, "<path>\n<exp>"))`. `exp` is the absolute epoch-second expiry
//! (`0` = no expiry). Verification is constant-time and expiry-checked. The path signed is the
//! canonical asset path (no leading slash), exactly as captured by the route, so signing and
//! verification operate on identical bytes.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::auth::ct_eq;

type HmacSha256 = Hmac<Sha256>;

/// Compute the lowercase-hex signature for `path` valid until `exp` (epoch seconds; `0` = forever).
pub fn sign(key: &[u8], path: &str, exp: i64) -> String {
    // `new_from_slice` only errors on a zero-length key for some MAC types; HMAC accepts any length.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(path.as_bytes());
    mac.update(b"\n");
    mac.update(exp.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify a presented `(exp, sig)` for `path` against `key` at wall-clock `now`. Returns `Ok(())`
/// when the signature matches AND the link has not expired; otherwise an explanatory error string.
pub fn verify(key: &[u8], path: &str, exp: i64, sig_hex: &str, now: i64) -> Result<(), &'static str> {
    if exp != 0 && now > exp {
        return Err("signed link expired");
    }
    let expected = sign(key, path, exp);
    if ct_eq(expected.as_bytes(), sig_hex.as_bytes()) {
        Ok(())
    } else {
        Err("invalid signature")
    }
}

/// Build the query string (`?exp=…&sig=…`) for a signed `/a/{path}` URL.
pub fn query(key: &[u8], path: &str, exp: i64) -> String {
    format!("?exp={exp}&sig={}", sign(key, path, exp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_signs_and_verifies() {
        let key = b"super-secret";
        let exp = 2_000_000_000;
        let sig = sign(key, "css/app.css", exp);
        assert!(verify(key, "css/app.css", exp, &sig, 1_000).is_ok());
    }

    #[test]
    fn rejects_tamper_and_wrong_key() {
        let key = b"super-secret";
        let sig = sign(key, "css/app.css", 0);
        // Different path.
        assert!(verify(key, "css/other.css", 0, &sig, 1_000).is_err());
        // Different key.
        assert!(verify(b"other-key", "css/app.css", 0, &sig, 1_000).is_err());
        // Garbage signature.
        assert!(verify(key, "css/app.css", 0, "deadbeef", 1_000).is_err());
    }

    #[test]
    fn rejects_expired_and_allows_no_expiry() {
        let key = b"k";
        let sig = sign(key, "x", 100);
        assert!(verify(key, "x", 100, &sig, 200).is_err(), "now past exp");
        assert!(verify(key, "x", 100, &sig, 50).is_ok(), "now before exp");
        // exp == 0 never expires.
        let forever = sign(key, "x", 0);
        assert!(verify(key, "x", 0, &forever, i64::MAX).is_ok());
    }

    #[test]
    fn query_is_parseable() {
        let q = query(b"k", "a/b.js", 42);
        assert!(q.starts_with("?exp=42&sig="));
    }
}
