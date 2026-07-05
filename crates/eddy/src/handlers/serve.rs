//! The public content-addressed edge (`/a/{*path}`).
//!
//! This subtree is `auth=public` at the Sluice gateway (a browser `<img>`/`<script>` cannot speak
//! the SSO cookie), so it consults NO identity. It serves a cached asset by its path with a strong
//! ETag (the content hash), a `Cache-Control: public, max-age=…`, conditional `304 Not Modified`
//! revalidation, and single-`Range` support (`206 Partial Content` / `416`). Each served request
//! bumps the asset's hit counter. When `EDDY_SIGNING_KEY` is configured, a valid HMAC `?exp=&sig=`
//! is REQUIRED before anything is revealed.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::blobs::BlobError;
use crate::{now_secs, sign, AppState};

/// Optional signed-URL parameters on a `/a/` request.
#[derive(Debug, Default, Deserialize)]
pub struct ServeQuery {
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub sig: Option<String>,
}

/// `GET /a/{*path}` — serve a cached asset's bytes (or a conditional/partial response).
pub async fn serve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Query(q): Query<ServeQuery>,
) -> Response {
    // --- 1. signed-URL gate (only when a signing key is configured) --------
    if let Some(key) = state.config.signing_key_bytes() {
        let exp = q.exp.unwrap_or(0);
        let sig = q.sig.as_deref().unwrap_or("");
        if sig.is_empty() || sign::verify(key, &path, exp, sig, now_secs()).is_err() {
            return (StatusCode::FORBIDDEN, "forbidden").into_response();
        }
    }

    // --- 2. metadata + bytes ----------------------------------------------
    let Some(asset) = state.store.get_by_path(&path).await else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let bytes = match state.blobs.get(&asset.content_hash).await {
        Ok(b) => b,
        Err(BlobError::NotFound) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => {
            tracing::error!(path = %path, error = %e, "blob read failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    // A served request is a cache hit — bump the counter (best-effort; never fails the response).
    state.store.bump_hits(&path).await;

    let etag = format!("\"{}\"", asset.content_hash);
    let cache_control = format!("public, max-age={}", state.config.cache_max_age);

    // --- 3. conditional revalidation (If-None-Match) -----------------------
    if if_none_match_hit(&headers, &etag) {
        return base_builder(
            StatusCode::NOT_MODIFIED,
            &asset.content_type,
            &etag,
            &cache_control,
        )
        .body(Body::empty())
        .expect("valid 304 response");
    }

    // --- 4. range vs. full --------------------------------------------------
    let total = bytes.len() as u64;
    match resolve_range(&headers, total) {
        RangeOutcome::Full => {
            base_builder(StatusCode::OK, &asset.content_type, &etag, &cache_control)
                .body(Body::from(bytes))
                .expect("valid 200 response")
        }
        RangeOutcome::Partial { start, end } => {
            let slice = bytes[start as usize..=end as usize].to_vec();
            base_builder(
                StatusCode::PARTIAL_CONTENT,
                &asset.content_type,
                &etag,
                &cache_control,
            )
            .header(
                header::CONTENT_RANGE,
                format!("bytes {start}-{end}/{total}"),
            )
            .body(Body::from(slice))
            .expect("valid 206 response")
        }
        RangeOutcome::Unsatisfiable => base_builder(
            StatusCode::RANGE_NOT_SATISFIABLE,
            &asset.content_type,
            &etag,
            &cache_control,
        )
        .header(header::CONTENT_RANGE, format!("bytes */{total}"))
        .body(Body::empty())
        .expect("valid 416 response"),
    }
}

/// Shared response headers for every served representation: content type, validators, cache policy,
/// range advertisement, and `nosniff` (so an asset never executes as a different type than stored).
fn base_builder(
    status: StatusCode,
    content_type: &str,
    etag: &str,
    cache_control: &str,
) -> axum::http::response::Builder {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::ETAG, etag)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
}

/// True when the request's `If-None-Match` matches our ETag (`*` or an exact list member).
fn if_none_match_hit(headers: &HeaderMap, etag: &str) -> bool {
    let Some(raw) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let raw = raw.trim();
    if raw == "*" {
        return true;
    }
    raw.split(',')
        .map(|t| t.trim().trim_start_matches("W/"))
        .any(|t| t == etag)
}

/// The outcome of evaluating an optional single `Range` header against a body of `total` bytes.
#[derive(Debug, PartialEq, Eq)]
enum RangeOutcome {
    /// No (usable) range — serve the whole body.
    Full,
    /// A satisfiable `start..=end` (inclusive) byte range.
    Partial { start: u64, end: u64 },
    /// A syntactically valid but unsatisfiable range.
    Unsatisfiable,
}

/// Resolve an optional `Range: bytes=…` header. Only a single range is honored; a malformed or
/// non-`bytes` range is ignored (`Full`), matching the RFC 7233 "MAY ignore" allowance.
fn resolve_range(headers: &HeaderMap, total: u64) -> RangeOutcome {
    let Some(raw) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) else {
        return RangeOutcome::Full;
    };
    let Some(spec) = raw.trim().strip_prefix("bytes=") else {
        return RangeOutcome::Full;
    };
    // Multiple ranges (comma-separated) are not supported — serve the whole body.
    if spec.contains(',') {
        return RangeOutcome::Full;
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeOutcome::Full;
    };
    let (start_s, end_s) = (start_s.trim(), end_s.trim());

    if total == 0 {
        return RangeOutcome::Unsatisfiable;
    }
    let last = total - 1;

    let (start, end) = if start_s.is_empty() {
        // Suffix range: "-N" => the final N bytes.
        let Ok(suffix) = end_s.parse::<u64>() else {
            return RangeOutcome::Full;
        };
        if suffix == 0 {
            return RangeOutcome::Unsatisfiable;
        }
        let len = suffix.min(total);
        (total - len, last)
    } else {
        let Ok(start) = start_s.parse::<u64>() else {
            return RangeOutcome::Full;
        };
        if start > last {
            return RangeOutcome::Unsatisfiable;
        }
        let end = if end_s.is_empty() {
            last
        } else {
            match end_s.parse::<u64>() {
                Ok(e) => e.min(last),
                Err(_) => return RangeOutcome::Full,
            }
        };
        if start > end {
            return RangeOutcome::Unsatisfiable;
        }
        (start, end)
    };
    RangeOutcome::Partial { start, end }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(name: header::HeaderName, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, value.parse().unwrap());
        h
    }

    #[test]
    fn no_range_is_full() {
        assert_eq!(resolve_range(&HeaderMap::new(), 100), RangeOutcome::Full);
    }

    #[test]
    fn closed_range() {
        let h = hm(header::RANGE, "bytes=0-9");
        assert_eq!(
            resolve_range(&h, 100),
            RangeOutcome::Partial { start: 0, end: 9 }
        );
    }

    #[test]
    fn open_ended_range_clamps_to_last() {
        let h = hm(header::RANGE, "bytes=90-");
        assert_eq!(
            resolve_range(&h, 100),
            RangeOutcome::Partial { start: 90, end: 99 }
        );
        let h = hm(header::RANGE, "bytes=0-9999");
        assert_eq!(
            resolve_range(&h, 100),
            RangeOutcome::Partial { start: 0, end: 99 }
        );
    }

    #[test]
    fn suffix_range() {
        let h = hm(header::RANGE, "bytes=-10");
        assert_eq!(
            resolve_range(&h, 100),
            RangeOutcome::Partial { start: 90, end: 99 }
        );
        // Suffix larger than the body clamps to the whole body.
        let h = hm(header::RANGE, "bytes=-500");
        assert_eq!(
            resolve_range(&h, 100),
            RangeOutcome::Partial { start: 0, end: 99 }
        );
    }

    #[test]
    fn unsatisfiable_when_start_past_end() {
        let h = hm(header::RANGE, "bytes=500-600");
        assert_eq!(resolve_range(&h, 100), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn malformed_range_is_ignored() {
        let h = hm(header::RANGE, "items=0-9");
        assert_eq!(resolve_range(&h, 100), RangeOutcome::Full);
        let h = hm(header::RANGE, "bytes=abc-def");
        assert_eq!(resolve_range(&h, 100), RangeOutcome::Full);
    }

    #[test]
    fn if_none_match_matches_etag_and_star() {
        let etag = "\"deadbeef\"";
        assert!(if_none_match_hit(
            &hm(header::IF_NONE_MATCH, "\"deadbeef\""),
            etag
        ));
        assert!(if_none_match_hit(&hm(header::IF_NONE_MATCH, "*"), etag));
        assert!(if_none_match_hit(
            &hm(header::IF_NONE_MATCH, "W/\"deadbeef\""),
            etag
        ));
        assert!(!if_none_match_hit(
            &hm(header::IF_NONE_MATCH, "\"other\""),
            etag
        ));
        assert!(!if_none_match_hit(&HeaderMap::new(), etag));
    }
}
