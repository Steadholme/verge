//! Asset path normalization + content-type resolution.
//!
//! Cached assets are addressed by a clean, slash-delimited `path` (the part after `/a/`). Paths are
//! validated to a conservative charset and rejected when they contain empty / `.` / `..` segments,
//! so a crafted path can never traverse or alias. The served content-type is resolved primarily
//! from the path extension (authoritative for static assets like CSS/JS), then a small magic sniff,
//! then the origin/upload hint, then `application/octet-stream`.

/// Hard cap on a stored asset path (characters).
const MAX_PATH_CHARS: usize = 512;

/// Normalize + validate an asset path: trim, strip any leading slash, reject empty / oversize paths
/// and any path with an empty, `.`, or `..` segment or a character outside the allowlist. Returns
/// the canonical path on success.
pub fn normalize_path(raw: &str) -> Option<String> {
    let p = raw.trim().trim_start_matches('/');
    if p.is_empty() || p.chars().count() > MAX_PATH_CHARS {
        return None;
    }
    for seg in p.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        if !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+' | '~'))
        {
            return None;
        }
    }
    Some(p.to_string())
}

/// Derive a candidate asset path from an origin URL: take its path component (minus query/fragment),
/// strip the leading slash, and normalize. Returns `None` when the result is empty/invalid (the
/// caller then falls back to the content hash).
pub fn path_from_origin_url(url: &str) -> Option<String> {
    // Strip scheme://authority.
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let path_and_rest = match after_scheme.find('/') {
        Some(i) => &after_scheme[i + 1..],
        None => return None,
    };
    let path = path_and_rest
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches('/');
    normalize_path(path)
}

/// Derive a candidate asset path from an uploaded file name (basename only), normalized. Returns
/// `None` when the result is empty/invalid.
pub fn path_from_filename(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    normalize_path(base)
}

/// Resolve the stored content-type for an asset: extension map first, then a magic sniff, then the
/// origin/upload `hint`, then `application/octet-stream`. Text-ish types carry `; charset=utf-8`.
pub fn resolve_content_type(path: &str, bytes: &[u8], hint: &str) -> String {
    if let Some(ct) = by_extension(path) {
        return ct.to_string();
    }
    if let Some(ct) = sniff_magic(bytes) {
        return ct.to_string();
    }
    let hint = hint.trim();
    if is_plausible_mime(hint) {
        return hint.to_string();
    }
    "application/octet-stream".to_string()
}

/// Content-type from a known file extension. `None` for unknown/extension-less paths.
fn by_extension(path: &str) -> Option<&'static str> {
    let ext = path.rsplit_once('.').map(|(_, e)| e)?.to_ascii_lowercase();
    let ct = match ext.as_str() {
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "svg" => "image/svg+xml; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "gz" => "application/gzip",
        "zip" => "application/zip",
        _ => return None,
    };
    Some(ct)
}

/// Best-effort magic sniff for the common binary asset types (used only when the extension is
/// unknown).
fn sniff_magic(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("image/png")
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if b.starts_with(b"GIF8") {
        Some("image/gif")
    } else if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else if b.starts_with(b"%PDF") {
        Some("application/pdf")
    } else if b.starts_with(&[0x1F, 0x8B]) {
        Some("application/gzip")
    } else if b.starts_with(&[0x00, 0x61, 0x73, 0x6D]) {
        Some("application/wasm")
    } else {
        None
    }
}

/// A loose check that a hint string looks like a `type/subtype` MIME, so a garbage `Content-Type`
/// header never becomes the stored type.
fn is_plausible_mime(s: &str) -> bool {
    match s.split(';').next().unwrap_or("").split_once('/') {
        Some((t, sub)) => {
            !t.is_empty()
                && !sub.is_empty()
                && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && sub
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | '.'))
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rejects_traversal_and_empty() {
        assert_eq!(
            normalize_path("/css/app.css"),
            Some("css/app.css".to_string())
        );
        assert_eq!(normalize_path("logo.png"), Some("logo.png".to_string()));
        assert!(normalize_path("../etc/passwd").is_none());
        assert!(normalize_path("a//b").is_none());
        assert!(normalize_path("a/./b").is_none());
        assert!(normalize_path("").is_none());
        assert!(normalize_path("has space.css").is_none());
    }

    #[test]
    fn path_from_origin_takes_path_component() {
        assert_eq!(
            path_from_origin_url("https://cdn.example.com/assets/app.css?v=2"),
            Some("assets/app.css".to_string())
        );
        assert_eq!(
            path_from_origin_url("http://host/logo.png"),
            Some("logo.png".to_string())
        );
        assert!(path_from_origin_url("https://host").is_none());
    }

    #[test]
    fn content_type_prefers_extension_then_magic() {
        assert_eq!(
            resolve_content_type("a/app.css", b"body{}", ""),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            resolve_content_type("blob", &[0x89, b'P', b'N', b'G', 0, 0], ""),
            "image/png"
        );
        assert_eq!(
            resolve_content_type("blob", b"???", "image/jpeg"),
            "image/jpeg"
        );
        assert_eq!(
            resolve_content_type("blob", b"???", "not a mime"),
            "application/octet-stream"
        );
    }
}
