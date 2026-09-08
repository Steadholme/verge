//! The SSO web console + management API (`edge.w33d.xyz/`).
//!
//! Mounted behind the gateway `auth=sso` route — the operator identity is taken from the injected
//! `X-Auth-Subject` / `X-Auth-Email` (Eddy trusts these; it is internal-only). The console lists the
//! cached assets with sizes + hit counts + the total cache size, and offers an add-asset form
//! (upload a file OR fetch from an origin URL) plus an exact purge. Every POST is double-submit CSRF
//! protected, and a cache purge emits a non-blocking `eddy.purge` audit event.

use axum::extract::{FromRequest, Multipart, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth::{self, Identity};
use crate::config::Config;
use crate::error::AppError;
use crate::handlers::{esc, html_with_csrf, human_size, page_with, redirect, short, ICON_CLOCK, ICON_EXTERNAL, ICON_FILE, ICON_FILE_CODE, ICON_IMAGE, ICON_KEY, ICON_PLUS, ICON_TRASH, ICON_UPLOAD_CLOUD};
use crate::media;
use crate::store::{Asset, CacheStats};
use crate::{now_secs, random_alnum, sha256_hex, sign, AppState};

const ASSET_ID_LEN: usize = 16;

// ===========================================================================
// GET / — console dashboard
// ===========================================================================

pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    render(&state, &headers, &who, &csrf, Reveal::None).await
}

// ===========================================================================
// POST /api/assets — add an asset (multipart upload OR {origin_url})
// ===========================================================================

/// `POST /api/assets` — accept an uploaded file OR fetch from `origin_url`, store the bytes
/// content-addressed on the blob volume, persist the metadata row, and surface the public `/a/`
/// URL. CSRF-checked; size-capped. Handles BOTH `multipart/form-data` (the upload form) and a
/// JSON / urlencoded `{origin_url}` body.
pub async fn create_asset(
    State(state): State<AppState>,
    req: Request,
) -> Result<Response, AppError> {
    let headers = req.headers().clone();
    let who = auth::identity(&headers);
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // --- 1. gather the input (multipart fields, or a structured body) ------
    let input = if content_type.starts_with("multipart/form-data") {
        let mut mp = Multipart::from_request(req, &state)
            .await
            .map_err(|e| AppError::BadRequest(format!("invalid multipart form: {e}")))?;
        read_multipart(&mut mp).await?
    } else {
        // JSON / urlencoded bodies are tiny; cap generously above any plausible field set.
        let bytes = axum::body::to_bytes(req.into_body(), 256 * 1024)
            .await
            .map_err(|e| AppError::BadRequest(format!("could not read request body: {e}")))?;
        parse_structured_body(&content_type, &bytes)?
    };

    // --- 2. CSRF (double-submit) -------------------------------------------
    if !auth::verify_csrf(&headers, &input.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }

    // --- 3. resolve the bytes (upload OR origin fetch) ---------------------
    let (bytes, hint, origin_url, filename) = match input.file {
        Some(f) if !f.bytes.is_empty() => {
            let hint = first_nonempty(&input.content_type, &f.client_type);
            (f.bytes, hint, String::new(), f.filename)
        }
        _ => {
            let url = input.origin_url.trim();
            if url.is_empty() {
                return Err(AppError::BadRequest(
                    "Provide a file to upload or an origin URL to fetch.".to_string(),
                ));
            }
            let (data, origin_ctype) =
                fetch_origin(&state.http, url, state.config.max_asset).await?;
            let hint = first_nonempty(&input.content_type, &origin_ctype);
            (data, hint, url.to_string(), String::new())
        }
    };

    if bytes.len() > state.config.max_asset {
        return Err(AppError::BadRequest(format!(
            "Asset is too large (maximum {}).",
            human_size(state.config.max_asset as i64)
        )));
    }

    // --- 4. content-address + resolve the public path ----------------------
    let hash = sha256_hex(&bytes);
    let size = bytes.len() as i64;
    let path = resolve_path(&input.path, &origin_url, &filename, &hash)?;
    let resolved_type = media::resolve_content_type(&path, &bytes, &hint);

    // --- 5. publish the bytes, then upsert the metadata row ----------------
    state.blobs.put(&hash, bytes).await?;

    let previous = state.store.get_by_path(&path).await;
    let asset = Asset {
        id: format!("as_{}", random_alnum(ASSET_ID_LEN)),
        path: path.clone(),
        content_hash: hash.clone(),
        content_type: resolved_type,
        bytes: size,
        origin_url,
        created_at: now_secs(),
        hits: 0,
    };
    state.store.upsert_asset(&asset).await?;

    // If this path used to point at different bytes, garbage-collect the now-unreferenced blob.
    if let Some(prev) = previous {
        if prev.content_hash != hash {
            gc_blob_if_unreferenced(&state, &prev.content_hash).await;
        }
    }

    tracing::info!(path = %path, hash = %short(&hash, 12), size, "asset cached");
    state.audit.emit(AuditEvent::info(
        "eddy.asset.put",
        &who.email,
        &path,
        &format!("hash={} bytes={size}", short(&hash, 12)),
    ));

    let url = public_url(&state.config, &path);
    let csrf = auth::new_csrf_token();
    Ok(render(&state, &headers, &who, &csrf, Reveal::Url(&url)).await)
}

// ===========================================================================
// POST /api/purge — exact invalidation by path or hash
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct PurgeForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub hash: String,
}

/// `POST /api/purge` — remove a cached asset exactly, by `path` or by `content_hash`, then 303 to
/// `/`. Garbage-collects the underlying blob once it is no longer referenced. Emits `eddy.purge`.
pub async fn purge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PurgeForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let path = form.path.trim();
    let hash = form.hash.trim();

    if !path.is_empty() {
        // Capture the hash before deleting, so we can GC the blob afterwards.
        let prev = state.store.get_by_path(path).await;
        let removed = state.store.delete_by_path(path).await?;
        if let Some(prev) = prev {
            gc_blob_if_unreferenced(&state, &prev.content_hash).await;
        }
        if removed {
            tracing::info!(path = %path, "asset purged by path");
            state.audit.emit(AuditEvent::warning(
                "eddy.purge",
                &who.email,
                path,
                "by path",
            ));
        }
    } else if !hash.is_empty() {
        let n = state.store.delete_by_hash(hash).await?;
        if n > 0 {
            // All references gone by definition — drop the blob.
            let _ = state.blobs.delete(hash).await;
            tracing::info!(hash = %short(hash, 12), removed = n, "assets purged by hash");
            state.audit.emit(AuditEvent::warning(
                "eddy.purge",
                &who.email,
                hash,
                &format!("by hash ({n} path(s))"),
            ));
        }
    } else {
        return Err(AppError::BadRequest(
            "Specify a path or a content hash to purge.".to_string(),
        ));
    }

    Ok(redirect("/"))
}

// ===========================================================================
// Input handling
// ===========================================================================

/// Parsed inputs for an add-asset request, from EITHER a multipart form or a structured body.
#[derive(Default)]
struct AssetInput {
    path: String,
    origin_url: String,
    content_type: String,
    csrf_token: String,
    file: Option<UploadedFile>,
}

struct UploadedFile {
    filename: String,
    client_type: String,
    bytes: Vec<u8>,
}

/// JSON / urlencoded body shape for the `{origin_url}` path (no file upload).
#[derive(Debug, Default, Deserialize)]
struct BodyInput {
    #[serde(default)]
    path: String,
    #[serde(default)]
    origin_url: String,
    #[serde(default)]
    content_type: String,
    #[serde(default)]
    csrf_token: String,
}

/// Read the multipart form fields into an [`AssetInput`]. The `file` field is optional (a text-only
/// submit still arrives with an empty file part, which is treated as absent).
async fn read_multipart(mp: &mut Multipart) -> Result<AssetInput, AppError> {
    let mut input = AssetInput::default();
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                return Err(AppError::BadRequest(format!(
                    "Upload failed (it may exceed the size limit): {e}"
                )))
            }
        };
        match field.name().unwrap_or("").to_string().as_str() {
            "csrf_token" => input.csrf_token = field_text(field).await?,
            "path" => input.path = field_text(field).await?,
            "origin_url" => input.origin_url = field_text(field).await?,
            "content_type" => input.content_type = field_text(field).await?,
            "file" => {
                let filename = field.file_name().unwrap_or("").to_string();
                let client_type = field.content_type().unwrap_or("").to_string();
                let data = field.bytes().await.map_err(|e| {
                    AppError::BadRequest(format!(
                        "Upload failed (it may exceed the size limit): {e}"
                    ))
                })?;
                if !data.is_empty() {
                    input.file = Some(UploadedFile {
                        filename,
                        client_type,
                        bytes: data.to_vec(),
                    });
                }
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }
    Ok(input)
}

async fn field_text(field: axum::extract::multipart::Field<'_>) -> Result<String, AppError> {
    field
        .text()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid form field: {e}")))
}

/// Parse a JSON or urlencoded `{origin_url, path?, content_type?, csrf_token}` body.
fn parse_structured_body(content_type: &str, bytes: &[u8]) -> Result<AssetInput, AppError> {
    let body: BodyInput = if content_type.contains("json") {
        serde_json::from_slice(bytes)
            .map_err(|e| AppError::BadRequest(format!("malformed JSON body: {e}")))?
    } else {
        serde_urlencoded::from_bytes(bytes)
            .map_err(|e| AppError::BadRequest(format!("malformed form body: {e}")))?
    };
    Ok(AssetInput {
        path: body.path,
        origin_url: body.origin_url,
        content_type: body.content_type,
        csrf_token: body.csrf_token,
        file: None,
    })
}

/// Fetch an asset from an origin URL (http/https only), returning its bytes + response content-type.
/// Size-capped: an oversize origin body is rejected rather than buffered whole again.
async fn fetch_origin(
    http: &reqwest::Client,
    url: &str,
    max: usize,
) -> Result<(Vec<u8>, String), AppError> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(AppError::BadRequest(
            "origin_url must start with http:// or https://".to_string(),
        ));
    }
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("origin fetch failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::BadRequest(format!(
            "origin returned HTTP {}",
            resp.status().as_u16()
        )));
    }
    let ctype = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp
        .bytes()
        .await
        .map_err(|e| AppError::BadRequest(format!("reading origin body failed: {e}")))?;
    if body.len() > max {
        return Err(AppError::BadRequest(format!(
            "origin asset is too large (maximum {}).",
            human_size(max as i64)
        )));
    }
    Ok((body.to_vec(), ctype))
}

/// Resolve the canonical public path: an explicit `path` field wins; else derive it from the origin
/// URL or the upload filename; else fall back to the content hash (always a valid, unique path).
fn resolve_path(
    explicit: &str,
    origin_url: &str,
    filename: &str,
    hash: &str,
) -> Result<String, AppError> {
    let explicit = explicit.trim();
    if !explicit.is_empty() {
        return media::normalize_path(explicit)
            .ok_or_else(|| AppError::BadRequest("invalid asset path".to_string()));
    }
    if !origin_url.is_empty() {
        if let Some(p) = media::path_from_origin_url(origin_url) {
            return Ok(p);
        }
    }
    if !filename.is_empty() {
        if let Some(p) = media::path_from_filename(filename) {
            return Ok(p);
        }
    }
    Ok(hash.to_string())
}

/// Delete a blob once no asset row references its content hash anymore.
async fn gc_blob_if_unreferenced(state: &AppState, hash: &str) {
    match state.store.count_by_hash(hash).await {
        Ok(0) => {
            if let Err(e) = state.blobs.delete(hash).await {
                tracing::warn!(hash = %short(hash, 12), error = %e, "orphan blob delete failed");
            }
        }
        Ok(_) => {} // still referenced by another path — keep it (de-dup)
        Err(e) => tracing::warn!(error = %e, "refcount lookup failed; leaving blob in place"),
    }
}

/// The first of two strings that is non-empty (after trimming), else empty.
fn first_nonempty(a: &str, b: &str) -> String {
    if !a.trim().is_empty() {
        a.trim().to_string()
    } else {
        b.trim().to_string()
    }
}

/// Build the public `/a/` URL for `path`, appending a signed `?exp=&sig=` when signing is enabled.
fn public_url(config: &Config, path: &str) -> String {
    let base = format!("{}/a/{}", config.public_base_url, path);
    match config.signing_key_bytes() {
        Some(key) => {
            let exp = now_secs() + config.signed_ttl;
            format!("{base}{}", sign::query(key, path, exp))
        }
        None => base,
    }
}

// ===========================================================================
// Rendering
// ===========================================================================

/// What (if anything) to surface in the banner above the dashboard after a POST.
enum Reveal<'a> {
    None,
    Url(&'a str),
}

/// Render the dashboard, optionally with the new asset's public URL revealed above the table.
async fn render(
    state: &AppState,
    headers: &HeaderMap,
    who: &Identity,
    csrf: &str,
    reveal: Reveal<'_>,
) -> Response {
    let body = build_dashboard(state, who, csrf, &reveal).await;
    html_with_csrf(
        StatusCode::OK,
        page_with(headers, "Static edge", Some(&who.email), &body),
        csrf,
    )
}

async fn build_dashboard(
    state: &AppState,
    _who: &Identity,
    csrf: &str,
    reveal: &Reveal<'_>,
) -> String {
    let assets = state.store.list_assets().await;
    let stats = state.store.stats().await;

    let reveal_html = render_reveal(reveal);
    let stat_grid = render_stats(&stats, state.blobs.backend());
    let asset_table = render_assets(&assets, csrf, &state.config);
    let signed = state.config.signing_enabled();
    let signed_pill = if signed {
        format!(r#"<span class="signed signed--on">{ICON_KEY}Signed URLs on</span>"#)
    } else {
        format!(r#"<span class="signed">{ICON_KEY}Signed URLs off</span>"#)
    };
    let signed_defs = if signed {
        format!(
            "?exp=&amp;sig= · HMAC · TTL {} s",
            state.config.signed_ttl
        )
    } else {
        "unsigned · /a/… served as-is".to_string()
    };
    let head_sub = format!(
        "{} · {} · {} · content-addressed · exact purge",
        esc(&host_of(&state.config.public_base_url)),
        plural(stats.count as usize, "asset", "assets"),
        esc(&human_size(stats.total_bytes)),
    );
    let first_steps = if assets.is_empty() {
        format!(
            r#"<section class="card"><div class="card__head"><h2>First asset</h2></div><div class="card__pad"><div class="steps">
<div class="step step--waiting"><span class="step__mark" aria-hidden="true">{ICON_CLOCK}</span><div><div class="step__label">Upload a file or fetch an origin URL</div><div class="step__who">max {max}</div></div></div>
<div class="step step--waiting"><span class="step__mark" aria-hidden="true">{ICON_CLOCK}</span><div><div class="step__label">Public path</div><div class="step__who">optional · derived from the URL or filename · else the sha256</div></div></div>
<div class="step step--waiting"><span class="step__mark" aria-hidden="true">{ICON_CLOCK}</span><div><div class="step__label">Serve from /a/…</div><div class="step__who">strong ETag · Cache-Control · 304 · Range</div></div></div>
</div></div></section>"#,
            max = esc(&human_size(state.config.max_asset as i64)),
        )
    } else {
        String::new()
    };

    format!(
        r##"<header class="pagehead">
  <div class="pagehead__titles"><h1>Static edge</h1><p class="pagehead__sub">{head_sub}</p></div>
  <div class="pagehead__actions"><a class="btn btn-secondary" href="/">Refresh</a></div>
</header>
{stat_grid}
{reveal_html}
<div class="two-col two-col--rail-lg">
  <div class="rail">
    <section class="card">
      <div class="card__head"><h2>Cached assets</h2><span class="card__count">{count}</span></div>
      {asset_table}
    </section>
    {first_steps}
  </div>
  <aside class="rail">
    <section class="card" id="add">
      <div class="card__head"><h2>Add an asset</h2></div>
      <div class="card__pad">
        <form class="form-stack" method="post" action="/api/assets" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <label class="drop" for="file">{ICON_UPLOAD_CLOUD}<span class="drop__title">Drop a file</span><span class="drop__limits">≤ {max} · any content type · sha256 addressed</span><input type="file" id="file" name="file"></label>
          <span class="or">or fetch from an origin URL</span>
          <div class="field"><label for="origin_url">Origin URL</label><input type="text" id="origin_url" name="origin_url" placeholder="https://origin.example.com/app.css" autocomplete="off"></div>
          <div class="field"><label for="path">Public path (optional)</label><input type="text" id="path" name="path" placeholder="css/app.css" autocomplete="off"></div>
          <button class="btn btn-primary" type="submit">{ICON_PLUS}Cache asset</button>
        </form>
      </div>
    </section>
    <section class="card">
      <div class="card__head"><h2>Edge</h2>{signed_pill}</div>
      <div class="defs">
        <div class="defs__row"><span class="defs__term">Storage</span><span class="defs__value mono">{backend}</span></div>
        <div class="defs__row"><span class="defs__term">Cache-Control</span><span class="defs__value mono">public, max-age={max_age}</span></div>
        <div class="defs__row"><span class="defs__term">Max asset</span><span class="defs__value">{max}</span></div>
        <div class="defs__row"><span class="defs__term">Public base</span><span class="defs__value mono">{base}</span></div>
        <div class="defs__row"><span class="defs__term">Signed URLs</span><span class="defs__value">{signed_defs}</span></div>
        <div class="defs__row"><span class="defs__term">Conditional</span><span class="defs__value">ETag · 304 · Range</span></div>
        <div class="defs__row"><span class="defs__term">Audit</span><span class="defs__value">eddy.asset.put · eddy.purge → Watchtower</span></div>
      </div>
    </section>
    <section class="card" id="purge">
      <div class="card__head"><h2>Purge</h2></div>
      <div class="card__pad">
        <form class="form-stack" method="post" action="/api/purge">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <div class="field"><label for="purge-path">Path</label><input type="text" id="purge-path" name="path" placeholder="css/app.css" autocomplete="off"></div>
          <div class="field"><label for="purge-hash">or sha256</label><input type="text" id="purge-hash" name="hash" placeholder="9f1c…" autocomplete="off"></div>
          <button class="btn btn-danger-soft" type="submit">{ICON_TRASH}Purge exact</button>
          <span class="drop__limits">blob GC when unreferenced</span>
        </form>
      </div>
    </section>
  </aside>
</div>"##,
        head_sub = head_sub,
        stat_grid = stat_grid,
        reveal_html = reveal_html,
        count = stats.count,
        asset_table = asset_table,
        first_steps = first_steps,
        csrf = esc(csrf),
        max = esc(&human_size(state.config.max_asset as i64)),
        backend = esc(state.blobs.backend()),
        max_age = state.config.cache_max_age,
        base = esc(&state.config.public_base_url),
        signed_pill = signed_pill,
        signed_defs = signed_defs,
    )
}

fn host_of(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string()
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn render_reveal(reveal: &Reveal<'_>) -> String {
    match reveal {
        Reveal::None => String::new(),
        Reveal::Url(url) => format!(
            r##"<section class="reveal reveal--asset" role="status">
  <span class="reveal__label">Asset cached · public URL</span>
  <div class="reveal__row"><input class="reveal__url" type="text" readonly value="{url}" spellcheck="false"><a class="btn btn-secondary" href="{url}">{ICON_EXTERNAL}Open</a></div>
</section>"##,
            url = esc(url),
        ),
    }
}

fn render_stats(stats: &CacheStats, backend: &str) -> String {
    format!(
        r##"<div class="stats">
  <div class="stat-tile stat-tile--accent"><div class="stat-tile__value">{count}</div><div class="stat-tile__name">cached assets</div></div>
  <div class="stat-tile"><div class="stat-tile__value">{size}</div><div class="stat-tile__name">total cache size</div></div>
  <div class="stat-tile"><div class="stat-tile__value">{hits}</div><div class="stat-tile__name">edge hits</div></div>
  <div class="stat-tile"><div class="stat-tile__value">{blobs}</div><div class="stat-tile__name">distinct blobs · {backend}</div></div>
</div>"##,
        count = stats.count,
        size = esc(&human_size(stats.total_bytes)),
        hits = stats.total_hits,
        blobs = stats.distinct_blobs,
        backend = esc(backend),
    )
}

fn kind_icon(content_type: &str) -> &'static str {
    if content_type.starts_with("image/") {
        ICON_IMAGE
    } else if content_type.contains("css")
        || content_type.contains("javascript")
        || content_type.contains("json")
    {
        ICON_FILE_CODE
    } else {
        ICON_FILE
    }
}

fn render_assets(assets: &[Asset], csrf: &str, config: &Config) -> String {
    if assets.is_empty() {
        return format!(
            r##"<div class="card__pad"><div class="empty-tile">{ICON_UPLOAD_CLOUD}<span>No assets cached yet</span><a class="btn btn-secondary btn-sm" href="#add">Cache the first asset</a></div></div>"##
        );
    }
    let rows = assets
        .iter()
        .map(|a| {
            let url = public_url(config, &a.path);
            format!(
                r##"<tr>
  <td class="c-kind"><span class="asset-kind">{icon}</span></td>
  <td class="c-path"><a href="{url}">/a/{path}</a></td>
  <td class="c-source">{ctype}</td>
  <td class="c-seq">{size}</td>
  <td class="c-seq">{hits}</td>
  <td class="c-hash"><span class="hash hash--sm" title="{fullhash}">{hash}</span></td>
  <td class="c-actions"><span class="row-actions">
    <form class="inline-form" method="post" action="/api/purge" onsubmit="return confirm('Purge this asset from the edge? This is immediate and exact.');">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="hidden" name="path" value="{path}">
      <button class="btn btn-danger-soft btn-sm" type="submit">Purge</button>
    </form>
  </span></td>
</tr>"##,
                icon = kind_icon(&a.content_type),
                url = esc(&url),
                path = esc(&a.path),
                ctype = esc(&a.content_type),
                size = esc(&human_size(a.bytes)),
                hits = a.hits,
                fullhash = esc(&a.content_hash),
                hash = esc(&short(&a.content_hash, 12)),
                csrf = esc(csrf),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        r##"<div class="table-scroll"><table class="timeline asset-table">
  <thead><tr><th class="c-kind"></th><th>Path</th><th>Content type</th><th class="c-seq">Size</th><th class="c-seq">Hits</th><th>sha256</th><th></th></tr></thead>
  <tbody>{rows}</tbody>
</table></div>"##,
        rows = rows,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_path_prefers_explicit_then_origin_then_hash() {
        let hash = "abc123";
        assert_eq!(
            resolve_path("css/app.css", "https://x/y.css", "z.css", hash).unwrap(),
            "css/app.css"
        );
        assert_eq!(
            resolve_path("", "https://x/assets/y.css", "", hash).unwrap(),
            "assets/y.css"
        );
        assert_eq!(resolve_path("", "", "logo.png", hash).unwrap(), "logo.png");
        assert_eq!(resolve_path("", "", "", hash).unwrap(), hash);
        assert!(resolve_path("../escape", "", "", hash).is_err());
    }

    #[test]
    fn public_url_signs_when_keyed() {
        let mut config = Config::dev();
        config.public_base_url = "https://edge.w33d.xyz".to_string();
        // Unsigned.
        assert_eq!(
            public_url(&config, "css/app.css"),
            "https://edge.w33d.xyz/a/css/app.css"
        );
        // Signed.
        config.signing_key = Some("k".to_string());
        let signed = public_url(&config, "css/app.css");
        assert!(signed.starts_with("https://edge.w33d.xyz/a/css/app.css?exp="));
        assert!(signed.contains("&sig="));
    }
}
