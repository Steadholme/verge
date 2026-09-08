# Eddy — static-asset edge cache / mini-CDN

Eddy is a self-hosted edge for static assets in the Steadholme sovereign-infra estate. It stores
assets **content-addressed** on a local volume, serves them from a public `/a/…` path with strong
ETags + `Cache-Control` + conditional `304` + `Range`, and supports **exact** invalidation and
optional **HMAC-signed** URLs — so user IPs and assets stay private and cache busting is precise.

- **Subdomain:** `edge.w33d.xyz` · **internal port:** `9220`
- **Stack:** Rust + axum, sqlx (Postgres, portable SQL, no macros), reqwest (rustls), pure-Rust HMAC.
  No OpenSSL anywhere.

## Surfaces (split at the Sluice gateway)

| Path | Auth | Purpose |
|------|------|---------|
| `GET /healthz` | public | Liveness (container HEALTHCHECK). |
| `GET /` | **SSO** | Console: cached-asset list (sizes, hit counts, total cache size) + add-asset form. |
| `POST /api/assets` | **SSO + CSRF** | Add an asset — multipart upload OR `{origin_url}` fetch. Stores content-addressed, returns the public `/a/` URL. |
| `POST /api/purge` | **SSO + CSRF** | Exact purge by `path` or `hash`. Emits `eddy.purge` to Watchtower. |
| `GET /a/{*path}` | **public** | Serve a cached asset (ETag / `Cache-Control` / `304` / `Range`); bumps hits. |

`/` (and `/api/`) is internal-only behind Sluice SSO; Eddy trusts the injected `X-Auth-Subject` /
`X-Auth-Email` (inbound `X-Auth-*` is stripped by the gateway). `/a/` is public so a browser
`<img>`/`<script>` can load a cached asset without an SSO cookie.

## Storage

`assets(id, path UNIQUE, content_hash, content_type, bytes, origin_url, created_at, hits)` +
`INDEX(content_hash)`. The bytes live in a content-addressed blob store keyed by SHA-256; identical
bytes across paths collapse to one physical blob, and a purge garbage-collects a blob only once no
asset references it.

- `EDDY_STORE=memory` (default) | `postgres` (`EDDY_DATABASE_URL` / `DATABASE_URL`).
- `EDDY_BLOBS=memory` (default) | `fs` (content-addressed at `<EDDY_DATA>/blobs/<sha256>`).

Boots zero-config (in-memory store + blobs, audit off, no signing).

## Configuration

| Env | Default | Notes |
|-----|---------|-------|
| `BIND_ADDR` | `0.0.0.0:9220` | Listen address. |
| `EDDY_STORE` | `memory` | `memory` \| `postgres`. |
| `EDDY_DATABASE_URL` | — | Required when `EDDY_STORE=postgres`. |
| `EDDY_BLOBS` | `memory` | `memory` \| `fs`. |
| `EDDY_DATA` | `/data` | Volume root; blobs under `<EDDY_DATA>/blobs`. |
| `PUBLIC_BASE_URL` | `https://edge.w33d.xyz` | Used to render `/a/` URLs. |
| `EDDY_CACHE_MAX_AGE` | `86400` | `Cache-Control: public, max-age=…` seconds. |
| `EDDY_MAX_ASSET` | `26214400` | Per-asset byte cap (25 MiB). |
| `EDDY_SIGNING_KEY` | — | When set, `/a/` requires a valid HMAC `?exp=&sig=`. |
| `EDDY_SIGNED_TTL` | `3600` | Validity window (seconds) for a freshly minted signed URL. |
| `AUDIT_ENABLED` / `WATCHTOWER_URL` / `AUDIT_INGEST_TOKEN` | off | Non-blocking audit emitter (`source=eddy`). |

## Build & test

```sh
CARGO_BUILD_JOBS=2 cargo check --all-targets
CARGO_BUILD_JOBS=2 cargo test
```

The container HEALTHCHECK is `eddy healthcheck` (a dependency-free loopback `GET /healthz`).

## 前端 v2（2026-09-08）

Static edge 控制台按 Figma 文件 `BYTQUgcUowEbuwaFOLvk0Q`（Verge，moss accent）
重做：套件栏（Mesh / Edge / VPN）、统计瓦片、缓存资产表、拖放上传卡、边缘定义
卡、精确清除卡。样式在 `static/service.css`，与 Odyssey 基底层叠后由
`/assets/eddy-20260908.css` 以不可变缓存提供；改样式时同步提升该路径里的日期
（测试会断言路径）。
