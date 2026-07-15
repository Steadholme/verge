# Mycelium — zero-trust WireGuard mesh control plane

Mycelium is the Steadholme stack's **mesh coordination server** — a self-hosted control plane in
the spirit of Tailscale's coordination service. It enrolls devices, manages peers and ACLs, and
**generates valid WireGuard configurations**. It does **not** bring up a live kernel tunnel on
this host.

- **Internal-only**, behind Sluice `auth=sso` at `mesh.w33d.xyz` (route `/` = SSO admin).
- **Internal port:** `9290`.
- **Identity:** trusts gateway-injected `X-Auth-Subject` / `X-Auth-Email` (Sluice strips inbound
  `X-Auth-*`). No login of its own.
- **Crypto:** real Curve25519 keypairs via the pure-Rust `x25519-dalek` crate — **no OpenSSL**.
  Each device gets a private key (shown **once**) plus a stored public key, and a stable mesh IP
  assigned from `MESH_CIDR` (default `10.77.0.0/24`).

## Endpoints

| Method + path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | Liveness (container HEALTHCHECK) |
| `GET /` | SSO | Admin dashboard: devices, enroll form, ACL table, trust/CIDR summary |
| `POST /api/devices` | SSO + CSRF | Enroll: server generates keypair + assigns mesh IP, returns the full `wg.conf` **once** |
| `POST /api/devices/{id}/revoke` | SSO + CSRF | Revoke (disable) a device |
| `POST /api/acls` | SSO + CSRF | Add an ACL rule (`src_tag → dst_tag` on `ports`) |
| `GET /api/config/{id}` | SSO | Re-render a device's `wg.conf` **without** the private key |

State-changing POSTs are double-submit CSRF protected (`__Host-csrf` cookie + hidden field).
Audit events `mycelium.enroll` / `mycelium.revoke` are emitted to Watchtower (non-blocking).

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:9290` | Listen address |
| `MYCELIUM_STORE` | `memory` | `memory` or `postgres` |
| `DATABASE_URL` | — | Required when `MYCELIUM_STORE=postgres` |
| `MESH_CIDR` | `10.77.0.0/24` | Mesh address space (IPv4) |
| `MESH_DNS` | CIDR gateway (`.1`) | DNS advertised in `[Interface]` |
| `MESH_ENDPOINT_DOMAIN` | `mesh.w33d.xyz` | Suffix for peer `Endpoint` hostnames (empty disables `Endpoint`) |
| `MESH_LISTEN_PORT` | `51820` | WireGuard port baked into peer `Endpoint`s |
| `AUDIT_ENABLED` / `WATCHTOWER_URL` / `AUDIT_INGEST_TOKEN` | off | Watchtower audit emitter |

Boots **zero-config** on the in-memory store (no database, no network).

## ACL model

Each device carries a set of tags. An ACL rule grants traffic from any device matching `src_tag`
to any device matching `dst_tag` (`*` matches any). When a device's config is generated, a peer
is included only if a rule allows the link. With **no** rules at all the mesh is full-allow
(default-allow) so a fresh install is immediately usable; adding the first rule switches the
posture to **default-deny**.

## Storage

`async-trait Store` with an in-memory default and a `PgStore` (sqlx 0.8, runtime queries only —
no macros, rustls, no OpenSSL). Portable standard SQL (`TEXT`/`BIGINT`/`BOOLEAN`, `PK`/`UNIQUE`/
`NOT NULL`/`DEFAULT`, `INSERT … ON CONFLICT`, `CREATE INDEX`), so the same statements run
unchanged on FusionDB over pgwire. `migrate()` runs idempotently on startup.

Tables: `devices`, `acls`, `tags`. IP allocation is serialized with a `tokio::sync::Mutex`; the
`UNIQUE(mesh_ip)` / `UNIQUE(public_key)` constraints are the backstop.

## Deferred — NOT implemented in v1 (by design)

Mycelium is the **control plane only**. It deliberately performs **no** privileged or kernel
operation, so it can never destabilize the shared host running the rest of the estate:

- **No live data plane.** It does not create a `wg` interface, configure routes, or touch the
  kernel `wireguard` module. Bringing up real tunnels needs `NET_ADMIN`, `/dev/net/tun`, and a
  dedicated privileged wg node.
- **No peer reachability.** Peer `Endpoint` hostnames are *derived* from a template, not measured
  — the actual public endpoints live on the (separate, privileged) wg node.
- **No key escrow.** Private keys are generated, shown once, and discarded server-side.

> **special_deploy:** real tunnels need a privileged wg node — control plane only here.

## Build & test

```bash
CARGO_BUILD_JOBS=2 cargo check --all-targets
cargo test                       # in-memory flow + unit tests (no DB)
# Postgres store test (optional, needs an external DB):
#   TEST_DATABASE_URL=postgres://… cargo test --test pg_store -- --nocapture
```
