# syntax=docker/dockerfile:1
#
# Multi-stage build for Verge (edge/mesh vhost demux over two vendored library crates, dual listener).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# Both surfaces embed their templates + static CSS via include_str! at COMPILE time, so the runtime
# image carries only the single statically-templated binary — no assets to ship. Eddy's reqwest uses
# rustls-tls, both stores use sqlx rustls, and Eddy's HMAC signing is RustCrypto, so the binary
# depends only on glibc — no libssl. ca-certificates is kept so Eddy's rustls client can verify an
# origin's TLS chain (and the audit emitter posts to Watchtower). The HEALTHCHECK uses the built-in
# `verge healthcheck` subcommand, so the image needs no curl.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Bring the whole self-contained crate (the binary + the two vendored surface crates under
# crates/) and build the release binary. The surfaces' static/ + templates/ are needed at build
# time for their include_str! embeds.
COPY Cargo.toml ./
COPY src ./src
COPY crates ./crates
RUN cargo build --release --bin verge \
    && strip target/release/verge

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home verge
COPY --from=builder /build/target/release/verge /usr/local/bin/verge

# Eddy's content-addressed blob root (EDDY_BLOBS=fs). Pre-creating it owned by uid 10001 means a
# FRESH named/anonymous volume mounted here inherits writable ownership.
RUN mkdir -p /data && chown verge:verge /data
VOLUME ["/data"]

USER verge
# Default in-container config; overridable at runtime. BIND_ADDR is the edge (Eddy) listener;
# MESH_BIND_ADDR is the mesh (Mycelium) listener — both serve the same demux router.
ENV BIND_ADDR=0.0.0.0:9220 \
    MESH_BIND_ADDR=0.0.0.0:9290 \
    EDDY_DATA=/data
EXPOSE 9220 9290

# Dependency-free liveness probe -> GET /healthz on the loopback (primary port), exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["verge", "healthcheck"]

CMD ["verge"]
