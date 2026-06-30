# syntax=docker/dockerfile:1
#
# Multi-stage build for Eddy (static-asset edge cache / mini-CDN).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# Like relay/aperture/cellar, Eddy links NO OpenSSL: reqwest uses `rustls-tls`, sqlx uses `rustls`,
# and the HMAC signing is RustCrypto (hmac + sha2), so the binary depends only on glibc — no libssl
# in either stage. `ca-certificates` is present so the rustls client can verify an origin's TLS
# chain when fetching an asset. The container HEALTHCHECK uses the built-in `eddy healthcheck`
# subcommand, so no extra HTTP tool is needed in the image.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib/bin against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin eddy \
    && rm -rf src

# Now build the real binary. static/ + templates/ are include_str!'d into the binary, so they must
# be present at compile time.
COPY src ./src
COPY static ./static
COPY templates ./templates
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin eddy \
    && strip target/release/eddy

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home eddy
COPY --from=builder /build/target/release/eddy /usr/local/bin/eddy

# Content-addressed blob root. Pre-creating it owned by uid 10001 means a FRESH named/anonymous
# volume mounted here inherits writable ownership (Docker seeds the volume from the image path).
RUN mkdir -p /data && chown eddy:eddy /data
VOLUME ["/data"]

USER eddy
# Default in-container config; overridable at runtime.
ENV BIND_ADDR=0.0.0.0:9220 \
    EDDY_DATA=/data
EXPOSE 9220

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["eddy", "healthcheck"]

ENTRYPOINT ["eddy"]
