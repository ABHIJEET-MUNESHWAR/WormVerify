# WormVerify off-chain relayer — multi-stage production image.
#
# Builds the `wormverify-node` binary with the `postgres` feature and ships it
# on a slim non-root Debian base.

FROM rust:1.89-slim-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# Build only the off-chain workspace (anchor/ is a separate workspace).
RUN cargo build --release -p wormverify-node \
    && strip target/release/wormverify-node

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --home-dir /nonexistent --no-create-home wormverify
COPY --from=build /app/target/release/wormverify-node /usr/local/bin/wormverify-node
USER 10001
EXPOSE 8080
ENV WV_BIND_ADDR=0.0.0.0:8080 RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/wormverify-node"]
CMD ["serve"]
