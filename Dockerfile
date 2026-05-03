# syntax=docker/dockerfile:1.7
ARG RUST_VERSION=1.94

FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
COPY Cargo.lock Cargo.toml ./
COPY xtask/Cargo.toml ./xtask/Cargo.toml
RUN mkdir -p xtask/src \
    && printf 'fn main() {}\n' > xtask/src/main.rs
COPY crates ./crates
RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/git \
    --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,target=/src/target \
    cargo build --locked --release -p rs3-server --features s3,k8s --bins \
    && cp /src/target/release/rs3-server /tmp/rs3-server \
    && cp /src/target/release/rs3-storage-measure-proxy /tmp/rs3-storage-measure-proxy

FROM debian:bookworm-slim AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /tmp/rs3-server /usr/local/bin/rs3-server
EXPOSE 9080
ENTRYPOINT ["/usr/local/bin/rs3-server"]

FROM runtime-base AS integration-tools
COPY --from=build /tmp/rs3-storage-measure-proxy /usr/local/bin/rs3-storage-measure-proxy
USER 65532:65532

FROM runtime-base AS runtime
USER 65532:65532
