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
    cargo build --locked --release -p rs3-server --features s3,k8s \
    && cp /src/target/release/rs3-server /tmp/rs3-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /tmp/rs3-server /usr/local/bin/rs3-server
USER 65532:65532
EXPOSE 9080
ENTRYPOINT ["/usr/local/bin/rs3-server"]
