# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG RUST_IMAGE=rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
ARG VERSION=0.1.0
ARG REVISION=unknown

FROM ${RUST_IMAGE} AS source
WORKDIR /src
COPY Cargo.lock Cargo.toml ./
COPY LICENSE ./LICENSE
COPY xtask/Cargo.toml ./xtask/Cargo.toml
RUN mkdir -p xtask/src \
    && printf 'fn main() {}\n' > xtask/src/main.rs
COPY crates ./crates

FROM source AS build-runtime
RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/git \
    --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,target=/src/target \
    cargo build --locked --release -p rs3-server --features s3,k8s --bin rs3-server \
    && cp /src/target/release/rs3-server /tmp/rs3-server

FROM source AS integration-source
COPY xtask/src ./xtask/src

FROM integration-source AS build-integration-tools
RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/git \
    --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,target=/src/target \
    cargo build --locked --release -p xtask --bin rs3-integration-storage-proxy \
    && cp /src/target/release/rs3-integration-storage-proxy /tmp/rs3-integration-storage-proxy

FROM ${DEBIAN_IMAGE} AS runtime-base
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="rs3" \
    org.opencontainers.image.description="Path-private, tamper-evident S3-compatible backup gateway" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${REVISION}" \
    org.opencontainers.image.source="https://github.com/w9n/rs3" \
    org.opencontainers.image.licenses="AGPL-3.0-only"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build-runtime /tmp/rs3-server /usr/local/bin/rs3-server
COPY LICENSE /usr/share/licenses/rs3/LICENSE
EXPOSE 9080
ENTRYPOINT ["/usr/local/bin/rs3-server"]

FROM runtime-base AS integration-tools
COPY --from=build-integration-tools /tmp/rs3-integration-storage-proxy /usr/local/bin/rs3-integration-storage-proxy
USER 65532:65532

FROM runtime-base AS runtime
USER 65532:65532
