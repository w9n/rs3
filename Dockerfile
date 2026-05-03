ARG RUST_VERSION=1.94

FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
COPY . .
RUN rm -f rust-toolchain.toml \
    && cargo build --locked --release -p rs3-server --features s3,k8s

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/rs3-server /usr/local/bin/rs3-server
USER 65532:65532
EXPOSE 9080
ENTRYPOINT ["/usr/local/bin/rs3-server"]
