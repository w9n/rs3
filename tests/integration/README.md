# Integration Harness

This directory is reserved for integration harness assets that are too broad
for default Cargo tests.

Current entrypoint:

```sh
cargo run -p xtask -- integration s3-local
```

The default mode expects an already running S3-compatible endpoint and an
existing test bucket. It delegates to the live storage contract test and uses
`RS3_TEST_S3_*` environment variables or matching command-line flags.

The container mode starts a local provider, creates a temporary bucket, and
then runs the same storage contract:

```sh
cargo run -p xtask --features containers -- integration s3-local --mode container
```

The gateway mode starts a local provider, creates a backend bucket, starts the
gateway, and drives object operations through the gateway's S3 endpoint:

```sh
cargo run -p xtask --features containers -- integration s3-gateway
```

Container provider setup stays behind the opt-in `xtask/containers` feature so
Docker and provider bootstrap dependencies stay outside normal unit tests and
runtime crates.
