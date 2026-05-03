# Integration Harness

This directory is reserved for integration harness assets that are too broad
for default Cargo tests.

Current entrypoint:

```sh
cargo run -p xtask -- integration s3-local
```

The first mode expects an already running S3-compatible endpoint and an existing
test bucket. It delegates to the live storage contract test and uses
`RS3_TEST_S3_*` environment variables or matching command-line flags.

Future modes should plug container and Kubernetes startup into the same xtask
entrypoint, so provider setup, cleanup, logs, and generated artifacts stay
outside normal unit tests.
