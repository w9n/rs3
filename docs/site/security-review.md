# Security Review

Use this checklist for changes that touch storage, crypto, namespace lookup,
anchors, retention, logs, metrics, or restore behavior.

## Inputs

Review the changed files, emitted backend objects, telemetry labels, failure
paths, tests, and any performance artifact. Do not accept intent alone; inspect
durable bytes and observable names.

## Privacy

| Question | Pass Condition |
| --- | --- |
| Handles client-visible names? | Names stay in trusted memory or encrypted/authenticated payloads. |
| Writes keys, tags, metadata, logs, traces, or metrics? | No plaintext path, Kubernetes name, snapshot label, tenant name, or backend object ID leaks. |
| Changes equality leakage? | Leakage is secret-keyed, necessary, and documented. |
| Changes LIST behavior? | Prefix listing remains gateway-owned. |
| Changes telemetry? | Labels use operation/result classes, never client data. |

## Integrity

| Question | Pass Condition |
| --- | --- |
| Can backend replay old objects? | Replay is rejected unless checkpoint and anchor state accept it. |
| Can partial writes become visible? | Visibility requires an accepted checkpoint. |
| Can checkpoint be forged? | Signature verifies under an enabled signing key. |
| Can old valid checkpoint appear latest? | Anchor or storage evidence detects stale sequence/digest. |
| Can cleanup delete needed objects? | GC is reachability and retention aware. |

## Retention

| Question | Pass Condition |
| --- | --- |
| Writes restore-critical data? | Payload, metadata, index, checkpoint, and evidence receive effective retention. |
| Extends retention? | Extension never shortens existing retention. |
| Provider cannot extend? | Protected write fails instead of claiming protection. |
| Dedup reuses old data? | Reused objects are retained until the newest protected reference expires. |
| Retires keys? | Blocked while retained data can require the key. |

## Evidence

| Claim | Evidence |
| --- | --- |
| Default checks pass | `just check` |
| Docs build | `just docs-build` inside Nix |
| S3 storage contract | `just integration-s3-local --mode container` |
| Gateway S3 path | `just integration-s3-gateway` |
| Kopia restore | `just integration-kopia-gateway` |
| Larger restore baseline | `kopia-measured-matrix --profile-set larger-restores --runs 3 --gateway-build-profile release` |
| Path privacy | repository path invariant tests plus object/log inspection |

## Stop Conditions

Stop the review if a change:

- adds plaintext names to backend keys, telemetry, tags, or errors
- treats Object Lock as the only latest-state authority
- falls back from external anchor to memory
- retires keys without retained-checkpoint analysis
- optimizes reads through path-indexed backend objects
- adds provider behavior without a capability test or documented contract
