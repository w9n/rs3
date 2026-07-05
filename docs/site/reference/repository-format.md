# Repository Format Reference

The repository format is draft. This page records the current intended shape,
not a compatibility promise.

## Invariants

- Backend object names are opaque.
- Plaintext logical paths and Kubernetes names do not appear in backend keys,
  tags, unauthenticated metadata, commit headers, metrics, or logs.
- Privacy-sensitive metadata is encrypted and authenticated.
- Commits are signed, monotonic, and selected by an external anchor.
- Old data remains readable while any protected anchored commit can reference it.
- Provider retention is never shortened by `rs3`.
- Retained restore-critical references are bound to provider object versions
  when the backend supports version IDs.

## Backend Object Classes

The design uses a small number of non-secret classes:

```text
format/
keyrings/
commits/
```

The class leaks broad object type. That is currently accepted because it helps
operations, lifecycle policy, and debugging. Hiding class prefixes would require
a future format version.

## v2 Preview

`v2-preview` is the only repository format accepted by the current gateway. It
is an evaluation format, not a stable compatibility target yet.

Preview change control: after the current v2 preview evidence gate, changes to
backend object classes, commit-key shape, signed header fields, section layout,
anchor fields, keyring/format-root references, or provider-profile semantics
must update this reference, the rationale/runbook text, and focused test
vectors before implementation is considered complete. Treat undocumented
format drift as a release blocker.

v2 commit objects use random, path-private keys:

```text
commits/v01/<20-digit-sequence>/<32-byte-random-id-base64url>
```

The sequence segment is for bounded listing only. The accepted head is the
external anchor's full commit key, body digest, provider version ID when
required, and signing key ID. A v2 reader verifies the fixed header, header
digest, canonical CBOR header, signed `self.commit_key`, Ed25519 signature,
section layout, and body digest before trusting a commit.
Current v2 writers pad the signed header span to 4 KiB, which gives readers a
single bounded prefix read for commit-header fallback and a stable section
region offset for hot-path payload refs. This is commit-header padding, not
per-file payload padding: small payloads still use the adaptive payload segment
policy and are not expanded to 4 KiB.

The layout below shows the physical commit object and the anchored range-read
path. A v2 commit object starts with a 64-byte fixed header, followed by
canonical CBOR header bytes. In the default multipart-padded upload mode, the
signed header span is padded to 4 KiB so readers know where the section region
begins. The section region contains encrypted `PAYLOAD` sections and either
`INDEX_DELTA` or `INDEX_SNAPSHOT` sections. Range reads use trusted index refs,
including signed content length and encrypted payload-section length, verify
the commit header, read exact retained versions when required, authenticate
payload segments, and return only verified plaintext bytes.

<figure class="rv-figure">
  <a class="rv-lightbox" href="../../assets/repository-v2-format-overview.png" aria-label="Enlarge v2 repository format overview diagram" aria-haspopup="dialog" data-rv-title="v2 repository format">
    <picture>
      <source srcset="../../assets/repository-v2-format-overview.webp" type="image/webp">
      <img class="rv-diagram" src="../../assets/repository-v2-format-overview.png" width="1693" height="929" loading="lazy" decoding="async" alt="v2 commit object layout and anchored range-read flow. The trusted index entry supplies content length and payload-section length; payload sections live in the section region after multipart-only 4 KiB header padding.">
    </picture>
  </a>
</figure>

The retained-version/Object Lock provider profile does not require atomic
`If-None-Match: *` support. It requires provider version IDs, exact-version
`HEAD`/`GET`/range `GET`, visible retention or legal-hold state, and preserved
old versions after a newer latest version exists.

Normal v2 delta commits contain zero or more encrypted `PAYLOAD` sections and
one encrypted `INDEX_DELTA` section. Snapshot commits contain an
`INDEX_SNAPSHOT` section. The encrypted index entries reference payload section
offsets and lengths inside the same commit; once the commit is accepted, the
reference is resolved to the anchored commit key, provider version ID when
available, and commit body digest. v2 does not write repository payloads to
backend `segments/`, nor does the current runtime read or write the older
checkpoint/manifest backend object stack.

The gateway uses commit batching knobs for v2. The default partial-batch wait
is 25 ms. Concurrent client PUTs can stage multiple encrypted payloads and
publish one signed v2 delta commit that covers all pending index updates; if
commit publication or anchor advancement fails, the unaccepted in-memory
namespace state is rolled back while the failed logical payload sequences
remain reserved.

v2 snapshot commits consolidate the live blinded namespace into an encrypted
`INDEX_SNAPSHOT` section. Readers walk the signed parent chain only until the
nearest snapshot, apply that full state, then replay newer delta commits. A
snapshot writer first flushes any pending client-write batch so the snapshot
chains from an accepted state. The explicit `rs3 write-index-snapshot` command
writes a snapshot only when repository state satisfies its safety preconditions;
otherwise it fails closed and reports the blocking condition.

v2 quick maintenance verifies the anchor-selected commit chain, reports
path-redacted orphan counts, and reports live commit versions whose provider
retention should be renewed soon. Full GC dry runs add request and byte budgets,
fully dead orphan bytes, retention/legal-hold blocked bytes, mixed accepted
commit bytes that compaction can reclaim, compaction write-byte estimates, and
retention-renewal request estimates. Conservative orphan GC can delete
unanchored commit candidates only after reachability, visible retention,
legal-hold, age, and same-sequence safety checks pass. Retained or legally held
candidates are reported and skipped; retained-profile candidates with missing
protection metadata are also skipped.

`rs3 export-restore-bundle` is format-aware: for `v2-preview` it verifies the
anchor-selected commit chain and exports the anchor state plus canonical
offline-signature payload bytes as the normal DR weak-subjectivity bundle. If
the external anchor is lost, `rs3 import-v2-anchor` recreates it from a trusted
bundle only after checking an operator-supplied `--min-sequence` floor,
verifying the offline Ed25519 signature when the selected provider profile is
production, refusing stored commit sequences newer than the imported anchor
unless `--force-rollback` is explicit, and verifying the named commit chain.
`rs3 verify-bundle` performs the same floor, signature, format-root,
keyring-envelope, and commit-chain verification as a no-write preflight.
`rs3 check-v2-provider` runs the selected v2 provider-profile probes against the
configured backend, including multipart upload behavior used by large streaming
writes; retained governance profiles require an explicit operator review flag
because gateway credentials must not be able to bypass retention.

## Payload Sections

Payload sections are encrypted with XChaCha20-Poly1305. Commit-embedded v2
payloads use a streamable segmented envelope: the payload header records the
segment size, key ID, and nonce prefix, while the signed index entry records the
total plaintext length and encrypted section length. Segment associated data
binds ciphertext to the payload identity, segment size, segment index,
segment-plaintext length, and final-segment marker.

Segment size is recorded per payload section. The current writer default keeps
small objects at 512 plaintext bytes per segment and uses larger segments for
medium and large objects. This is a tuning policy, not a permanent format
guarantee. Current writers also record the parsed payload-header facts and the
commit section-region offset inside the encrypted index payload reference.
Readers can therefore plan range reads from trusted index state and fetch only
the overlapping encrypted segments on the hot path. Older or incomplete refs
fall back to verifying the commit header and probing the payload header. Full
file reads fetch the payload section, not the whole commit body.

## Index State

Namespace index state maps blinded logical names and prefix tokens to encrypted
metadata needed for `HEAD`, `GET`, and `LIST`.

Metadata records are sealed with AES-256-GCM-SIV under the repository metadata
key. Associated data is object-type specific: manifest records bind to the
manifest ID, and index sections bind to the v2 commit key and section index.
Anchored signed commits decide which sealed metadata is reachable repository
state.

Namespace entries reference the accepted commit key, provider version ID when
available, commit body digest, payload identity, and payload section
offset/length. New v2 refs also carry the payload segment size, plaintext
length, payload key ID, nonce prefix, payload-header length, and section-region
offset needed for one-range restore reads. Retained/Object Lock repository
operation requires the provider version ID so restore can read the exact
retained commit version even if the backend later presents a different latest
version.

For retained-version providers, a same-key write may create another retained
version instead of failing as a duplicate. The format does not treat latest
object state as authoritative in that profile; anchored commit keys, provider
version IDs, and digests decide reachable state.

Index changes are append-friendly deltas covered by signed commits. Snapshot
commits compact live namespace state, but they must preserve rollback and
retention rules.

## Anchors

The external v2 anchor records the accepted commit sequence, commit key, commit
body digest, provider version ID when available, signing key ID, and format-root
reference. It is the latest-state authority. A backend listing, a newest-looking
commit key, or retained object history is never enough to advance repository
state without the anchor.

Anchors must fail closed. If the anchor cannot be read, cannot be advanced, or
does not match the verified commit chain, the gateway must not silently accept
newer-looking backend state. Disaster recovery uses a trusted v2 restore bundle,
an external operator `--min-sequence` floor, and an offline recovery signature
for production profiles, then verifies the named commit chain before recreating
the anchor.

## Keyrings

The repository uses purpose-specific keys for:

- namespace PRF
- content encryption
- metadata and index encryption
- Ed25519 commit signing

New writes use primary keys. Reads and replay accept enabled historical keys
until retention policy and repository reachability allow retirement. Data-key
rotation adds a fresh primary key for one purpose and demotes the previous
primary to enabled historical use.

The preferred bootstrap shape is to use an operator-provided repository ID and
public salt, generate random purpose-specific data keys, and store them in an
encrypted keyring envelope under a counted `keyrings/` object. The wrapping-key
source, such as a KMS key or high-entropy wrapping key, stays outside the
repository. The encrypted v2 format root binds the active envelope by
generation, object ID, provider version ID when available, and digest so a
backend cannot silently swap envelopes. The envelope is format-root-bound and
commit-referenced, not embedded in every commit.

Wrapping-key rewrap preserves the same repository data keys. It is useful for
moving the wrapping-key source or retiring a clean wrapping key, but it is not
recovery from exposure of an old wrapping key plus the old envelope bytes.

Repository-local orphan cleanup is reachability and retention aware. It derives
candidates from the accepted commit chain plus any operator-supplied protected
historical roots, skips objects with known retention or legal hold, and treats
provider retention or legal-hold delete failures as blocked cleanup rather than
as successful deletion. Historical roots are explicit inputs to maintenance:
without an explicit discard, their reachable commits remain protected from
orphan deletion.

Retention renewal is currently planned, not applied, by v2 full-maintenance dry
runs. The planner inspects current and protected-root commit versions and
includes needed retention-extension calls in the reported budgets. Compaction
apply writes a new snapshot commit through a temporary anchor, verifies it with
a fresh reader, then adopts that exact commit into the real anchor and leaves
old source commits for retention-aware orphan GC. Replacement-root rewriting
remains intentionally deferred.

Initial empty repositories are initialized by writing an encrypted keyring
envelope, an encrypted format root, and a genesis commit. Existing anchored
repositories open through the format-root and commit-chain references inside
the accepted anchor, not through S3 listing order or a mutable latest pointer.

In retained/Object Lock mode, keyring envelopes, format roots, and commit
objects must all return provider version IDs at write time. Missing version IDs
are treated as provider capability failures, because retained restore cannot
depend on mutable latest-object reads.

Commit-signing descriptors include the Ed25519 public verification key so commit
headers can be verified without exposing signing material.

See [Cryptography](cryptography.md) for primitive choices, nonce rules, and
known preview limits.

## Compatibility Promise

There is no stable repository-format promise yet. The production-preview target
is an evaluation contract, not a durable repository-format guarantee. Before a
stable format, the project still needs final decisions for:

- canonical metadata encoding
- default segment-size policy
- index compaction thresholds
- padding policy
- KMS/HSM/Vault wrapping-key integration workflow
