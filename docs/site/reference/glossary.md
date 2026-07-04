# Glossary

## Anchor

External rollback boundary for the repository. In `v2-preview`, the anchor
records the accepted commit sequence, commit key, digest, signing key, format
root, and provider version ID when available. A gateway must fail closed if it
cannot read or advance the anchor.

## Backend

The object store where `rs3` writes repository objects. The backend can observe
object class prefixes, object counts, sizes, timing, tenant configuration, and
configured backend bucket or prefix names. It must not learn plaintext client
paths from backend object keys or unauthenticated metadata.

## Blinded Identifier

Opaque identifier derived from repository key material and a logical path. The
namespace index uses blinded identifiers instead of plaintext path components.

## Checkpoint

Older repository state summary used by the removed v1 stack and retained where
compatibility text still needs to distinguish v1 from v2. Current `v2-preview`
state is selected by signed commits and an external anchor, not by the older
checkpoint object stack.

## Commit

Signed repository update. In `v2-preview`, a commit contains encrypted payload
sections plus an encrypted index delta or snapshot. The accepted commit chain is
selected by the anchor and verified before state is trusted.

## Commit Chain

Parent-linked sequence of signed commits from the accepted head back to a
genesis commit or index snapshot boundary. Recovery and maintenance verify the
chain instead of trusting the newest object seen in storage.

## Format Root

Encrypted repository-format metadata for `v2-preview`. It binds the repository
format, repository context, provider profile, and active keyring envelope
reference so a backend cannot silently swap critical repository metadata.

## Keyring

Repository data keys grouped by purpose: namespace derivation, content
encryption, metadata or index encryption, and commit signing. New writes use
primary keys; reads may accept enabled historical keys until retention and
reachability allow retirement.

## Keyring Envelope

Encrypted object that stores the repository keyring under an operator-managed
wrapping key. The envelope lives under `keyrings/` and is referenced by the
format root and commits. The wrapping key itself stays outside the repository.

## Legal Hold

Object-store protection that blocks deletion while enabled. `rs3` treats legal
hold as restore-critical protection when the selected provider profile supports
it.

## Logical Path

Client-visible object key or prefix, such as an S3 key supplied by Kopia or
Velero. Logical paths are privacy-sensitive and must not appear in backend
keys, unauthenticated metadata, logs, metrics labels, or errors.

## Path Privacy

Product invariant that plaintext paths, directory names, Kubernetes object
names, namespaces, and snapshot names are not exposed through backend keys,
unauthenticated metadata, logs, metrics labels, or errors.

## Prefix Token

Opaque namespace lookup token for a logical prefix. Prefix tokens let the
gateway list client prefixes without storing plaintext directory components in
backend-visible state.

## Provider Profile

Declared set of object-store semantics used by a repository. Examples include
the default development profile and retained-version profiles that require
version IDs, exact-version reads, and visible retention or legal-hold state.

## Public Bucket

S3 bucket name exposed by the gateway to backup clients. It is separate from
the backend bucket where repository objects are stored.

## Repository

All backend objects, key material references, signed commits, and anchor state
for one `rs3` backup gateway namespace. A repository is operated as one
rollback domain.

## Restore Bundle

Operator-reviewed recovery artifact exported by `rs3 export-restore-bundle`.
For `v2-preview`, it carries the anchor state and offline-signature payload
needed to recreate a lost external anchor after chain verification.

## Retention

Object-store protection that prevents deletes until a retain-until time. `rs3`
may extend retention for restore-critical objects but must not shorten it.

## Rollback Resistance

Property that a backend cannot make the gateway silently accept older or
newer-looking repository state by listing, deleting, delaying, or replaying
objects. Anchors, signed commits, provider versions, and operator recovery
floors enforce this.

## Weak-Subjectivity Floor

Operator-supplied minimum accepted sequence for disaster recovery. Importing an
anchor below the floor is rejected, even if the backend contains an otherwise
valid commit chain.

## v2-preview

Current evaluation repository format. It uses random commit keys, signed commit
headers, encrypted payload and index sections, an encrypted format root, an
encrypted keyring envelope, and an external anchor.
