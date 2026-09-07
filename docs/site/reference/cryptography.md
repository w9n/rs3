# Cryptography Reference

This reference describes the cryptography used by the current `v3-preview`
gateway for implementers and security reviewers. It is not an external audit,
FIPS validation, or stable repository-format promise. Exact encodings and
bounds are in the [repository format reference](repository-format.md).

## Boundary and Keys

All encryption, signing, hashing, derivation, randomness and secret-byte handling
live behind `rs3-crypto`. Higher-level crates supply canonical bytes and public
associated data. Cryptography does not hide backend object count, ciphertext
size, timing, broad object classes or provider network metadata.

Initialization generates separate random keys for four purposes:

| Purpose | Primitive and use |
| --- | --- |
| Namespace | HMAC-SHA-256 blinded lookup keys inside encrypted index runs |
| Content | XChaCha20-Poly1305 payload segments |
| Metadata | AES-256-GCM-SIV index frames and roots |
| Signing | Ed25519 commit signatures |

Prefix listing uses ordered logical paths inside encrypted index frames; v03
does not persist prefix-token objects. Backend object keys contain random
identifiers, not content hashes or path derivations.

The keyring is encrypted under an external high-entropy wrapping key. Kubernetes
Secret custody is the initial deployment model; the wrapping-key source stays
outside the object store. A human passphrase is not a suitable raw wrapping key.
The public repository salt is required restore context, not another secret.
Domain-separated HMAC derivations use explicit framing for variable-length
inputs. New derivations require distinct domains inside `rs3-crypto`.

## Payload Authentication

Payload carriers contain ciphertext and 16-byte tags only. Their layout is
stored in the encrypted, authenticated index. There is no plaintext payload
header or stored nonce per segment.

Each carrier has a random 256-bit identity. Each sealing attempt has a fresh
256-bit identity. A keyed HMAC derives each 24-byte XChaCha20-Poly1305 nonce
from the authenticated context, attempt, part or record number, and segment
number. [Shared segment authentication](repository-format.md#shared-segment-authentication)
specifies the exact nonce and associated-data construction.

Associated data binds the repository and historical keyring, containing object
key, content-key ID, optional section ordinal, carrier and attempt identities,
part or record ordinal, segment ordinal, plaintext length, final-segment marker
and carrier layout. Moving ciphertext to another context fails authentication.
Provider versions are assigned after upload; accepted exact references bind
them through signed, encrypted repository metadata.

A pack record of at most 64 KiB uses one segment. Larger packed records use
64 KiB segments. Detached carriers record their segment size and ordered part
attempts in the authenticated descriptor. Empty values are index-only.
Replacement parts or changed packs require fresh attempts. Retransmitting
already prepared ciphertext preserves its attempt; matching bytes alone do not
identify a successful client operation.

Detached upload publication requires complete exact-version readback, length,
EOF and ciphertext-digest verification under a 1 MiB chunk ceiling. Payload
storage alone does not publish namespace state. Reads authenticate bounded
segments before releasing plaintext; full detached reads withhold the final
group until aggregate digest and exact EOF checks pass.

The optional process-local plaintext segment cache binds repository, historical
keyring, exact carrier/version, attempt, part, segment and authenticated layout
facts. It does not replace signature, AEAD or exact-version validation. Disable
it with `RS3_DECRYPTED_SEGMENT_CACHE_MAX_BYTES=0`.

## Metadata Authentication

Index metadata uses AES-256-GCM-SIV with a fresh random 96-bit nonce from the
operating system for each seal. The nonce and 16-byte tag travel with ciphertext.
Randomness failure aborts sealing. Exact publication retries reuse prepared
ciphertext; resealing is a new encryption.

Index-frame associated data binds repository and historical keyring context,
containing object key, section ordinal, run identity, framing header and frame
descriptor. Index roots bind their repository context, containing object,
section ordinal and root header. Signed section digests authenticate the exact
stored index bytes selected for recovery.

Front coding compresses listing paths inside encrypted frames. Ciphertext sizes
can reveal aggregate path lengths and shared-prefix structure. Full paths stay
inside trusted gateway memory. Aggregate key-use and rotation limits still
require production qualification and external review.

## Keyring and Format Envelopes

Both envelopes use canonical version-3 CBOR and AES-256-GCM-SIV with a random
96-bit nonce. Their associated data is the canonical map of version, purpose,
generation, repository ID, public salt, wrapping-key ID and nonce. Each purpose
derives a separate AEAD key from the wrapping key. Envelope SHA-256 digests
cover the complete canonical bytes. Keyring plaintext and secret serialization
use zeroizing buffers.

The format root binds the full keyring-envelope reference, including generation,
object ID, digest and provider version. Signed commits bind the historical
keyring object and digest. The external anchor binds the exact format root.
These bindings prevent a backend from substituting another envelope into
accepted state.

Rewrap changes wrapping protection around unchanged repository data keys; it
cannot restore confidentiality after those data keys are compromised. The
gateway has no in-place format or data-key rotation operation. Historical
reads can use enabled keys. Retirement requires proof that no protected restore
root needs the key.

## Signed Commits and Recovery Bundles

V03 commits use Ed25519 over the complete 40-byte prelude and canonical CBOR
header with the signature field zeroed. The header binds sequence, self key,
exact parent, publish time, kind, algorithm identifiers, historical keyring,
section layout/digests and body digest. The body digest is SHA-256 over the exact
concatenated section bytes. There is no separate header digest. The anchor and
index root carry the format-root reference.

The external Kubernetes Lease selects the accepted exact commit and format
references. Sequence and parent checks establish chain order; backend listing
order and timestamps do not. Strict parent-relative publication timestamps are
not yet enforced by the writer or replay. They must not be treated as a proven
retention-history clock.

Version-3 recovery bundles use canonical CBOR. Optional offline Ed25519
signatures bind repository identity, salt digest, accepted anchor, recovery
floor and export time under a separate signature domain. Signed bundle import
is an explicit disaster-recovery path; an offline signer is not a dependency of
normal initialization or serving.

## Review Requirements

Changes must preserve path-free associated data and diagnostics, bounded parsing,
AEAD authentication before plaintext release, and fail-closed anchor handling.
Fixed public keys and nonces in golden fixtures are test inputs only. See
[Testing](../testing.md#v03-codec-fixtures) for executable coverage
and its limitations.

Production qualification still requires external cryptographic review, nonce
and aggregate key-use analysis, retained-key retirement policy, current-provider
recovery evidence and the remaining history implementation. See the
[security model](../security-model.md) and
[production-preview gates](../production-preview.md).

## References

- [RFC 5116: Authenticated Encryption With Associated Data](https://www.rfc-editor.org/rfc/rfc5116)
- [RFC 8439: ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [RFC 8452: AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452.html)
- [libsodium: XChaCha20-Poly1305 construction](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
- [NIST SP 800-108 Rev. 1: Key Derivation Using Pseudorandom Functions](https://csrc.nist.gov/pubs/sp/800/108/r1/final)
- [NIST SP 800-57 Part 1 Rev. 5: Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [RFC 8032: EdDSA and Ed25519](https://www.rfc-editor.org/rfc/rfc8032.html)
