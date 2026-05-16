# Cryptography Reference

This page describes the current production-preview cryptographic shape. It is
an implementation reference, not an external audit, FIPS validation, or stable
repository-format promise.

## Boundary

All encryption, signing, hashing, key derivation, and secret-byte handling live
behind `rs3-crypto`. Higher-level crates provide canonical bytes and public
associated data; they should not add ad hoc cryptography.

Cryptography protects repository bytes and state transitions. It does not hide
backend object count, ciphertext size, request timing, broad object class
prefixes, or provider network metadata.

## Key Material

An empty repository initializes a random purpose-specific keyring:

| Purpose | Current primitive |
| --- | --- |
| Namespace lookup | HMAC-SHA-256 blind path and prefix tokens |
| Payload encryption | XChaCha20-Poly1305 content keys |
| Metadata encryption | AES-256-GCM-SIV metadata keys |
| Commit signing | Ed25519 signing keys |

The keyring is stored as an encrypted keyring envelope. The repository stores
only encrypted key material plus public key descriptors. The wrapping-key source
stays outside the object store.

The configured wrapping key is raw high-entropy key material. A human
passphrase must be converted outside `rs3` by a KMS, HSM, Vault, or password
KDF before it is provided as `RS3_KEYRING_WRAPPING_KEY_HEX`.

## Derivation

`rs3` uses domain-separated HMAC-SHA-256 for repository-local derivations:

- blind path lookup tokens
- prefix lookup tokens
- opaque backend object IDs
- AEAD subkeys
- deterministic metadata nonces
- Ed25519 signing seeds

New derivations must use a unique `rs3:` domain string. When a derivation input
combines more than one variable-length field, the caller must use canonical
length framing before deriving bytes.

The public repository salt is bound into the keyring envelope context. It is
restore metadata, not a password and not a second secret.

## Payloads

Payloads are split into independently encrypted segments. Each segment uses:

- XChaCha20-Poly1305
- a content key selected from the repository keyring
- a 24-byte nonce made from a random per-object prefix plus a segment counter
- associated data containing the payload object domain, backend object ID,
  segment size, plaintext length, segment index, and final-segment marker

The associated data is authenticated but not encrypted. It is limited to public,
path-free repository metadata.

Payload authentication fails if a backend tampers with ciphertext, changes the
segment context, or moves encrypted segment bytes under a different backend
object ID.

Segment size is recorded in each payload header and authenticated as segment
associated data. The default writer chooses the segment size per object: small
objects keep 512 B segments, medium objects use 8 KiB, and larger objects use
64 KiB. This changes overhead and read granularity without changing the
repository format because readers trust the authenticated header, not a global
setting.

The gateway may cache decrypted payload segments in memory. The default limit is
256 MiB and can be disabled with
`RS3_DECRYPTED_SEGMENT_CACHE_MAX_BYTES=0`. The cache key uses the backend object
ID, provider version ID when present, and segment index; it does not use
client-visible paths. The cache is process-local acceleration only: commit
verification, AEAD authentication, and exact-version restore rules are
unchanged.

## Metadata

Manifest and index metadata are sealed with AES-256-GCM-SIV. The metadata nonce
is deterministic: it is derived from the metadata key, associated data, and
plaintext. This makes retrying the same metadata write stable.

Deterministic sealing intentionally leaks equality for the same metadata key,
associated data, and plaintext. The design accepts that leakage for the preview
because the plaintext metadata is path-sensitive and encrypted, while the
remaining equality signal is narrower than exposing paths or Kubernetes names.

Metadata associated data is object-type specific:

- manifest records bind to the manifest ID
- index deltas bind to the index-delta object domain

Signed commits and object IDs decide which sealed metadata is reachable
repository state.

## Keyring Envelopes

Keyring envelopes use AES-256-GCM-SIV with a random 96-bit nonce. Envelope
associated data binds:

- envelope format version
- envelope generation
- repository ID
- public repository salt
- wrapping-key ID
- envelope nonce

The encrypted v2 format root and signed commits bind the active envelope by
generation, object ID, and digest. The backend cannot silently swap a different
envelope into accepted repository state without breaking that binding.

Rewrapping an envelope changes only the wrapping-key source around the same
repository data keys. It is operational hygiene, not compromise recovery.

Data-key rotation changes one purpose-specific repository key at a time. The old
primary remains enabled for historical reads or commit verification until
retention-aware retirement proves it is no longer required. A rotated keyring is
stored in a new envelope and becomes active only when accepted v2 repository
state binds that envelope.

## V2 Commits

V2 commits sign canonical repository-state transitions with Ed25519. The signed
header includes the sequence, parent commit reference, section table, active
keyring-envelope reference, publish time, active format-root reference, and
signature metadata.

Commit body digests are domain-separated SHA-256 digests over the serialized
commit body. Commit keys are random and path-private. The Kubernetes Lease
anchor stores the accepted commit position: sequence, commit key, body digest,
signing key ID, format-root reference, and provider version ID when required.
Retained commit versions are useful history, not the latest-state authority.

## Review Rules

Before adding or changing crypto-sensitive code:

- keep the primitive inside `rs3-crypto`
- use AEAD instead of separate encryption and MAC glue
- make nonce uniqueness or deterministic misuse-resistance explicit
- authenticate public context with associated data
- keep plaintext paths and Kubernetes names out of object keys, AAD, logs,
  metrics, traces, tags, and unauthenticated metadata
- keep secrets out of `Debug`, errors, and reports unless intentionally printed
  as generated key material
- document new leakage in the security model

## Preview Limits

The current design has not had an external cryptographic review. Before a stable
format v1, the project still needs final review of:

- deterministic metadata sealing and accepted equality leakage
- prefix-token structure and namespace-shape leakage
- padding and pack-size policy
- KMS/HSM/Vault wrapping-key workflow
- key-retirement policy for retained historical data
- durable format compatibility guarantees

## References

- [RFC 5116: Authenticated Encryption With Associated Data](https://www.rfc-editor.org/rfc/rfc5116)
- [RFC 8439: ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [RFC 8452: AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452.html)
- [libsodium: XChaCha20-Poly1305 construction](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
- [NIST SP 800-108 Rev. 1: Key Derivation Using Pseudorandom Functions](https://csrc.nist.gov/pubs/sp/800/108/r1/final)
- [NIST SP 800-57 Part 1 Rev. 5: Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [RFC 8032: EdDSA and Ed25519](https://www.rfc-editor.org/rfc/rfc8032.html)
