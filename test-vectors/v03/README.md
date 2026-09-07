# v03 protocol vectors

These fixed public fixtures pin the preview codecs. They are not an independent
cryptographic review or a complete repository qualification. The workspace
unit tests and `rs3-repository/tests/v03_vectors.rs` verify them. `just fuzz-smoke`
loads each target's directory alongside its small raw/malformed seed corpus.

All secrets and nonces in these fixtures are public test values. Production
metadata sealing still generates random nonces; no deterministic sealing option
was added. Fixture encoders are tested against checked-in bytes, and fixture
readers authenticate/decode those bytes independently of new sealing calls.

| Fixture | Construction and executable check |
| --- | --- |
| `v03_commit/commit-{root,delta,pack}.bin` | All three signed envelope shapes at sequence 42, fixed signing secret `03` repeated 32 times, key ID `signing`. `frozen_commit_shapes_verify_and_reject_every_truncation` pins complete prelude, CBOR, signature and section bytes. Sections contain synthetic opaque bytes; actual index decoding is tested separately. |
| `v03_index_run/{external-pack,standalone,completion}.bin` | Wire 8 container tables, namespace/listing projections and front-coded paths. `frozen_container_tables_preserve_canonical_wire_bytes` checks exact encoding, decoding and all truncations. The inline run vector remains an additional readable hex assertion. |
| `v03_index_root/{root,completion}.bin` | Canonical root plaintext, wire generation 4, including a bounded completion-receipt snapshot. `frozen_root_plaintext_preserves_canonical_bytes` and `canonical_logical_encoding_is_stable` pin bytes and SHA-256. Encrypted frame/context tests exercise sealing separately. |
| `v03_payload_pack/segment.bin`, `v03_standalone_single/segment.bin` | Ciphertext for `hello`, content secret `02` repeated 32 times, fixed carrier/attempt/segment facts in `rs3-crypto/src/payload.rs::segment_context`. The fixtures differ only in embedded section `Some(0)` versus detached `None`. `frozen_pack_and_standalone_segments_pin_domain_separation` pins encryption, authentication and truncation rejection. |
| `repository_envelope/{keyring,format}.cbor` | Repo `repo-a`, salt `02` repeated 32 times, wrapping key `09` repeated 32 times, wrapping ID `wrap-v1`, generation 1, nonce `03` repeated 12 times. The keyring has one namespace key with public fixture secret `04` repeated 32 times. Format-envelope plaintext is the opaque string `format plaintext`, testing the envelope independently of the format-root codec. `frozen_canonical_envelopes_authenticate_and_reject_every_truncation` pins bytes, purpose-separated authentication, wrong salt/key-ID refusal and all truncations. |
| `v03_format_root/retained.cbor` | Independently specified CBOR array for repo `r`, envelope reference `(1, 11 repeated 32 bytes, k, null)`, signing ID `s`, retained provider and 30-day compliance retention. `frozen_retained_format_root_has_exact_canonical_bytes` checks its semantic values and canonical re-encoding. |
| `recovery_bundle/unsigned.cbor` | Independently specified CBOR array with explicit anchor format generation 3. `canonical_bundle_has_pinned_bytes_and_rejects_malformed_encodings` pins it; the signature-domain test covers every unsigned field and rejects field tampering. |

## Rejection coverage

Tests named below are ordinary workspace tests unless specified otherwise.

| Required rejection | Executable coverage |
| --- | --- |
| Commit reserved bytes/capabilities, retired versions | `v03_fixed_fields_and_capabilities_are_closed`, `vector_invalid_cases_have_expected_classes` |
| Retired sections, overlapping/gapped or duplicate section roles | `retired_section_codes_fail_closed_even_without_required_flag`, `framed_section_semantics_reject_noncanonical_shapes`, `section_layout_rejects_reserved_flags_and_unauthenticated_gaps` |
| Noncanonical CBOR and signatures | Shared `rs3-types::cbor` canonical parser tests, commit invalid vectors, `signature_tampering_is_rejected` |
| Trailing or truncated commit bytes | `frozen_commit_shapes_verify_and_reject_every_truncation` |
| Index overlong varints and invalid path prefixes | `rejects_noncanonical_varint`, `listing_path_decoder_rejects_noncanonical_and_oversized_prefixes` |
| Projection mismatch, unused/duplicate container or key table | `rejects_projection_fact_mismatch_and_duplicate_ordinal`, `rejects_noncanonical_and_unused_containers`, `rejects_malformed_namespace_key_tables_and_ordinals` |
| Frame ordinal duplication/reordering/transplants | `rejects_missing_repeated_or_reordered_frames_across_all_roles`, `rejects_directory_context_object_section_and_header_transplants`, `rejects_directory_frame_and_selected_range_tampering` |
| Root level, run count, generation/context | `rejects_invalid_level_and_compaction_generation_pairs`, `rejects_duplicate_runs_invalid_bounds_and_limits`, `rejects_legacy_root_wire_version`, `v2_full_gc_rejects_cross_format_protected_root_before_storage_reads` |
| Payload repository/object/section/record/segment/length/final-flag changes | `shared_segment_authenticates_every_identity_and_layout_field`, `segment_reorder_and_cross_record_transplant_fail_closed` |
| Noncanonical segmentation and physical layout | `invalid_ranges_record_counts_and_sizes_are_rejected`, `complete_layout_rejects_gaps_overlaps_and_bad_logical_ordinals` |
| Envelope field order, duplicates, unknown fields and truncation | `reject_noncanonical_unknown_duplicate_truncated_and_trailing_fields`, frozen envelope tests |
| Bundle fields, signature, salt and exact bounds | Canonical/signature tests in `rs3-repository/src/v2/recovery_bundle.rs` |
| Full detached-object readback before publication | `standalone_publication_requires_complete_bounded_exact_version_readback` and the S3 SDK response-version contract test |

A bare commit codec has no trusted parent timestamp. Strictly increasing
publication times along accepted ancestry still require writer clock handling
and replay validation; that requirement is not established by these fixtures.
Existing compaction fault, staging rollback and compaction-scale lanes remain
separate runtime tests. Uploading a successor commit before accepting its parent
is not implemented and is not a claimed failure-test scenario.
