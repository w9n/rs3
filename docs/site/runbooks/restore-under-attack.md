# Restore Under Attack

Do not repair state automatically during an incident. First choose the trusted
checkpoint, then restore with the narrowest credentials practical.

## Assume

- object storage can delay, delete, replay, or hide objects
- the Kubernetes anchor can be stale or maliciously advanced
- a backup pod may have written bad new state
- old retained versions may exist even when latest listings mislead
- in-cluster logs may be incomplete

## Immediate Actions

1. Stop new gateway writes.
2. Preserve logs, metrics, checkpoint IDs, and anchor state.
3. Read the external anchor.
4. Read storage evidence if configured.
5. Select the highest checkpoint whose signature, parent chain, and
   anchor/evidence relation verify.
6. Restore with read-only credentials into an isolated target.

## Decision Table

| Observation | Action |
| --- | --- |
| Signature fails | Reject checkpoint. |
| Parent chain broken | Reject unless it is a trusted compaction root. |
| Sequence lower than trusted anchor | Treat as rollback. |
| Digest differs from anchor | Fail closed and investigate. |
| Anchor unavailable | Do not accept newer-looking storage state silently. |
| Evidence higher than anchor | Investigate anchor rollback or missed anchor advance. |
| Evidence lower than anchor | Investigate failed evidence write or backend replay. |

## Break Glass

Break-glass restore, if implemented, must require:

- explicit operator command
- selected checkpoint ID and sequence
- audit reason or ticket
- read-only backend credentials where possible
- no automatic anchor repair

Its job is data recovery, not making ambiguous state look healthy.

## Preserve

- selected checkpoint ID, sequence, and digest
- parent chain or compaction root
- anchor and evidence state
- gateway version and configuration hash
- restore command and target
- object-store audit events

Do not include plaintext paths or Kubernetes secrets in shared artifacts.
