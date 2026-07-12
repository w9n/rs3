# Deduplication Design Note

Deduplication is not part of the baseline `v02` repository format. This note
records the researched extension boundary so storage savings do not quietly
weaken path privacy, confidentiality, retention, or restore correctness.

!!! warning "Research status"
    Finish mixed-pack cleaning, the operator maintenance controller, and the
    stable retained-provider scale gates first. The
    modes below are not implemented or configurable. Enabling one will require
    a new format capability, security review, and workload evidence.

## Decision

The default mode remains `private`: randomized authenticated encryption and
compact packing, with no persistent content-equality index. Small-file
efficiency comes from removing repeated representation overhead, not from
making ciphertext deterministic.

If non-Kopia workloads later justify deduplication, implement the extensions in
this order:

1. `repository-exact`: exact whole-object reuse inside one repository;
2. `repository-cdc`: content-defined chunk reuse inside one repository, only
   after real traces prove incremental value over exact reuse; and
3. no cross-repository, cross-tenant, or public message-locked mode.

The policy is bound into the signed format root. Moving from `private` to a
deduplicating mode is an explicit security transition. Moving back stops new
equality creation but cannot erase equality and sharing already visible in
retained history.

## First-Principles Boundary

Useful deduplication requires some component to decide that two plaintexts are
equal. If the untrusted storage provider makes that decision, it needs a stable
public or provider-visible equality signal. If the trusted gateway makes the
decision before randomized encryption, public content hashes and deterministic
ciphertext are unnecessary, but physical sharing still leaks through omitted
writes, aggregate sizes, timing, shared retention, and repeated reads of the
same pack ranges.

`rs3` already has the correct trusted boundary: the gateway receives the full
S3 request body and holds repository secrets. It can deduplicate plaintext,
then encrypt each unique physical value with normal randomized AEAD. This is
deduplication-before-encryption; it does not require convergent encryption,
message-derived encryption keys, an enclave, or a provider-side equality API.

That does not make equality free. A chosen-plaintext writer may distinguish a
hit through response timing or later storage accounting, and the backend may
correlate suppressed payload bytes or shared range reads. The `private` mode is
therefore the only mode that makes no cross-object equality concession.

## Why Exact Objects Come First

Whole-object reuse has a much smaller correctness surface than chunk reuse:

- one logical object still resolves to one authenticated payload record;
- existing full and range reads need no recipe layer;
- the namespace remains the exact reachability authority;
- a duplicate-only commit adds an index mutation without writing payload bytes;
- pack cleaning and retention rules do not gain chunk graphs; and
- already compressed, encrypted, or client-packed inputs pay only a bounded
  failed-lookup cost.

A large desktop and backup study found that whole-file dedup captured about 75%
of the block-dedup savings in its live-filesystem corpus and 87% in its backup
images. That is not a claim about Kubernetes or database backups, but it is a
strong reason to measure exact reuse before building CDC.

Kopia, restic, and similar clients already chunk and pack content. Running CDC
again over their compressed or encrypted repository blobs adds CPU and metadata
while normally finding no plaintext similarity. Those clients stay in
`private` mode.

## Repository-Exact Protocol

An exact-dedup generation uses a dedicated repository-scoped secret PRF key.
The content tag is a domain-separated 256-bit PRF over the plaintext length and
complete plaintext. It is not a raw hash, backend object name, encryption key,
S3 tag, metric label, log field, or client-visible identifier. Namespace,
content-tag, index-encryption, and payload-encryption keys remain separate.

The write path is:

1. Ingest the complete client body into bounded trusted memory or encrypted
   scratch while computing the content tag. Do not tell the client whether a
   candidate exists.
2. Check the pending batch, then the accepted repository content projection.
3. Treat a match only as a candidate. Verify its accepted exact container and
   record reference, current live reachability, and protection state. Range-read,
   authenticate, decrypt, length-check, and byte-compare the candidate before
   omitting the new bytes. Equality metadata never grants read authorization.
4. Check the physical object's protection cohort. Reuse only when retention and
   legal hold are at least as strong as the new logical reference. Otherwise
   extend protection on the exact version when policy permits, or write a new
   copy in the stronger cohort.
5. For a verified hit, publish the new namespace record pointing to the existing
   immutable payload. For a miss, add the value to the new payload pack.
6. Publish the signed commit and advance the anchor under the normal live writer
   fence before acknowledging the client.

Batch-local equality can share the first staged record without a catalog read.
An implementation may store a harmless duplicate when a performance cache
misses; perfect space reduction is not a commit-correctness invariant. It must
never coalesce unequal plaintext, weaken protection, or acknowledge an
unanchored reference.

Key rotation is epoch-scoped and bounded. New writes use the primary content-
tag key. Readers keep only the explicitly enabled historical epochs needed by
reachable state. Compaction may re-tag encrypted index metadata without
rewriting payloads, but rotation cannot retract equality learned during an old
epoch.

## Content Projection

A deduplicating capability adds an encrypted content projection to `INDEX_RUN`.
It maps one repository-secret tag and plaintext length to a bounded list of
exact payload candidates by protection cohort. Namespace records continue to
hold compact physical pointers; they do not repeat 32-byte content tags.

The projection is a lookup accelerator, not liveness authority. Content
identity and physical liveness are different domains: one content tag may have
several exact physical copies after races, failed publication, protection-
cohort splits, key rotation, or repacking. Historical signed roots bind those
exact copies, not an abstract latest or canonical location. A candidate is
eligible only when the accepted current namespace's reverse payload map still
contains it. Catalog checkpoints rebuild the projection from accepted current
state and discard dead candidates. Protected historical roots still keep their
payloads reachable, but the writer need not search history merely to obtain a
dedup hit.

Authenticated Bloom filters may reject absent tags without reading every run.
A Bloom positive never authorizes reuse, and a local cache never establishes
repository truth. False positives cost reads; false negatives or incomplete
near-match indexes may cost storage; neither may change restored bytes. The
signed catalog and encrypted runs rebuild all performance state after failover.

## Optional Content-Defined Chunking

CDC is justified only for large plaintext-like inputs whose shifted or edited
versions retain substantial common content. It turns one logical S3 object into
an encrypted ordered recipe of chunk references. Fixed blocks should remain a
benchmark competitor for naturally aligned disk or database images; automatic
content sniffing is not a security or operations contract.

If real non-Kopia traces justify CDC:

- use a bounded FastCDC-style algorithm with a repository-secret-derived Gear
  table so boundary and tag domains do not cross repositories;
- keep min, target, and max chunk sizes explicit and immutable per recipe;
- start experiments around a 1 MiB target, not the 8 KiB values chosen for old
  local-disk systems, then select parameters from net provider cost and restore
  evidence;
- accumulate unique chunks in ingest order into immutable 16-32 MiB encrypted
  chunk packs under random backend keys, never one S3 object per chunk;
- retain segmented AEAD inside chunks for bounded range reads;
- batch fingerprint lookups into selected encrypted index frames and use local
  manifest or pack caches to avoid one S3 request per chunk; and
- evaluate compression as a separate opt-in transform with its own length-
  leakage, decompression-limit, and range-read analysis.

CDC solves the boundary-shift problem demonstrated by LBFS. FastCDC reduces the
CPU cost of Rabin-style rolling chunking. DDFS and Sparse Indexing show that
immutable containers, negative filters, stream locality, and batched manifest
selection are what make chunk lookup practical at scale. None of their measured
8 KiB-era parameters transfer directly to an S3 request-cost model.

Sparse or champion-based lookup is allowed only as a later explicitly near-
exact performance mode: it may miss a duplicate and store it again, but it may
never return a false match. Start with an exact durable content catalog and use
filters only as authenticated accelerators.

## Reachability, Retention, and Cleaning

Shared payload liveness is derived from signed roots, not mutable reference
counts. The collector freezes the anchor and authenticated protected-root
registry generation under the maintenance fence. Its exact mark resolves
highest-generation namespace records and CDC recipes from every root, then
marks exact object key, provider version, pack, and record locations. A bounded
implementation may external-sort records and coalesce per-pack-version bitmaps.
Only a completed unambiguous mark may authorize deletion.

Retention and legal hold apply to a physical pack, not an individual record.
Writers pack only compatible protection cohorts. Reusing a weakly protected
record for a stronger logical reference requires verified protection extension
or a new physical copy. Reusing a stronger record is safe but may increase
over-retention, which the cost report must surface.

Content-index compaction never copies values. Pack cleaning remains a separate
operation: copy authenticated live records from a sufficiently sparse pack into
a new random pack, publish higher-generation physical references, and retain
the old exact version while any protected root reaches it. A content tag does
not make a public content-addressed object immortal.

## Concurrency

The current single fenced publisher makes exact dedup tractable. The pending
overlay reserves content tags within a batch, and publication validates the
same writer epoch and anchor position used by ordinary commits. Racing client
PUTs either share the staged value or store harmless duplicates.

A writer must not reuse a candidate from a pack selected by a frozen cleaning
generation; it stores a duplicate instead. The collector rechecks the fence,
anchor, and protected-root generation before every exact-version deletion. This
conservative rule avoids undelete markers, distributed counts, and resurrection
races.

Disconnected writers cannot use a public content key plus conditional S3 PUT as
a substitute for repository coordination. They may independently write the
same content, but deciding which branch, namespace mutation, retention policy,
and physical candidate becomes authoritative still requires authenticated
branch and merge semantics. Dedup does not solve multi-writer ordering.

## Security Modes

| Mode | Equality scope | Security posture |
| --- | --- | --- |
| `private` | None across logical objects | Default. Random AEAD and opaque pack keys; packing only. |
| `repository-exact` | Exact objects in one repository | Explicit opt-in. Secret tags and shared physical refs leak repository-local equality and frequency. |
| `repository-cdc` | Chunks in one repository | Experimental. Adds recipes, greater equality leakage, restore scatter, and shared chunk liveness. |
| Future tenant scope | One independently keyed tenant | Only if a future multi-tenant product has a real tenant authority model. Never share physical refs across principals by accident. |
| Public/global MLE | Global | Forbidden. Guessable backup content admits offline confirmation and equality leakage. |

Message-locked or convergent encryption addresses a different architecture in
which clients want an untrusted provider to deduplicate ciphertext. Its privacy
requires sufficiently unpredictable messages. Kubernetes manifests, Secrets,
configuration fragments, common binaries, database pages, and known backup
formats are frequently guessable or drawn from small sets.

DupLESS reduces cheap offline guessing by using an online, rate-limited
oblivious-PRF key service. It still preserves equality, adds a separate trust and
availability dependency, and is not a disconnected-S3 technique. Proof of
ownership may stop a hash-holder from acquiring shared data, but it does not
remove presence testing. `rs3` will not add either mechanism unless it becomes a
different fleet service with an explicit cross-principal threat model.

## Economics and Qualification

Dedup is useful only when gross duplicate bytes avoided exceed all content-
catalog, recipe, verification-read, pack-fragmentation, cleaning-copy,
over-retention, CPU, and latency costs. For content size `S`, duplicate
probability `p`, and added per-content metadata `m`, even the storage-only
necessary condition is approximately `p * S > m`. Small unique values can lose
before any S3 request cost is counted.

Every proposed mode must compare against `private` using:

- exact-duplicate corpora at 0%, 50%, and 90% duplicate bytes;
- large objects with prefix, middle, and suffix insertions;
- unique incompressible, whole-stream compressed, and client-encrypted inputs;
- tiny values below the lookup bypass threshold;
- repeated real backup generations and real non-Kopia traces;
- mixed retention deadlines and legal holds;
- deletes, protected historical roots, interrupted repacks, key rotation, stale
  fencing, restart, and rollback attempts; and
- cold and warm full reads plus small and large ranges after fresh-process
  recovery.

Report logical bytes, unique bytes, content and chunk hit rates, index and recipe
bytes, pack utilization, CPU throughput, client latency distributions, backend
PUT/GET/range counts, read and write amplification, GC copy amplification,
over-retained bytes, and cache dependence. A dedup hit and miss must return the
same S3 semantics and no hit indicator. Timing leakage must be measured rather
than hand-waved away.

## Research Basis

- [A Low-bandwidth Network File System](https://pdos.csail.mit.edu/papers/lbfs%3Asosp01/lbfs.pdf)
  established shift-resistant content-defined chunking and its round-trip
  tradeoffs.
- [FastCDC](https://www.usenix.org/system/files/conference/atc16/atc16-paper-xia.pdf)
  demonstrated faster bounded normalized CDC relative to the algorithms it
  evaluated.
- [Avoiding the Disk Bottleneck in DDFS](https://www.usenix.org/conference/fast-08/avoiding-disk-bottleneck-data-domain-deduplication-file-system)
  combined immutable containers, a negative summary, and locality-preserving
  fingerprint caching.
- [Sparse Indexing](https://www.usenix.org/legacy/event/fast09/tech/full_papers/lillibridge/lillibridge_html/index.html)
  traded occasional missed duplicates for bounded lookup memory and I/O by
  selecting similar historical manifests.
- [DDFS physical garbage collection](https://www.usenix.org/conference/fast17/technical-sessions/presentation/douglis)
  used consistent-root mark-and-sweep and conservative live filtering instead
  of mutable reference counts.
- [A Study of Practical Deduplication](https://www.usenix.org/conference/fast11/study-practical-deduplication)
  measured the relationship between whole-file and block-level savings on a
  large desktop corpus and backup images.
- [Venti](https://www.usenix.org/conference/fast-02/venti-new-approach-archival-data-storage)
  demonstrated immutable content sharing; `rs3` deliberately does not expose
  content hashes as backend object names.
- [Message-Locked Encryption and Secure Deduplication](https://eprint.iacr.org/2012/631.pdf)
  formalized the unpredictability requirement for message-derived encryption.
- [DupLESS](https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_bellare.pdf)
  added a rate-limited oblivious-PRF service to resist cheap offline guessing.
- [Side Channels in Cloud Services](https://www.pinkas.net/PAPERS/hps.pdf)
  analyzed presence testing and covert channels created by cross-user dedup.
- [DUPEFS](https://www.usenix.org/conference/fast22/presentation/bacs)
  demonstrated practical remote timing leakage from filesystem deduplication.
- [WiscKey](https://www.usenix.org/conference/fast16/technical-sessions/presentation/lu)
  and [Integrated BlobDB](https://rocksdb.org/blog/2021/05/26/integrated-blob-db.html)
  support separating value cleaning from metadata compaction.
