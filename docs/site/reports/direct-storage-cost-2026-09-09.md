# Gateway and direct S3 cost evidence: September 9, 2026

This dated report preserves the complete measured method, lane-level values, revision binding, artifact link and limits. It is local RustFS evidence, not external-provider pricing or capacity qualification.

For the operator summary, see [Performance](../performance.md).


## Results

At `2d284c9`, backup-sized objects have little incremental encoding overhead,
but multipart verification and small serial writes remain material costs.
All **24 runs pass**: three alternating direct/gateway pairs for each of four
workloads, with exact-version retention audits and content recovery checks.
The [numerical evidence](../assets/direct-storage-cost-2026-09-09.json) includes
every sample, phase, operation/status count, inventory, client version and
source/binary/helper/log hash. These results use real RustFS and a Kubernetes
Lease on a shared local host; they do not establish external-provider prices.

### Measured storage and backend traffic

Ratios are medians of three paired **gateway/direct** samples. Stored bytes
include all surviving object versions and fixed gateway setup data. Operating
traffic excludes gateway bootstrap and includes the client workload, restores,
one maintenance dry-run/apply and observed automatic background work. The same
HTTP meter counts both paths, including retries and verification requests.

| Workload | Stored object bytes | Uploaded body bytes | Downloaded body bytes | Backend HTTP requests |
| --- | ---: | ---: | ---: | ---: |
| Kubernetes-shaped Kopia, two snapshots | 1.035x | 0.999x | 0.567x | 0.105x |
| PostgreSQL-shaped Kopia, two snapshots | 1.013x | 0.999x | 0.966x | 3.379x |
| Two 100 MiB multipart versions | 1.025x | 1.000x | 2.001x | 24.385x |
| 512 serial overwrites of 512 B | 27.693x | 7.670x | 6,658.494x | 28.259x |

Gateway setup leaves about **5.006 MiB** of object data, chiefly provider
qualification artifacts. It also uses 319 backend requests, approximately
5.007 MiB uploaded and 0.068 MiB downloaded, reported separately from operating
traffic. Subtracting each gateway
initial inventory, incremental stored bytes are **1.00075x** direct for
Kubernetes, **1.00050x** for PostgreSQL, **1.00028x** for multipart and
**7.66875x** for tiny overwrites. This subtraction isolates workload growth;
it does not make the retained setup objects free.

The tiny workload retains 0.250 MiB directly and 6.923 MiB through rs3, including
setup. It downloads only 1,124 B directly versus 7.137 MiB through rs3, so the
large download ratio has a very small denominator. Each overwrite waits for
success before the next starts: these writes cannot share a publication batch.
The results include historical lookup and maintenance costs; they are not a
measurement of concurrent small-write batching.

### Upload verification and restore caching

The multipart write phases send **200.001 MiB** directly versus **200.055 MiB**
through rs3. During those writes, the backend returns about **0.001 MiB** directly
versus **200.070 MiB** through rs3. The gateway reads completed encrypted parts
back before publication. This makes write-path body traffic approximately
**2x direct S3**, independently of later user downloads.

Kopia writes use the packed commit path, whose post-write checks differ from
standalone/multipart body verification. These two-snapshot fixtures upload
about 148 MiB for Kubernetes and 395 MiB for PostgreSQL on either path. The
write phases use 88 versus 355 backend requests for Kubernetes and 100 versus
463 for PostgreSQL, direct versus gateway.

Kopia restores remove its local disk cache before each restore. The gateway
remains running with its default **256 MiB** decrypted-segment cache. That
extra cache is part of the measured service and can reuse data between restores:

| Restore backend downloads, median MiB | Direct A | Gateway A | Direct B | Gateway B |
| --- | ---: | ---: | ---: | ---: |
| Kubernetes-shaped Kopia | 131.624 | 132.716 | 131.642 | 15.971 |
| PostgreSQL-shaped Kopia | 352.045 | 365.410 | 352.045 | 313.965 |

The aggregate download savings do not describe a cold gateway restart. rs3 also
answers client metadata requests from its namespace state, which explains much
of the request reduction for the many-file Kubernetes restore. PostgreSQL has
fewer files, so retained-history and maintenance calls outweigh that benefit.

### Retention cost and comparison limits

Both paths enforce a **30-day protection floor** for newly written data. Direct
S3 uses bucket-default COMPLIANCE retention. rs3 uses explicit version locks,
a 30-day recovery window, a one-day renewal margin and 60-second clock allowance.
The provider adapter rounds retention upward to whole days. Exact-version HEAD
audits observe about **32 days** of protection on rs3 repository objects versus
**30 days** directly. Matching the requested floor does not remove this overhead.

Summing each retained version's bytes times its observed remaining lock duration
gives **1.101x** direct locked byte-days for Kubernetes, **1.080x** for PostgreSQL,
**1.092x** for multipart and **28.205x** for tiny overwrites, including setup.
These are current lock obligations, not an elapsed 30-day storage measurement
or a monthly bill. The JSON also reports a separate constant-size 30-day
projection. Neither projection models future writes, renewals or reclamation.
No provider lifecycle rule or accelerated expiry runs in this fixture; gateway
reclamation is disabled.

The policies are not equivalent for long-lived objects: native bucket defaults
start at version creation, while rs3 maintains dependencies for its recovery
promises. Native S3 Object Lock permits new versions and delete markers while
protecting an older version. See the [S3 Object Lock contract](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html).
Native version retention also lacks rs3's path privacy, external rollback anchor
and authenticated repository recovery points.

### Method and verification

Each lane starts a fresh disposable RustFS instance with the same pinned image,
a 4 GiB memory limit and 3 GiB tmpfs. Gateway lanes use a generated salt and a
real Kind Lease. The source, release executable and helper hashes remain
unchanged throughout all 24 runs. Kopia is version 0.22.3; raw S3 operations use
Boto3 1.42.31. No concurrent benchmark builds run. Shared-host CPU and cache
conditions limit elapsed-time interpretation. Phase times and writer CPU/RSS
are included in the JSON; writer samples exclude bootstrap and historical
reader processes, Kubernetes and provider resources.

The synthetic Kubernetes tree contains 6,144 YAML records and a 128 MiB binary
fragment. The PostgreSQL tree contains 192 one-MiB relation files, eight 16 MiB
WAL-shaped files and a 32 MiB dump-shaped file. Generation B changes about 10%
of records and bulk data, replaces about 1% of records and rotates one WAL file.
Paired source manifests match exactly; independent Kopia repository encryption
and absolute source paths make their repository metadata differ. Every file
and directory in both immutable snapshots is checked after restore. These are
synthetic file backups, not Kubernetes or PostgreSQL consistency qualification.

Raw cases verify latest full/range reads, deletion visibility and recovery of
the original value after overwrite/deletion. Direct S3 selects an old version;
rs3 starts a fresh historical reader. Historical phase timing includes that
reader's startup and shutdown. Kopia source-file churn is not snapshot pruning.

The meter streams both paths with the same close-per-request connection policy.
Counters include decoded HTTP bodies and exclude headers, chunk framing,
TCP/TLS and Kubernetes traffic. Small-request header overhead is therefore
absent from byte totals. The relay also removes fixed-length AWS `aws-chunked` request framing for
counting; it does not authenticate chunk signatures or decode other content
encodings.
Shared bucket provisioning and exact-version inventory audits bypass the meter;
excluded audit request counts are recorded. All observed background backend
traffic remains in the published totals. No transport errors occurred.

Stored object bytes sum exact-version payload lengths, including retained old
versions and qualification artifacts. They exclude provider filesystem metadata,
replication and erasure coding. Delete markers and their UTF-8 key bytes are
counted separately. Provider rates, operation/status billing, transfer placement
and gateway compute must be applied separately to estimate money. Owned
containers and the Kind cluster were removed after the run.
