//! Multipart S3 routes and owned bounded upload work.

mod checksum;
mod sessions;
use super::*;
use crate::s3::content_md5::upload_part_expected_md5;
use rs3_repository::v2::{V3ClientMultipartUpload, V3MultipartSelection};
use rs3_types::{LogicalPath, MultipartUploadId};
use s3s::dto::*;
pub(super) use sessions::MultipartSessions;

fn internal() -> s3s::S3Error {
    s3s::s3_error!(InternalError, "multipart state unavailable")
}
fn no_upload() -> s3s::S3Error {
    s3s::s3_error!(NoSuchUpload, "multipart upload is unknown or expired")
}

impl GatewayS3Service {
    async fn multipart_request<T: Send + 'static>(
        &self,
        operation: &'static str,
        bucket: String,
        mutation: bool,
        work: impl std::future::Future<Output = S3Result<T>> + Send + 'static,
    ) -> S3Result<S3Response<T>> {
        let permit = self.admit_request(operation)?;
        self.check_bucket(&bucket)?;
        if mutation {
            self.check_mutation_allowed()?;
        }
        let service = self.clone();
        let request_id = self.next_request_id();
        let span = self.request_span(operation, request_id, Some(&bucket));
        tokio::spawn(
            async move {
                let _permit = permit;
                let started = Instant::now();
                let result = work.await.map(S3Response::new);
                service.record_request_result(
                    operation,
                    request_id,
                    Some(&bucket),
                    started.elapsed(),
                    &result,
                    match operation {
                        "AbortMultipartUpload" => http::StatusCode::NO_CONTENT,
                        _ => http::StatusCode::OK,
                    },
                );
                result
            }
            .instrument(span),
        )
        .await
        .map_err(|_| internal())?
    }

    pub(super) async fn multipart_create(
        &self,
        req: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        let input = req.input;
        let service = self.clone();
        self.multipart_request(
            "CreateMultipartUpload",
            input.bucket.clone(),
            true,
            async move {
                crate::s3::checksum::validate_request_headers(&req.headers)
                    .map_err(|error| error.into_s3_error())?;
                reject_options(&[
                    input.acl.is_some(),
                    input.bucket_key_enabled.is_some(),
                    input.cache_control.is_some(),
                    input.content_disposition.is_some(),
                    input.content_encoding.is_some(),
                    input.content_language.is_some(),
                    input.expected_bucket_owner.is_some(),
                    input.expires.is_some(),
                    input.grant_full_control.is_some(),
                    input.grant_read.is_some(),
                    input.grant_read_acp.is_some(),
                    input.grant_write_acp.is_some(),
                    // Custom metadata is accepted but intentionally not retained in the v03 preview.
                    input.request_payer.is_some(),
                    input.sse_customer_algorithm.is_some(),
                    input.sse_customer_key.is_some(),
                    input.sse_customer_key_md5.is_some(),
                    input.ssekms_encryption_context.is_some(),
                    input.ssekms_key_id.is_some(),
                    input.server_side_encryption.is_some(),
                    input.tagging.is_some(),
                    input.website_redirect_location.is_some(),
                    input
                        .content_type
                        .as_deref()
                        .is_some_and(|v| v != "application/octet-stream"),
                    input
                        .storage_class
                        .as_ref()
                        .is_some_and(|v| v.as_str() != StorageClass::STANDARD),
                    input.object_lock_legal_hold_status.is_some(),
                ])?;
                let checksum_policy = checksum::creation_policy(&input)?;
                let protection = PutObjectInput {
                    object_lock_mode: input.object_lock_mode,
                    object_lock_retain_until_date: input.object_lock_retain_until_date,
                    ..Default::default()
                };
                let retention = put_object_retention_policy(&protection)?;
                if retention.is_some() && !service.retention_writes_qualified {
                    return Err(s3s::s3_error!(
                        NotImplemented,
                        "retained multipart writes are not configured"
                    ));
                }
                let key = logical_path(input.key.clone())?;
                let permit = service.multipart.reserve()?;
                let upload = service
                    .repository
                    .create_multipart_upload(
                        key,
                        RepositoryPutOptions {
                            retention,
                            ..Default::default()
                        },
                        Some(checksum_policy),
                    )
                    .await
                    .map_err(repository_error)?;
                let id = service.multipart.insert(upload, permit).await?;
                Ok(CreateMultipartUploadOutput {
                    checksum_algorithm: Some(checksum_algorithm_output(
                        checksum_policy.algorithm(),
                    )),
                    checksum_type: Some(checksum_kind_output(checksum_policy.kind())),
                    bucket: Some(input.bucket),
                    key: Some(input.key),
                    upload_id: Some(hex::encode(id.as_bytes())),
                    ..Default::default()
                })
            },
        )
        .await
    }

    pub(super) async fn multipart_upload_part(
        &self,
        req: S3Request<UploadPartInput>,
    ) -> S3Result<S3Response<UploadPartOutput>> {
        let mut input = req.input;
        let service = self.clone();
        self.multipart_request("UploadPart", input.bucket.clone(), true, async move {
            reject_options(&[
                input.expected_bucket_owner.is_some(),
                input.request_payer.is_some(),
                input.sse_customer_algorithm.is_some(),
                input.sse_customer_key.is_some(),
                input.sse_customer_key_md5.is_some(),
            ])?;
            let number = u32::try_from(input.part_number)
                .ok()
                .filter(|v| (1..=10_000).contains(v))
                .ok_or_else(|| s3s::s3_error!(InvalidArgument, "invalid multipart part number"))?;
            let len = input.content_length.ok_or_else(|| {
                s3s::s3_error!(MissingContentLength, "UploadPart requires Content-Length")
            })?;
            let len = u64::try_from(len)
                .map_err(|_| s3s::s3_error!(InvalidArgument, "invalid multipart content length"))?;
            let stored_len = len
                .checked_add(
                    len.div_ceil(64 * 1024)
                        .checked_mul(16)
                        .ok_or_else(too_large)?,
                )
                .ok_or_else(too_large)?;
            if len > service.max_put_object_bytes
                || stored_len > rs3_storage::MULTIPART_MAX_PART_BYTES
            {
                return Err(too_large());
            }
            let id = upload_id(&input.upload_id)?;
            let key = logical_path(input.key.clone())?;
            let session = service.multipart.get(&id)?;
            let state = session.upload.read().await;
            session.ensure_live()?;
            let upload = matching_upload(&state, &key)?;
            let policy = upload.checksum_policy().ok_or_else(internal)?;
            let request = ChecksumRequest::from_upload_part(
                &input,
                &req.headers,
                req.trailing_headers,
                policy.algorithm(),
            )
            .map_err(|error| error.into_s3_error())?;
            if request.algorithm() != policy.algorithm() {
                return Err(s3s::s3_error!(
                    BadDigest,
                    "part checksum algorithm differs from upload"
                ));
            }
            let expected_md5 = upload_part_expected_md5(&input, &req.headers)
                .map_err(|error| error.into_s3_error())?;
            let checksum = rs3_repository::UploadChecksum::pending();
            let (body, checksum_failure) =
                validate_body(input.body.take(), request, checksum.clone());
            let slot = session.part_slot(number)?;
            let _part = slot.lock.lock().await;
            session.ensure_live()?;
            let mut reservation = service.upload_body_budget.reservation();
            reservation.reserve_until("UploadPart", CLIENT_PART_WORKING_SET_BYTES)?;
            let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let body = ClientPartBody {
                body: Some(body),
                len,
                remaining: len,
                timeout: service.stream_read_stall_timeout,
                failed: Arc::clone(&failed),
                terminal: false,
            };
            let result = upload
                .upload_part(number, Box::new(body), Some(checksum), expected_md5)
                .await;
            if failed.load(Ordering::Acquire) {
                return Err(checksum_failure.map_error(s3s::s3_error!(
                    IncompleteBody,
                    "multipart body did not match its declared bounded length"
                )));
            }
            let part =
                result.map_err(|error| checksum_failure.map_error(repository_error(error)))?;
            record_s3_request_body_bytes("UploadPart", usize::try_from(len).unwrap_or(usize::MAX));
            let checksum = checksum_output(part.checksum());
            Ok(UploadPartOutput {
                checksum_crc32: checksum.checksum_crc32,
                checksum_crc32c: checksum.checksum_crc32c,
                checksum_crc64nvme: checksum.checksum_crc64nvme,
                checksum_sha1: checksum.checksum_sha1,
                checksum_sha256: checksum.checksum_sha256,
                e_tag: Some(ETag::Strong(part.etag())),
                ..Default::default()
            })
        })
        .await
    }

    pub(super) async fn multipart_complete(
        &self,
        req: S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<CompleteMultipartUploadOutput>> {
        let input = req.input;
        let service = self.clone();
        self.multipart_request(
            "CompleteMultipartUpload",
            input.bucket.clone(),
            true,
            async move {
                crate::s3::checksum::validate_request_headers(&req.headers)
                    .map_err(|error| error.into_s3_error())?;
                reject_options(&[
                    input.expected_bucket_owner.is_some(),
                    input.if_match.is_some(),
                    input.request_payer.is_some(),
                    input.sse_customer_algorithm.is_some(),
                    input.sse_customer_key.is_some(),
                    input.sse_customer_key_md5.is_some(),
                ])?;
                let selection = selected_parts(&input)?;
                let create_only = match input.if_none_match {
                    None => false,
                    Some(ETagCondition::Any) => true,
                    _ => {
                        return Err(s3s::s3_error!(
                            InvalidRequest,
                            "only If-None-Match: * is supported"
                        ));
                    }
                };
                let expected_size = input
                    .mpu_object_size
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| {
                        s3s::s3_error!(InvalidArgument, "invalid multipart object size")
                    })?;
                let id = upload_id(&input.upload_id)?;
                let key = logical_path(input.key.clone())?;
                let accepted = || {
                    service
                        .repository
                        .accepted_multipart_completion(&id, &key, &selection)
                        .map_err(repository_error)
                };
                if let Some(receipt) = accepted()? {
                    return completion_output(&input.bucket, &input.key, receipt, expected_size);
                }
                let session = match service.multipart.get(&id) {
                    Ok(session) => session,
                    Err(error) => {
                        // A completion can install and remove its session after the
                        // first lookup. Recheck accepted state before NoSuchUpload.
                        if let Some(receipt) = accepted()? {
                            return completion_output(
                                &input.bucket,
                                &input.key,
                                receipt,
                                expected_size,
                            );
                        }
                        return Err(error);
                    }
                };
                let mut state = session.upload.write().await;
                if let Some(receipt) = accepted()? {
                    return completion_output(&input.bucket, &input.key, receipt, expected_size);
                }
                session.ensure_live()?;
                let upload = matching_upload(&state, &key)?;
                upload
                    .validate_selection(&selection)
                    .map_err(|error| match error {
                        RepositoryError::ObjectChecksumMismatch => repository_error(error),
                        _ => s3s::s3_error!(
                            InvalidPart,
                            "selected part is missing, replaced or has invalid checksum facts"
                        ),
                    })?;
                let len = upload.selected_size(&selection).map_err(|_| {
                    s3s::s3_error!(
                        EntityTooSmall,
                        "nonfinal multipart parts must be at least 5 MiB"
                    )
                })?;
                if len > service.max_put_object_bytes {
                    return Err(too_large());
                }
                if expected_size.is_some_and(|expected| expected != len) {
                    return Err(s3s::s3_error!(
                        InvalidRequest,
                        "multipart object size does not match selected parts"
                    ));
                }
                let mut upload = state.take().ok_or_else(no_upload)?;
                if create_only {
                    upload.require_absent_at_publication();
                }
                let result = service
                    .repository
                    .complete_multipart_upload(upload, selection.clone())
                    .await;
                service.multipart.remove(&id, &session);
                let receipt = result.map_err(repository_error)?;
                completion_output(&input.bucket, &input.key, receipt, expected_size)
            },
        )
        .await
    }

    pub(super) async fn multipart_abort(
        &self,
        input: AbortMultipartUploadInput,
    ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        let service = self.clone();
        self.multipart_request(
            "AbortMultipartUpload",
            input.bucket.clone(),
            true,
            async move {
                reject_options(&[
                    input.expected_bucket_owner.is_some(),
                    input.if_match_initiated_time.is_some(),
                    input.request_payer.is_some(),
                ])?;
                let id = upload_id(&input.upload_id)?;
                let key = logical_path(input.key)?;
                let session = service.multipart.get(&id)?;
                let mut state = session.upload.write().await;
                matching_upload(&state, &key)?;
                let upload = state.take().ok_or_else(no_upload)?;
                let result = upload.abort().await;
                service.multipart.remove(&id, &session);
                result.map_err(repository_error)?;
                Ok(AbortMultipartUploadOutput::default())
            },
        )
        .await
    }

    pub(super) async fn multipart_list(
        &self,
        input: ListPartsInput,
    ) -> S3Result<S3Response<ListPartsOutput>> {
        let service = self.clone();
        self.multipart_request("ListParts", input.bucket.clone(), false, async move {
            reject_options(&[
                input.expected_bucket_owner.is_some(),
                input.request_payer.is_some(),
                input.sse_customer_algorithm.is_some(),
                input.sse_customer_key.is_some(),
                input.sse_customer_key_md5.is_some(),
            ])?;
            let max_parts = input.max_parts.unwrap_or(1000);
            let marker = input.part_number_marker.unwrap_or(0);
            if !(0..=1000).contains(&max_parts) || !(0..=10_000).contains(&marker) {
                return Err(s3s::s3_error!(
                    InvalidArgument,
                    "invalid multipart listing limit or marker"
                ));
            }
            let id = upload_id(&input.upload_id)?;
            let key = logical_path(input.key.clone())?;
            let session = service.multipart.get(&id)?;
            let state = session.upload.read().await;
            session.ensure_live()?;
            let upload = matching_upload(&state, &key)?;
            let mut parts = upload
                .list_parts(marker as u32, max_parts as usize + 1)
                .map_err(repository_error)?;
            let truncated = max_parts > 0 && parts.len() > max_parts as usize;
            parts.truncate(max_parts as usize);
            let next = parts.last().map(|part| part.part_number() as i32);
            let parts = parts
                .into_iter()
                .map(|part| {
                    let checksum = checksum_output(part.checksum());
                    Part {
                        checksum_crc32: checksum.checksum_crc32,
                        checksum_crc32c: checksum.checksum_crc32c,
                        checksum_crc64nvme: checksum.checksum_crc64nvme,
                        checksum_sha1: checksum.checksum_sha1,
                        checksum_sha256: checksum.checksum_sha256,
                        part_number: Some(part.part_number() as i32),
                        size: Some(part.plaintext_len() as i64),
                        e_tag: Some(ETag::Strong(part.etag())),
                        ..Default::default()
                    }
                })
                .collect();
            let policy = upload.checksum_policy().ok_or_else(internal)?;
            Ok(ListPartsOutput {
                checksum_algorithm: Some(checksum_algorithm_output(policy.algorithm())),
                checksum_type: Some(checksum_kind_output(policy.kind())),
                bucket: Some(input.bucket),
                key: Some(input.key),
                upload_id: Some(input.upload_id),
                max_parts: Some(max_parts),
                part_number_marker: Some(marker),
                is_truncated: Some(truncated),
                next_part_number_marker: truncated.then_some(next).flatten(),
                parts: Some(parts),
                storage_class: Some(StorageClass::from_static(StorageClass::STANDARD)),
                ..Default::default()
            })
        })
        .await
    }
}

fn reject_options(options: &[bool]) -> S3Result<()> {
    if options.iter().any(|present| *present) {
        Err(s3s::s3_error!(
            NotImplemented,
            "requested multipart option is not supported"
        ))
    } else {
        Ok(())
    }
}
fn too_large() -> s3s::S3Error {
    s3s::s3_error!(EntityTooLarge, "multipart value exceeds supported size")
}
fn upload_id(value: &str) -> S3Result<MultipartUploadId> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(no_upload());
    }
    let mut id = [0; 32];
    hex::decode_to_slice(value, &mut id).map_err(|_| no_upload())?;
    Ok(MultipartUploadId::from_bytes(id))
}
fn matching_upload<'a>(
    state: &'a Option<V3ClientMultipartUpload>,
    key: &LogicalPath,
) -> S3Result<&'a V3ClientMultipartUpload> {
    state
        .as_ref()
        .filter(|upload| upload.matches_key(key))
        .ok_or_else(no_upload)
}
fn selected_parts(input: &CompleteMultipartUploadInput) -> S3Result<V3MultipartSelection> {
    let parts = input
        .multipart_upload
        .as_ref()
        .and_then(|upload| upload.parts.as_ref())
        .ok_or_else(|| {
            s3s::s3_error!(
                InvalidRequest,
                "multipart completion requires selected parts"
            )
        })?;
    if parts.is_empty() || parts.len() > 10_000 {
        return Err(s3s::s3_error!(
            InvalidRequest,
            "invalid multipart selected part count"
        ));
    }
    let expected = checksum::completion_checksum(input, parts.len())?;
    let kind = checksum::completion_kind(input)?;
    let mut previous = 0;
    let mut selection = Vec::with_capacity(parts.len());
    for part in parts {
        let checksum = checksum::part_checksum(part)?;
        let number = part
            .part_number
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| (1..=10_000).contains(v))
            .ok_or_else(|| s3s::s3_error!(InvalidPart, "invalid selected part number"))?;
        if number <= previous {
            return Err(s3s::s3_error!(
                InvalidPartOrder,
                "selected parts must be strictly ordered"
            ));
        }
        previous = number;
        let etag = part
            .e_tag
            .clone()
            .and_then(ETag::into_strong)
            .ok_or_else(|| s3s::s3_error!(InvalidPart, "selected part requires its strong ETag"))?;
        selection.push((number, etag, checksum));
    }
    V3MultipartSelection::with_checksums_and_kind(selection, expected, kind)
        .map_err(|_| s3s::s3_error!(InvalidPart, "invalid selected part ETag"))
}
fn completion_output(
    bucket: &str,
    key: &str,
    receipt: rs3_index::completion::CompletionReceipt,
    expected_size: Option<u64>,
) -> S3Result<CompleteMultipartUploadOutput> {
    if expected_size.is_some_and(|size| size != receipt.content_len) {
        return Err(s3s::s3_error!(
            InvalidRequest,
            "multipart object size does not match accepted completion"
        ));
    }
    let checksum = checksum_output(receipt.checksum.as_ref());
    Ok(CompleteMultipartUploadOutput {
        checksum_crc32: checksum.checksum_crc32,
        checksum_crc32c: checksum.checksum_crc32c,
        checksum_crc64nvme: checksum.checksum_crc64nvme,
        checksum_sha1: checksum.checksum_sha1,
        checksum_sha256: checksum.checksum_sha256,
        checksum_type: checksum.checksum_type,
        bucket: Some(bucket.to_owned()),
        key: Some(key.to_owned()),
        e_tag: Some(ETag::Strong(receipt.etag.to_s3_string())),
        ..Default::default()
    })
}

// Plaintext transport plus sealer input/output segments and one provider frame.
const CLIENT_PART_WORKING_SET_BYTES: u64 =
    2 * rs3_storage::MAX_BLOB_READ_CHUNK_BYTES as u64 + 4 * 64 * 1024;
struct ClientPartBody {
    body: Option<StreamingBlob>,
    len: u64,
    remaining: u64,
    timeout: Duration,
    failed: Arc<std::sync::atomic::AtomicBool>,
    terminal: bool,
}

// An outer producer timeout can drop the pending read before its local timeout
// records failure. This also covers transport cancellation while reading input;
// it establishes an incomplete read, not which peer caused the interruption.
struct ClientPartReadGuard<'a>(Option<&'a std::sync::atomic::AtomicBool>);

impl Drop for ClientPartReadGuard<'_> {
    fn drop(&mut self) {
        if let Some(failed) = self.0 {
            failed.store(true, Ordering::Release);
        }
    }
}

#[async_trait::async_trait]
impl rs3_storage::BlobRead for ClientPartBody {
    fn exact_len(&self) -> u64 {
        self.len
    }
    async fn next_chunk(&mut self) -> rs3_storage::Result<Option<Bytes>> {
        if self.terminal {
            return Ok(None);
        }
        let mut read_guard = ClientPartReadGuard(Some(&self.failed));
        let next = match &mut self.body {
            Some(body) => next_body_chunk(body, self.timeout).await,
            None => Ok(None),
        };
        read_guard.0 = None;
        match next {
            Ok(Some(bytes))
                if bytes.len() <= rs3_storage::MAX_BLOB_READ_CHUNK_BYTES
                    && bytes.len() as u64 <= self.remaining =>
            {
                self.remaining -= bytes.len() as u64;
                Ok(Some(bytes))
            }
            Ok(None) if self.remaining == 0 => {
                self.terminal = true;
                Ok(None)
            }
            _ => {
                self.failed.store(true, Ordering::Release);
                self.terminal = true;
                Err(StorageError::Provider(
                    "invalid multipart request body".to_owned(),
                ))
            }
        }
    }
}

fn checksum_algorithm_output(algorithm: rs3_types::ChecksumAlgorithm) -> ChecksumAlgorithm {
    use rs3_types::ChecksumAlgorithm as Algorithm;
    ChecksumAlgorithm::from_static(match algorithm {
        Algorithm::Crc32 => ChecksumAlgorithm::CRC32,
        Algorithm::Crc32c => ChecksumAlgorithm::CRC32C,
        Algorithm::Crc64Nvme => ChecksumAlgorithm::CRC64NVME,
        Algorithm::Sha1 => ChecksumAlgorithm::SHA1,
        Algorithm::Sha256 => ChecksumAlgorithm::SHA256,
    })
}
fn checksum_kind_output(kind: rs3_repository::MultipartChecksumKind) -> ChecksumType {
    ChecksumType::from_static(match kind {
        rs3_repository::MultipartChecksumKind::FullObject => ChecksumType::FULL_OBJECT,
        rs3_repository::MultipartChecksumKind::Composite => ChecksumType::COMPOSITE,
    })
}
