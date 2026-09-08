use super::*;
use s3s::Body;
use s3s::dto::*;

const KEY: &str = "private/multipart-checksum";
// Frozen independent vectors: CRC64/NVME("123456789"), SHA256("abc"),
// and SHA256 of the raw SHA256("abc") digest, with the selected count suffix.
const CRC64: &str = "rosUhgp5mIg=";
const SHA256: &str = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";
const COMPOSITE: &str = "T4tCwi3TcptRm6b2jS2nzFstYG0F2u1a1RKMwD5sY1g=-1";
const WRONG_SHA256: &str = "iBCtWB5Z8rw5KLJhcHpxMI9+E56wSCA2bcTVwY2YAiU=";

async fn create(service: &GatewayS3Service, sha256: bool) -> CreateMultipartUploadOutput {
    service
        .create_multipart_upload(s3_request(CreateMultipartUploadInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            checksum_algorithm: sha256
                .then(|| ChecksumAlgorithm::from_static(ChecksumAlgorithm::SHA256)),
            checksum_type: sha256.then(|| ChecksumType::from_static(ChecksumType::COMPOSITE)),
            ..Default::default()
        }))
        .await
        .expect("create upload")
        .output
}

fn part_input(id: &str, bytes: &'static [u8]) -> UploadPartInput {
    UploadPartInput {
        bucket: "client-bucket".into(),
        key: KEY.into(),
        upload_id: id.into(),
        part_number: 1,
        content_length: Some(bytes.len() as i64),
        body: Some(StreamingBlob::from(Body::from(Bytes::from_static(bytes)))),
        ..Default::default()
    }
}

fn complete_input(id: &str, etag: ETag) -> CompleteMultipartUploadInput {
    CompleteMultipartUploadInput {
        bucket: "client-bucket".into(),
        key: KEY.into(),
        upload_id: id.into(),
        multipart_upload: Some(CompletedMultipartUpload {
            parts: Some(vec![CompletedPart {
                part_number: Some(1),
                e_tag: Some(etag),
                ..Default::default()
            }]),
        }),
        ..Default::default()
    }
}

async fn list(service: &GatewayS3Service, id: &str) -> ListPartsOutput {
    service
        .list_parts(s3_request(ListPartsInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            upload_id: id.into(),
            ..Default::default()
        }))
        .await
        .expect("list active parts")
        .output
}

async fn head(service: &GatewayS3Service) -> HeadObjectOutput {
    service
        .head_object(s3_request(HeadObjectInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            checksum_mode: Some(ChecksumMode::from_static(ChecksumMode::ENABLED)),
            ..Default::default()
        }))
        .await
        .expect("checksum HEAD")
        .output
}

#[tokio::test]
async fn multipart_default_crc64_is_computed_and_echoed_through_completion_and_head() {
    let service = gateway_service().await;
    let created = create(&service, false).await;
    assert_eq!(
        created.checksum_algorithm.as_ref().map(|v| v.as_str()),
        Some("CRC64NVME")
    );
    assert_eq!(
        created.checksum_type.as_ref().map(|v| v.as_str()),
        Some("FULL_OBJECT")
    );
    let id = created.upload_id.expect("upload id");
    let part = service
        .upload_part(s3_request(part_input(&id, b"123456789")))
        .await
        .expect("computed part checksum")
        .output;
    assert_eq!(part.checksum_crc64nvme.as_deref(), Some(CRC64));
    let etag = part.e_tag.expect("part token");
    let listed = list(&service, &id).await;
    assert_eq!(
        listed.checksum_algorithm.as_ref().map(|v| v.as_str()),
        Some("CRC64NVME")
    );
    assert_eq!(
        listed.checksum_type.as_ref().map(|v| v.as_str()),
        Some("FULL_OBJECT")
    );
    let parts = listed.parts.expect("parts");
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].checksum_crc64nvme.as_deref(), Some(CRC64));
    assert_eq!(parts[0].e_tag, Some(etag.clone()));
    assert_eq!(accepted_v2_sequence(&service).await, 1);
    // Full CRC permits omitted per-part declarations and computes the final value.
    let completed = service
        .complete_multipart_upload(s3_request(complete_input(&id, etag)))
        .await
        .expect("complete")
        .output;
    assert_eq!(completed.checksum_crc64nvme.as_deref(), Some(CRC64));
    assert_eq!(
        completed.checksum_type.as_ref().map(|v| v.as_str()),
        Some("FULL_OBJECT")
    );
    let metadata = head(&service).await;
    assert_eq!(metadata.content_length, Some(9));
    assert_eq!(metadata.checksum_crc64nvme.as_deref(), Some(CRC64));
    assert_eq!(accepted_v2_sequence(&service).await, 2);
}

#[tokio::test]
async fn multipart_bad_digest_replacement_preserves_prior_part_and_its_checksum() {
    let service = gateway_service().await;
    let id = create(&service, false).await.upload_id.expect("upload id");
    let original = service
        .upload_part(s3_request(part_input(&id, b"123456789")))
        .await
        .expect("original")
        .output;
    let error = service
        .upload_part(s3_request(UploadPartInput {
            checksum_crc64nvme: Some(CRC64.into()),
            ..part_input(&id, b"different")
        }))
        .await
        .expect_err("incorrect replacement digest");
    assert_eq!(error.code().as_str(), "BadDigest");
    let listed = list(&service, &id).await.parts.expect("parts");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].e_tag, original.e_tag);
    assert_eq!(listed[0].checksum_crc64nvme.as_deref(), Some(CRC64));
    assert_eq!(accepted_v2_sequence(&service).await, 1);
    service
        .complete_multipart_upload(s3_request(complete_input(
            &id,
            original.e_tag.expect("original token"),
        )))
        .await
        .expect("original still completes");
    let restored = service
        .get_object(s3_request(GetObjectInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            ..Default::default()
        }))
        .await
        .expect("restore original")
        .output;
    assert_eq!(
        collect_body(restored.body, 32).await.expect("bytes"),
        Bytes::from_static(b"123456789")
    );
    assert_eq!(
        head(&service).await.checksum_crc64nvme.as_deref(),
        Some(CRC64)
    );
}

#[tokio::test]
async fn multipart_sha256_composite_validates_parts_and_final_before_consuming_upload() {
    let service = gateway_service().await;
    let created = create(&service, true).await;
    assert_eq!(
        created.checksum_algorithm.as_ref().map(|v| v.as_str()),
        Some("SHA256")
    );
    assert_eq!(
        created.checksum_type.as_ref().map(|v| v.as_str()),
        Some("COMPOSITE")
    );
    let id = created.upload_id.expect("upload id");
    let error = service
        .upload_part(s3_request(UploadPartInput {
            checksum_sha256: Some(WRONG_SHA256.into()),
            ..part_input(&id, b"abc")
        }))
        .await
        .expect_err("bad part digest");
    assert_eq!(error.code().as_str(), "BadDigest");
    assert!(list(&service, &id).await.parts.expect("parts").is_empty());
    let part = service
        .upload_part(s3_request(UploadPartInput {
            checksum_sha256: Some(SHA256.into()),
            ..part_input(&id, b"abc")
        }))
        .await
        .expect("verified part")
        .output;
    assert_eq!(part.checksum_sha256.as_deref(), Some(SHA256));
    let etag = part.e_tag.expect("token");
    let missing = complete_input(&id, etag.clone());
    let error = service
        .complete_multipart_upload(s3_request(missing.clone()))
        .await
        .expect_err("composite requires selected digest");
    assert_eq!(error.code().as_str(), "InvalidPart");
    let mut request = missing;
    request.checksum_type = Some(ChecksumType::from_static(ChecksumType::COMPOSITE));
    request
        .multipart_upload
        .as_mut()
        .expect("selection")
        .parts
        .as_mut()
        .expect("parts")[0]
        .checksum_sha256 = Some(WRONG_SHA256.into());
    let error = service
        .complete_multipart_upload(s3_request(request.clone()))
        .await
        .expect_err("changed selected digest");
    assert_eq!(error.code().as_str(), "BadDigest");
    request
        .multipart_upload
        .as_mut()
        .expect("selection")
        .parts
        .as_mut()
        .expect("parts")[0]
        .checksum_sha256 = Some(SHA256.into());
    request.checksum_sha256 = Some(format!("{WRONG_SHA256}-1"));
    let error = service
        .complete_multipart_upload(s3_request(request.clone()))
        .await
        .expect_err("bad final digest");
    assert_eq!(error.code().as_str(), "BadDigest");
    assert_eq!(accepted_v2_sequence(&service).await, 1);
    assert_eq!(
        list(&service, &id).await.parts.expect("parts")[0].e_tag,
        Some(etag)
    );
    // Request checksum is a raw Base64 digest; the response adds its part count.
    request.checksum_sha256 = Some(COMPOSITE.strip_suffix("-1").expect("suffix").into());
    let complete = service
        .complete_multipart_upload(s3_request(request))
        .await
        .expect("same session completes after correcting digest")
        .output;
    assert_eq!(complete.checksum_sha256.as_deref(), Some(COMPOSITE));
    assert_eq!(
        complete.checksum_type.as_ref().map(|v| v.as_str()),
        Some("COMPOSITE")
    );
    let metadata = head(&service).await;
    assert_eq!(metadata.checksum_sha256.as_deref(), Some(COMPOSITE));
    assert_eq!(
        metadata.checksum_type.as_ref().map(|v| v.as_str()),
        Some("COMPOSITE")
    );
    assert_eq!(accepted_v2_sequence(&service).await, 2);
}

#[tokio::test]
async fn multipart_lost_response_retry_returns_accepted_checksum_after_overwrite_and_rejects_changed_facts()
 {
    let service = gateway_service().await;
    let id = create(&service, false).await.upload_id.expect("upload id");
    let part = service
        .upload_part(s3_request(part_input(&id, b"123456789")))
        .await
        .expect("part")
        .output;
    let mut request = complete_input(&id, part.e_tag.expect("token"));
    request.checksum_type = Some(ChecksumType::from_static(ChecksumType::FULL_OBJECT));
    request.checksum_crc64nvme = Some(CRC64.into());
    request
        .multipart_upload
        .as_mut()
        .expect("selection")
        .parts
        .as_mut()
        .expect("parts")[0]
        .checksum_crc64nvme = Some(CRC64.into());
    // Model a client that never received the accepted response and must retry.
    drop(
        service
            .complete_multipart_upload(s3_request(request.clone()))
            .await
            .expect("accepted response lost to client"),
    );
    service
        .put_object(s3_request(PutObjectInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            content_length: Some(5),
            body: Some(StreamingBlob::from(Body::from(Bytes::from_static(
                b"newer",
            )))),
            ..Default::default()
        }))
        .await
        .expect("newer independent write");
    let before = accepted_v2_sequence(&service).await;
    let current = head(&service).await;
    assert_ne!(current.checksum_crc64nvme.as_deref(), Some(CRC64));
    let retry = service
        .complete_multipart_upload(s3_request(request.clone()))
        .await
        .expect("accepted retry")
        .output;
    assert_eq!(retry.checksum_crc64nvme.as_deref(), Some(CRC64));
    assert_eq!(
        retry.checksum_type.as_ref().map(|v| v.as_str()),
        Some("FULL_OBJECT")
    );
    assert_eq!(accepted_v2_sequence(&service).await, before);
    for change in 0..4 {
        let mut changed = request.clone();
        match change {
            0 => changed.checksum_type = None,
            1 => changed.checksum_crc64nvme = Some("AAAAAAAAAAA=".into()),
            2 => {
                changed
                    .multipart_upload
                    .as_mut()
                    .expect("selection")
                    .parts
                    .as_mut()
                    .expect("parts")[0]
                    .checksum_crc64nvme = None
            }
            _ => changed.checksum_type = Some(ChecksumType::from_static(ChecksumType::COMPOSITE)),
        }
        assert!(
            service
                .complete_multipart_upload(s3_request(changed))
                .await
                .is_err(),
            "changed fact {change}"
        );
        assert_eq!(accepted_v2_sequence(&service).await, before);
    }
    assert_eq!(
        head(&service).await.checksum_crc64nvme,
        current.checksum_crc64nvme
    );
}
