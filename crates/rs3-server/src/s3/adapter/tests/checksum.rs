use super::*;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use s3s::dto::{ChecksumMode, ETag, Range};

fn input(body: &'static [u8], declared: Option<i64>, digest: &str) -> PutObjectInput {
    PutObjectInput {
        bucket: "client-bucket".into(),
        key: "private/checksummed".into(),
        content_length: declared,
        checksum_sha256: Some(digest.into()),
        body: Some(StreamingBlob::from(Body::from(Bytes::from_static(body)))),
        ..Default::default()
    }
}

fn md5_input(body: &'static [u8], declared: Option<i64>, digest: &str) -> PutObjectInput {
    PutObjectInput {
        bucket: "client-bucket".into(),
        key: "private/content-md5".into(),
        content_length: declared,
        content_md5: Some(digest.into()),
        body: Some(StreamingBlob::from(Body::from(Bytes::from_static(body)))),
        ..Default::default()
    }
}

#[tokio::test]
async fn content_md5_validates_every_put_body_path_and_keeps_the_prior_etag() {
    // Frozen MD5 values, independently generated from RFC 1321 test vectors.
    let original = "4vxxTEcn7pOV8yTNLn8zHw==";
    let original_etag = "e2fc714c4727ee9395f324cd2e7f331f";
    let bad = "AAAAAAAAAAAAAAAAAAAAAA==";
    for (threshold, declared) in [(64, Some(4)), (3, Some(4)), (64, None), (3, None)] {
        let service = gateway_service_with_put_body_limits(64, threshold, 5 * 1024 * 1024).await;
        let base = accepted_v3_sequence(&service).await;
        let error = service
            .put_object(s3_request(md5_input(b"abcd", declared, bad)))
            .await
            .expect_err("mismatched Content-MD5");
        assert_eq!(error.code().as_str(), "BadDigest");
        assert_eq!(accepted_v3_sequence(&service).await, base);

        let put = service
            .put_object(s3_request(md5_input(b"abcd", declared, original)))
            .await
            .expect("verified Content-MD5 PUT")
            .output;
        assert_eq!(put.e_tag, Some(ETag::Strong(original_etag.to_owned())));

        let accepted = accepted_v3_sequence(&service).await;
        let error = service
            .put_object(s3_request(md5_input(b"wxyz", declared, original)))
            .await
            .expect_err("failed replacement");
        assert_eq!(error.code().as_str(), "BadDigest");
        assert_eq!(accepted_v3_sequence(&service).await, accepted);
        let head = service
            .head_object(s3_request(HeadObjectInput {
                bucket: "client-bucket".into(),
                key: "private/content-md5".into(),
                ..Default::default()
            }))
            .await
            .expect("retained object")
            .output;
        assert_eq!(head.e_tag, Some(ETag::Strong(original_etag.to_owned())));
    }
}

#[tokio::test]
async fn content_md5_does_not_publish_a_truncated_known_length_stream() {
    let service = gateway_service_with_put_body_limits(64, 3, 5 * 1024 * 1024).await;
    let base = accepted_v3_sequence(&service).await;
    let error = service
        .put_object(s3_request(md5_input(
            b"abc",
            Some(4),
            "kAFQmDzST7DWlj99KOF/cg==",
        )))
        .await
        .expect_err("truncated streaming body");
    assert_eq!(error.code().as_str(), "IncompleteBody");
    assert_eq!(accepted_v3_sequence(&service).await, base);
}

#[tokio::test]
async fn checksum_put_validates_every_body_path_before_publication() {
    // Frozen SHA256("abcd"), independent of the production checksum hasher.
    let good = STANDARD.encode(
        hex::decode("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589")
            .expect("vector"),
    );
    let bad = STANDARD.encode([0u8; 32]);
    for (threshold, declared) in [(64, Some(4)), (3, Some(4)), (64, None), (3, None)] {
        let service = gateway_service_with_put_body_limits(64, threshold, 5 * 1024 * 1024).await;
        let base = accepted_v3_sequence(&service).await;
        let error = service
            .put_object(s3_request(input(b"abcd", declared, &bad)))
            .await
            .expect_err("mismatch");
        assert_eq!(error.code().as_str(), "BadDigest");
        assert_eq!(accepted_v3_sequence(&service).await, base);
        let put = service
            .put_object(s3_request(input(b"abcd", declared, &good)))
            .await
            .expect("verified PUT")
            .output;
        assert_eq!(put.checksum_sha256.as_deref(), Some(good.as_str()));
        assert_eq!(
            put.checksum_type.as_ref().map(|kind| kind.as_str()),
            Some("FULL_OBJECT")
        );
        let accepted = accepted_v3_sequence(&service).await;
        let error = service
            .put_object(s3_request(input(b"abcd", declared, &bad)))
            .await
            .expect_err("bad overwrite");
        assert_eq!(error.code().as_str(), "BadDigest");
        assert_eq!(accepted_v3_sequence(&service).await, accepted);
        let head = service
            .head_object(s3_request(HeadObjectInput {
                bucket: "client-bucket".into(),
                key: "private/checksummed".into(),
                checksum_mode: Some(ChecksumMode::from_static(ChecksumMode::ENABLED)),
                ..Default::default()
            }))
            .await
            .expect("metadata-only HEAD")
            .output;
        assert_eq!(head.checksum_sha256, Some(good.clone()));
        let get = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".into(),
                key: "private/checksummed".into(),
                checksum_mode: Some(ChecksumMode::from_static(ChecksumMode::ENABLED)),
                ..Default::default()
            }))
            .await
            .expect("GET")
            .output;
        assert_eq!(get.checksum_sha256, Some(good.clone()));
        assert_eq!(
            collect_body(get.body, 64).await.expect("body"),
            Bytes::from_static(b"abcd")
        );
        let partial = service
            .get_object(s3_request(GetObjectInput {
                bucket: "client-bucket".into(),
                key: "private/checksummed".into(),
                checksum_mode: Some(ChecksumMode::from_static(ChecksumMode::ENABLED)),
                range: Some(Range::Int {
                    first: 1,
                    last: Some(2),
                }),
                ..Default::default()
            }))
            .await
            .expect("range")
            .output;
        assert!(partial.checksum_sha256.is_none());
        assert!(partial.checksum_type.is_none());
        assert_eq!(
            collect_body(partial.body, 64).await.expect("range body"),
            Bytes::from_static(b"bc")
        );
    }
}

#[tokio::test]
async fn checksum_default_and_empty_put_are_verified() {
    let service = gateway_service().await;
    for body in [b"".as_slice(), b"123456789".as_slice()] {
        let output = service
            .put_object(s3_request(PutObjectInput {
                bucket: "client-bucket".into(),
                key: "private/default-checksum".into(),
                body: Some(StreamingBlob::from(Body::from(Bytes::copy_from_slice(
                    body,
                )))),
                content_length: Some(body.len() as i64),
                ..Default::default()
            }))
            .await
            .expect("default checksum PUT")
            .output;
        let expected = if body.is_empty() {
            0u64
        } else {
            0xae8b14860a799888
        };
        assert_eq!(
            output.checksum_crc64nvme,
            Some(STANDARD.encode(expected.to_be_bytes()))
        );
    }
}
