use super::*;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use s3s::dto::*;
use std::sync::Arc;
use tokio::sync::{Barrier, Notify};

const KEY: &str = "private/multipart.bin";
async fn create(service: &GatewayS3Service) -> String {
    service
        .create_multipart_upload(s3_request(CreateMultipartUploadInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            ..Default::default()
        }))
        .await
        .expect("create")
        .output
        .upload_id
        .expect("upload id")
}
fn part_input(id: &str, number: i32, body: StreamingBlob, len: i64) -> UploadPartInput {
    UploadPartInput {
        bucket: "client-bucket".into(),
        key: KEY.into(),
        upload_id: id.into(),
        part_number: number,
        body: Some(body),
        content_length: Some(len),
        ..Default::default()
    }
}
fn body(bytes: Bytes) -> StreamingBlob {
    let chunks = bytes
        .chunks(64 * 1024)
        .map(Bytes::copy_from_slice)
        .map(Ok::<_, std::io::Error>)
        .collect::<Vec<_>>();
    StreamingBlob::wrap(futures_util::stream::iter(chunks))
}
async fn part(service: &GatewayS3Service, id: &str, number: i32, bytes: Bytes) -> ETag {
    let len = bytes.len() as i64;
    service
        .upload_part(s3_request(part_input(id, number, body(bytes), len)))
        .await
        .expect("part")
        .output
        .e_tag
        .expect("etag")
}
fn complete_input(id: &str, parts: Vec<(i32, ETag)>) -> CompleteMultipartUploadInput {
    CompleteMultipartUploadInput {
        bucket: "client-bucket".into(),
        key: KEY.into(),
        upload_id: id.into(),
        multipart_upload: Some(CompletedMultipartUpload {
            parts: Some(
                parts
                    .into_iter()
                    .map(|(number, etag)| CompletedPart {
                        part_number: Some(number),
                        e_tag: Some(etag),
                        ..Default::default()
                    })
                    .collect(),
            ),
        }),
        ..Default::default()
    }
}
fn list_input(id: &str) -> ListPartsInput {
    ListPartsInput {
        bucket: "client-bucket".into(),
        key: KEY.into(),
        upload_id: id.into(),
        ..Default::default()
    }
}
async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("bounded multipart operation")
}

#[tokio::test(start_paused = true)]
async fn multipart_stalled_body_maps_outer_timeout_and_keeps_session_retryable() {
    for client_timeout in [Duration::from_secs(1), Duration::from_secs(2)] {
        let mut service =
            gateway_service_with_stream_read_stall_timeout(Duration::from_secs(1), 3).await;
        // The longer adapter timeout deterministically exercises cancellation by
        // the repository's outer producer timeout. Equal deadlines cover runtime defaults.
        service.stream_read_stall_timeout = client_timeout;
        let id = create(&service).await;
        let permits = service.request_slots.available_permits();
        let pending =
            StreamingBlob::wrap(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
        let error = service
            .upload_part(s3_request(part_input(&id, 1, pending, 4)))
            .await
            .expect_err("stalled body");
        assert_eq!(error.code().as_str(), "IncompleteBody");
        assert_eq!(service.request_slots.available_permits(), permits);
        assert_eq!(accepted_v3_sequence(&service).await, 1);
        let etag = part(&service, &id, 1, Bytes::from_static(b"body")).await;
        service
            .complete_multipart_upload(s3_request(complete_input(&id, vec![(1, etag)])))
            .await
            .expect("retry completes");
        assert_eq!(accepted_v3_sequence(&service).await, 2);
    }
}

#[tokio::test]
async fn multipart_content_md5_validates_before_replacing_a_part_and_returns_standard_etags() {
    let service = gateway_service().await;
    let id = create(&service).await;
    // Frozen MD5("body") from RFC 1321-compatible tooling.
    let part_md5 =
        STANDARD.encode(hex::decode("841a2d689ad86bd1611447453c22c6fc").expect("vector"));
    let mut first = part_input(&id, 1, body(Bytes::from_static(b"body")), 4);
    first.content_md5 = Some(part_md5);
    let part = service
        .upload_part(s3_request(first))
        .await
        .expect("verified part")
        .output
        .e_tag
        .expect("part ETag");
    assert_eq!(
        part,
        ETag::Strong("841a2d689ad86bd1611447453c22c6fc".to_owned())
    );

    let mut replacement = part_input(&id, 1, body(Bytes::from_static(b"tail")), 4);
    replacement.content_md5 = Some(STANDARD.encode([0_u8; 16]));
    let error = service
        .upload_part(s3_request(replacement))
        .await
        .expect_err("mismatched replacement");
    assert_eq!(error.code().as_str(), "BadDigest");
    let listed = service
        .list_parts(s3_request(list_input(&id)))
        .await
        .expect("list retained part")
        .output
        .parts
        .expect("part list");
    assert_eq!(listed[0].e_tag, Some(part.clone()));

    let complete = service
        .complete_multipart_upload(s3_request(complete_input(&id, vec![(1, part)])))
        .await
        .expect("complete")
        .output;
    let expected = rs3_crypto::multipart_etag(&[rs3_crypto::md5(b"body")])
        .expect("one-part aggregate")
        .to_s3_string();
    assert_eq!(complete.e_tag, Some(ETag::Strong(expected)));
}

#[tokio::test]
async fn multipart_routes_replace_select_publish_and_repeat_without_overwriting() {
    let service = gateway_service().await;
    let id = create(&service).await;
    let first = part(&service, &id, 2, Bytes::from(vec![7; 5 * 1024 * 1024])).await;
    let old = part(&service, &id, 9, Bytes::from_static(b"old")).await;
    let last = part(&service, &id, 9, Bytes::from_static(b"tail")).await;
    assert_ne!(old, last);
    let page = service
        .list_parts(s3_request(ListPartsInput {
            max_parts: Some(1),
            ..list_input(&id)
        }))
        .await
        .expect("list")
        .output;
    assert_eq!(page.is_truncated, Some(true));
    assert_eq!(page.next_part_number_marker, Some(2));
    assert_eq!(page.parts.expect("parts")[0].part_number, Some(2));
    let page = service
        .list_parts(s3_request(ListPartsInput {
            part_number_marker: Some(2),
            ..list_input(&id)
        }))
        .await
        .expect("next")
        .output;
    assert_eq!(page.parts.expect("parts")[0].e_tag, Some(last.clone()));
    let stale = service
        .complete_multipart_upload(s3_request(complete_input(
            &id,
            vec![(2, first.clone()), (9, old)],
        )))
        .await
        .expect_err("stale token");
    assert_eq!(stale.code().as_str(), "InvalidPart");
    assert_eq!(accepted_v3_sequence(&service).await, 1);
    let request = complete_input(&id, vec![(2, first), (9, last)]);
    let result = service
        .complete_multipart_upload(s3_request(request.clone()))
        .await
        .expect("complete")
        .output;
    assert_eq!(accepted_v3_sequence(&service).await, 2);
    let get = service
        .get_object(s3_request(GetObjectInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            ..Default::default()
        }))
        .await
        .expect("get")
        .output;
    let bytes = collect_body(get.body, 6 * 1024 * 1024).await.expect("body");
    assert_eq!(bytes.len(), 5 * 1024 * 1024 + 4);
    assert_eq!(&bytes[5 * 1024 * 1024..], b"tail");
    service
        .put_object(s3_request(PutObjectInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            body: Some(body(Bytes::from_static(b"newer"))),
            ..Default::default()
        }))
        .await
        .expect("overwrite");
    let before = accepted_v3_sequence(&service).await;
    let retry = service
        .complete_multipart_upload(s3_request(request))
        .await
        .expect("durable retry")
        .output;
    assert_eq!(retry.e_tag, result.e_tag);
    assert_eq!(accepted_v3_sequence(&service).await, before);
    let error = service
        .list_parts(s3_request(list_input(&id)))
        .await
        .expect_err("completed");
    assert_eq!(error.code().as_str(), "NoSuchUpload");
}

#[tokio::test]
async fn multipart_parallel_parts_and_completion_freeze() {
    let service = gateway_service().await;
    let id = create(&service).await;
    let barrier = Arc::new(Barrier::new(2));
    let make = |number| {
        let barrier = Arc::clone(&barrier);
        let body = StreamingBlob::wrap(futures_util::stream::once(async move {
            barrier.wait().await;
            Ok::<_, std::io::Error>(Bytes::from_static(b"part"))
        }));
        service.upload_part(s3_request(part_input(&id, number, body, 4)))
    };
    let (a, b) = bounded(async { tokio::join!(make(1), make(2)) }).await;
    let a = a.expect("parallel first").output.e_tag.expect("etag");
    b.expect("parallel second");
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let entered_body = Arc::clone(&entered);
    let release_body = Arc::clone(&release);
    let input = part_input(
        &id,
        3,
        StreamingBlob::wrap(futures_util::stream::once(async move {
            entered_body.notify_one();
            release_body.notified().await;
            Ok::<_, std::io::Error>(Bytes::from_static(b"pending"))
        })),
        7,
    );
    let writer = tokio::spawn({
        let service = service.clone();
        async move { service.upload_part(s3_request(input)).await }
    });
    bounded(entered.notified()).await;
    let completion = tokio::spawn({
        let service = service.clone();
        let request = complete_input(&id, vec![(1, a)]);
        async move { service.complete_multipart_upload(s3_request(request)).await }
    });
    tokio::task::yield_now().await;
    assert!(!completion.is_finished());
    assert_eq!(accepted_v3_sequence(&service).await, 1);
    release.notify_one();
    bounded(writer).await.expect("writer task").expect("part");
    bounded(completion)
        .await
        .expect("completion task")
        .expect("complete selected subset");
    assert_eq!(accepted_v3_sequence(&service).await, 2);
}

#[tokio::test]
async fn multipart_invalid_selection_keeps_session_and_empty_completion_is_index_only() {
    let service = gateway_service().await;
    let id = create(&service).await;
    let a = part(&service, &id, 1, Bytes::from_static(b"small")).await;
    let b = part(&service, &id, 2, Bytes::new()).await;
    for (parts, code) in [
        (vec![(2, b.clone()), (1, a.clone())], "InvalidPartOrder"),
        (vec![(1, a), (2, b.clone())], "EntityTooSmall"),
        (vec![], "InvalidRequest"),
    ] {
        let error = service
            .complete_multipart_upload(s3_request(complete_input(&id, parts)))
            .await
            .expect_err("invalid selection");
        assert_eq!(error.code().as_str(), code);
    }
    let mut request = complete_input(&id, vec![(2, b)]);
    request.mpu_object_size = Some(1);
    assert!(
        service
            .complete_multipart_upload(s3_request(request.clone()))
            .await
            .is_err()
    );
    request.mpu_object_size = Some(0);
    service
        .complete_multipart_upload(s3_request(request))
        .await
        .expect("empty completion");
    let store = service.repository.memory_store().expect("memory");
    assert!(
        store
            .list_prefix("objects/v03/")
            .await
            .expect("objects")
            .is_empty()
    );
    let metadata = service
        .head_object(s3_request(HeadObjectInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            ..Default::default()
        }))
        .await
        .expect("head")
        .output;
    assert_eq!(metadata.content_length, Some(0));
}

#[tokio::test]
async fn multipart_accepts_but_does_not_persist_custom_metadata() {
    let service = gateway_service().await;
    let created = service
        .create_multipart_upload(s3_request(CreateMultipartUploadInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            metadata: Some(std::collections::HashMap::from([(
                "arbitrary-client-metadata".to_owned(),
                "accepted-but-not-retained".to_owned(),
            )])),
            ..Default::default()
        }))
        .await
        .expect("metadata-bearing create")
        .output;
    let id = created.upload_id.expect("upload id");
    let bytes = Bytes::from_static(b"multipart metadata");
    let part_etag = part(&service, &id, 1, bytes.clone()).await;
    let completed = service
        .complete_multipart_upload(s3_request(complete_input(&id, vec![(1, part_etag)])))
        .await
        .expect("metadata-bearing completion")
        .output;
    let expected_etag = ETag::Strong(
        rs3_crypto::multipart_etag(&[rs3_crypto::md5(bytes.as_ref())])
            .expect("one-part aggregate")
            .to_s3_string(),
    );
    assert_eq!(completed.e_tag, Some(expected_etag));
    assert_eq!(
        response_body(
            service
                .get_object(s3_request(GetObjectInput {
                    bucket: "client-bucket".into(),
                    key: KEY.into(),
                    ..Default::default()
                }))
                .await
                .expect("completed object"),
        )
        .await,
        bytes
    );
    let head = service
        .head_object(s3_request(HeadObjectInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            ..Default::default()
        }))
        .await
        .expect("head")
        .output;
    assert!(head.metadata.is_none());
}

#[tokio::test]
async fn multipart_rejects_wrong_identity_readonly_and_invalid_body() {
    let mut service = gateway_service().await;
    let id = create(&service).await;
    let error = service
        .upload_part(s3_request(UploadPartInput {
            key: "other/key".into(),
            ..part_input(&id, 1, body(Bytes::new()), 0)
        }))
        .await
        .expect_err("wrong key");
    assert_eq!(error.code().as_str(), "NoSuchUpload");
    for (bytes, len) in [(b"abc".as_slice(), 2), (b"a".as_slice(), 2)] {
        let error = service
            .upload_part(s3_request(part_input(
                &id,
                1,
                body(Bytes::copy_from_slice(bytes)),
                len,
            )))
            .await
            .expect_err("length");
        assert_eq!(error.code().as_str(), "IncompleteBody");
    }
    for number in [0, 10001, -1] {
        assert!(
            service
                .upload_part(s3_request(part_input(&id, number, body(Bytes::new()), 0)))
                .await
                .is_err()
        );
    }
    service.mode = GatewayMode::RestoreReadOnly;
    for error in [
        service
            .create_multipart_upload(s3_request(CreateMultipartUploadInput {
                bucket: "client-bucket".into(),
                key: KEY.into(),
                ..Default::default()
            }))
            .await
            .expect_err("readonly create"),
        service
            .upload_part(s3_request(part_input(&id, 1, body(Bytes::new()), 0)))
            .await
            .expect_err("readonly part"),
        service
            .complete_multipart_upload(s3_request(complete_input(&id, vec![])))
            .await
            .expect_err("readonly complete"),
        service
            .abort_multipart_upload(s3_request(AbortMultipartUploadInput {
                bucket: "client-bucket".into(),
                key: KEY.into(),
                upload_id: id.clone(),
                ..Default::default()
            }))
            .await
            .expect_err("readonly abort"),
    ] {
        assert_eq!(error.code().as_str(), "AccessDenied");
    }
    service
        .list_parts(s3_request(list_input(&id)))
        .await
        .expect("readonly list");
}

#[tokio::test(start_paused = true)]
async fn multipart_expiry_and_admission_release_session_and_part_slots() {
    let mut service = gateway_service().await;
    service.multipart =
        super::super::multipart::MultipartSessions::with_limits(1, 1, Duration::from_secs(10));
    let id = create(&service).await;
    let error = service
        .create_multipart_upload(s3_request(CreateMultipartUploadInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            ..Default::default()
        }))
        .await
        .expect_err("session cap");
    assert_eq!(error.code().as_str(), "SlowDown");
    part(&service, &id, 1, Bytes::from_static(b"first")).await;
    part(&service, &id, 1, Bytes::from_static(b"replacement")).await;
    let error = service
        .upload_part(s3_request(part_input(&id, 2, body(Bytes::new()), 0)))
        .await
        .expect_err("part budget");
    assert_eq!(error.code().as_str(), "SlowDown");
    tokio::time::advance(Duration::from_secs(11)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    let error = service
        .list_parts(s3_request(list_input(&id)))
        .await
        .expect_err("expired");
    assert_eq!(error.code().as_str(), "NoSuchUpload");
    let next = create(&service).await;
    part(&service, &next, 1, Bytes::from_static(b"new")).await;
    service
        .abort_multipart_upload(s3_request(AbortMultipartUploadInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            upload_id: next.clone(),
            ..Default::default()
        }))
        .await
        .expect("abort");
    assert!(
        service
            .list_parts(s3_request(list_input(&next)))
            .await
            .is_err()
    );
    assert_eq!(accepted_v3_sequence(&service).await, 1);
}

#[tokio::test]
async fn multipart_owned_part_finishes_after_request_waiter_cancellation() {
    let service = gateway_service().await;
    let id = create(&service).await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let signal = Arc::clone(&entered);
    let waiter = Arc::clone(&release);
    let body = StreamingBlob::wrap(futures_util::stream::once(async move {
        signal.notify_one();
        waiter.notified().await;
        Ok::<_, std::io::Error>(Bytes::from_static(b"body"))
    }));
    let input = part_input(&id, 1, body, 4);
    let before = service.request_slots.available_permits();
    let request = tokio::spawn({
        let service = service.clone();
        async move { service.upload_part(s3_request(input)).await }
    });
    bounded(entered.notified()).await;
    request.abort();
    assert!(request.await.expect_err("cancelled waiter").is_cancelled());
    assert_eq!(service.request_slots.available_permits(), before - 1);
    release.notify_one();
    bounded(async {
        loop {
            let listed = service
                .list_parts(s3_request(list_input(&id)))
                .await
                .expect("list")
                .output
                .parts
                .expect("parts");
            if !listed.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(service.request_slots.available_permits(), before);
    assert_eq!(accepted_v3_sequence(&service).await, 1);
}

#[tokio::test]
async fn multipart_replacements_serialize_and_duplicate_completions_publish_once() {
    let service = gateway_service().await;
    let id = create(&service).await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let signal = Arc::clone(&entered);
    let released = Arc::clone(&release);
    let input = part_input(
        &id,
        1,
        StreamingBlob::wrap(futures_util::stream::once(async move {
            signal.notify_one();
            released.notified().await;
            Ok::<_, std::io::Error>(Bytes::from_static(b"old"))
        })),
        3,
    );
    let initial_permits = service.request_slots.available_permits();
    let first = tokio::spawn({
        let service = service.clone();
        async move { service.upload_part(s3_request(input)).await }
    });
    bounded(entered.notified()).await;
    let second_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::clone(&second_read);
    let input = part_input(
        &id,
        1,
        StreamingBlob::wrap(futures_util::stream::once(async move {
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, std::io::Error>(Bytes::from_static(b"new"))
        })),
        3,
    );
    let second = tokio::spawn({
        let service = service.clone();
        async move { service.upload_part(s3_request(input)).await }
    });
    bounded(async {
        while service.request_slots.available_permits() != initial_permits - 2 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(!second_read.load(std::sync::atomic::Ordering::SeqCst));
    release.notify_one();
    let first = bounded(first)
        .await
        .expect("first task")
        .expect("first")
        .output
        .e_tag
        .expect("etag");
    let second = bounded(second)
        .await
        .expect("second task")
        .expect("second")
        .output
        .e_tag
        .expect("etag");
    assert_ne!(first, second);
    let request = complete_input(&id, vec![(1, second)]);
    let (a, b) = tokio::join!(
        service.complete_multipart_upload(s3_request(request.clone())),
        service.complete_multipart_upload(s3_request(request))
    );
    assert_eq!(
        a.expect("completion").output.e_tag,
        b.expect("repeat").output.e_tag
    );
    assert_eq!(accepted_v3_sequence(&service).await, 2);
}

#[tokio::test]
async fn multipart_complete_conditions_and_frontend_limits_precede_publication() {
    let mut service = gateway_service().await;
    let id = create(&service).await;
    let too_large = service
        .upload_part(s3_request(part_input(
            &id,
            1,
            body(Bytes::new()),
            5 * 1024 * 1024 * 1024,
        )))
        .await
        .expect_err("ciphertext overhead");
    assert_eq!(too_large.code().as_str(), "EntityTooLarge");
    let etag = part(&service, &id, 1, Bytes::from_static(b"three")).await;
    service.max_put_object_bytes = 4;
    let request = complete_input(&id, vec![(1, etag)]);
    let error = service
        .complete_multipart_upload(s3_request(request.clone()))
        .await
        .expect_err("logical object cap");
    assert_eq!(error.code().as_str(), "EntityTooLarge");
    service.max_put_object_bytes = 10;
    service
        .put_object(s3_request(PutObjectInput {
            bucket: "client-bucket".into(),
            key: KEY.into(),
            body: Some(body(Bytes::from_static(b"newer"))),
            ..Default::default()
        }))
        .await
        .expect("racing value");
    let before = accepted_v3_sequence(&service).await;
    let mut request = request;
    request.if_none_match = Some(ETagCondition::Any);
    let error = service
        .complete_multipart_upload(s3_request(request))
        .await
        .expect_err("create-only race");
    assert_eq!(error.code().as_str(), "PreconditionFailed");
    assert_eq!(accepted_v3_sequence(&service).await, before);
}
