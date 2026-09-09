//! Shared integration-test helpers for storage backends.

use bytes::Bytes;
use rs3_storage::{BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::{BackendObjectId, LegalHoldStatus, RetentionMode, RetentionPolicy};

/// Builds a backend object ID or panics with the validation error.
pub(crate) fn object_id(value: &str) -> BackendObjectId {
    BackendObjectId::new(value).unwrap_or_else(|error| panic!("{error}"))
}

/// Verifies the core `BlobStore` behavior with configurable duplicate
/// create-only semantics for provider qualification profiles.
pub(crate) async fn assert_core_blob_store_contract_with_create_only<S>(
    store: &S,
    scope: &str,
    require_duplicate_rejection: bool,
) where
    S: BlobStore + ?Sized,
{
    let scope = normalize_scope(scope);
    let first = object_id(&format!("{scope}/segments/first"));
    let second = object_id(&format!("{scope}/segments/second"));
    let outside = object_id(&format!("{scope}/index/outside"));

    store
        .put(
            &first,
            Bytes::from_static(b"hello live s3 backend"),
            PutOptions {
                do_not_recreate: true,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("put first object: {error}"));
    store
        .put(
            &second,
            Bytes::from_static(b"another object"),
            PutOptions::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("put second object: {error}"));
    store
        .put(
            &outside,
            Bytes::from_static(b"outside listing prefix"),
            PutOptions::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("put outside object: {error}"));

    let metadata = store
        .head(&first)
        .await
        .unwrap_or_else(|error| panic!("head first object: {error}"));
    assert_eq!(metadata.object_id, first);
    assert_eq!(metadata.content_len, 21);

    let full = store
        .get_range(&first, ByteRange::Full)
        .await
        .unwrap_or_else(|error| panic!("get full object: {error}"));
    assert_eq!(full, Bytes::from_static(b"hello live s3 backend"));

    let range = store
        .get_range(&first, ByteRange::Slice { offset: 6, len: 4 })
        .await
        .unwrap_or_else(|error| panic!("get object range: {error}"));
    assert_eq!(range, Bytes::from_static(b"live"));

    let list_prefix = format!("{scope}/segments/");
    let listed = store
        .list_prefix(&list_prefix)
        .await
        .unwrap_or_else(|error| panic!("list object prefix: {error}"));
    let listed_ids = listed
        .into_iter()
        .map(|metadata| metadata.object_id)
        .collect::<Vec<_>>();
    assert_eq!(listed_ids, vec![first.clone(), second.clone()]);

    for (prefix, expected) in [
        (format!("{scope}/segments/fir"), vec![first.clone()]),
        (first.as_str().to_owned(), vec![first.clone()]),
        (format!("{scope}/seg"), vec![first.clone(), second.clone()]),
        (format!("{scope}/missing"), vec![]),
    ] {
        let listed = store.list_prefix(&prefix).await.expect("string prefix");
        assert_eq!(
            listed
                .into_iter()
                .map(|entry| entry.object_id)
                .collect::<Vec<_>>(),
            expected
        );
        let mut pages = store
            .open_bounded_list(&prefix, rs3_storage::BlobListMode::Current)
            .await
            .expect("bounded string prefix");
        let limit = std::num::NonZeroUsize::new(1).expect("nonzero");
        let mut listed = Vec::new();
        let mut complete = false;
        for _ in 0..32 {
            let page = pages.next_page(limit).await.expect("bounded prefix page");
            assert!(page.entries.len() <= page.consumed_items);
            assert!(page.consumed_items <= 1);
            listed.extend(page.entries.into_iter().map(|entry| entry.object_id));
            if page.is_complete {
                complete = true;
                break;
            }
        }
        assert!(complete, "listing did not finish within the fixture budget");
        listed.sort();
        assert_eq!(listed, expected);
    }
    for range in [
        ByteRange::Slice { offset: 99, len: 1 },
        ByteRange::Slice {
            offset: u64::MAX,
            len: 2,
        },
    ] {
        assert_eq!(
            store.get_range(&first, range).await,
            Err(StorageError::InvalidRange)
        );
    }

    let duplicate = store
        .put(
            &first,
            Bytes::from_static(b"must not overwrite"),
            PutOptions {
                do_not_recreate: true,
                ..PutOptions::default()
            },
        )
        .await;
    if require_duplicate_rejection {
        assert!(matches!(duplicate, Err(StorageError::AlreadyExists(_))));
    } else {
        match duplicate {
            Ok(_) | Err(StorageError::AlreadyExists(_)) => {}
            Err(error) => panic!("duplicate create-only probe failed unexpectedly: {error}"),
        }
    }

    store
        .delete(&first)
        .await
        .unwrap_or_else(|error| panic!("delete first object: {error}"));
    assert!(matches!(
        store.head(&first).await,
        Err(StorageError::NotFound(_))
    ));

    cleanup(store, &[second, outside]).await;
}

async fn cleanup<S>(store: &S, object_ids: &[BackendObjectId])
where
    S: BlobStore + ?Sized,
{
    for object_id in object_ids {
        let _ = store.delete(object_id).await;
    }
}

fn normalize_scope(scope: &str) -> String {
    let scope = scope.trim_matches('/');
    if scope.is_empty() {
        "contract".to_owned()
    } else {
        scope.to_owned()
    }
}

/// Checks exact-version protection below a current delete marker.
pub(crate) async fn assert_current_delete_preserves_protected_versions<S: BlobStore + ?Sized>(
    store: &S,
    scope: &str,
) {
    for (index, (retention, legal_hold, expected_error)) in [
        (
            Some(RetentionPolicy::new(RetentionMode::Compliance, 1)),
            None,
            StorageError::RetentionBlocked,
        ),
        (
            None,
            Some(LegalHoldStatus::On),
            StorageError::LegalHoldBlocked,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let prefix = format!("{scope}/history-{index}/");
        let key = object_id(&format!("{prefix}object"));
        let old = store
            .put(
                &key,
                Bytes::from_static(b"protected"),
                PutOptions {
                    retention,
                    legal_hold,
                    ..PutOptions::default()
                },
            )
            .await
            .expect("protected version");
        let current = store
            .put(&key, Bytes::from_static(b"current"), PutOptions::default())
            .await
            .expect("current version");
        store.delete(&key).await.expect("delete current value");
        assert!(matches!(
            store.head(&key).await,
            Err(StorageError::NotFound(_))
        ));
        assert!(matches!(
            store.get_range(&key, ByteRange::Full).await,
            Err(StorageError::NotFound(_))
        ));
        assert!(
            store
                .list_prefix(&prefix)
                .await
                .expect("current list")
                .is_empty()
        );
        assert_eq!(
            store
                .get_range_at(&key, old.version_id.as_ref(), ByteRange::Full)
                .await
                .expect("protected history"),
            Bytes::from_static(b"protected")
        );
        assert_eq!(
            store.delete_at(&key, old.version_id.as_ref()).await,
            Err(expected_error)
        );
        store
            .delete_at(&key, current.version_id.as_ref())
            .await
            .expect("delete unprotected exact version");
        assert!(
            matches!(store.head(&key).await, Err(StorageError::NotFound(_))),
            "deleting a version below a marker must not resurrect older data"
        );
        let recreated = store
            .put(
                &key,
                Bytes::from_static(b"recreated"),
                PutOptions {
                    do_not_recreate: true,
                    ..PutOptions::default()
                },
            )
            .await
            .expect("create over marker");
        assert!(old.version_id.is_some());
        assert!(recreated.version_id.is_some());
        assert_ne!(recreated.version_id, old.version_id);
        let mut inventory = store
            .open_bounded_list(&prefix, rs3_storage::BlobListMode::Versions)
            .await
            .expect("version pages");
        let mut consumed = 0;
        let mut exact_versions = Vec::new();
        let mut complete = false;
        for _ in 0..8 {
            let page = inventory
                .next_page(std::num::NonZeroUsize::new(1).expect("limit"))
                .await
                .expect("version page");
            assert!(page.entries.len() <= page.consumed_items);
            assert!(page.consumed_items <= 1);
            consumed += page.consumed_items;
            exact_versions.extend(page.entries.into_iter().map(|entry| entry.version_id));
            if page.is_complete {
                complete = true;
                break;
            }
        }
        assert!(complete);
        assert_eq!(consumed, 3, "two values and a delete marker");
        assert_eq!(exact_versions.len(), 2);
        assert!(exact_versions.contains(&old.version_id));
        assert!(exact_versions.contains(&recreated.version_id));
        assert_eq!(
            store
                .list_prefix_versions(&prefix)
                .await
                .expect("history inventory")
                .len(),
            2
        );
        assert_eq!(
            store
                .get_range(&key, ByteRange::Full)
                .await
                .expect("new current"),
            Bytes::from_static(b"recreated")
        );
    }
}

/// Rejected internal multipart parts must not mutate an accepted part.
pub(crate) async fn assert_multipart_rejection_preserves_parts<S: BlobStore + ?Sized>(
    store: &S,
    scope: &str,
) {
    let key = object_id(&format!("{scope}/multipart-rejection"));
    let mut upload = store
        .create_multipart_upload(&key, PutOptions::default())
        .await
        .expect("multipart session");
    upload
        .put_part(0, Bytes::from_static(b"original"))
        .await
        .expect("first part");
    assert!(
        matches!(upload.put_part(0, Bytes::from_static(b"replacement")).await,
        Err(StorageError::Provider(reason)) if reason == "multipart part was uploaded twice")
    );
    for index in [10_000, usize::MAX] {
        assert!(
            matches!(upload.put_part(index, Bytes::from_static(b"invalid")).await,
            Err(StorageError::Provider(reason)) if reason == "multipart part number is out of range")
        );
    }
    let metadata = upload.complete().await.expect("complete original upload");
    assert_eq!(metadata.content_len, 8);
    assert_eq!(
        store
            .get_range(&key, ByteRange::Full)
            .await
            .expect("read original part"),
        Bytes::from_static(b"original")
    );
    store
        .delete_at(&key, metadata.version_id.as_ref())
        .await
        .expect("cleanup completed upload");

    let mut upload = store
        .create_multipart_upload(&key, PutOptions::default())
        .await
        .expect("boundary session");
    upload
        .put_part(9_999, Bytes::from_static(b"last permitted part"))
        .await
        .expect("maximum part index is accepted before completion");
    upload
        .abort()
        .await
        .expect("abort incomplete boundary session");
}
