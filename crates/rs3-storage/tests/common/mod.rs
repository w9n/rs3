//! Shared integration-test helpers for storage backends.

use bytes::Bytes;
use rs3_storage::{BlobStore, ByteRange, PutOptions, StorageError};
use rs3_types::BackendObjectId;

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
