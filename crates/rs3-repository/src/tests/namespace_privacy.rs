use super::*;

#[test]
fn prefix_tokens_include_root_and_delimiter_prefixes() {
    let keyring = KeyRing::single_namespace(secret());
    let tokens = prefix_tokens_for_key(&keyring, &primary_key_id(&keyring), "p/12/abcdef")
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(tokens.len(), 3);
}

#[test]
fn indexed_list_prefix_classifies_fallback_without_prefix_value() {
    assert_eq!(indexed_list_prefix(""), "");
    assert_eq!(indexed_list_prefix_mode("").as_str(), "root");
    assert_eq!(indexed_list_prefix("p/12/"), "p/12/");
    assert_eq!(indexed_list_prefix_mode("p/12/").as_str(), "delimiter");
    assert_eq!(indexed_list_prefix("p/12"), "p/");
    assert_eq!(
        indexed_list_prefix_mode("p/12").as_str(),
        "parent_delimiter_fallback"
    );
    assert_eq!(indexed_list_prefix("p/12/abc"), "p/12/");
    assert_eq!(
        indexed_list_prefix_mode("p/12/abc").as_str(),
        "parent_delimiter_fallback"
    );
    assert_eq!(indexed_list_prefix("p12"), "");
    assert_eq!(indexed_list_prefix_mode("p12").as_str(), "root_fallback");
}

#[tokio::test]
async fn backend_object_ids_do_not_contain_client_key() {
    let store = MemoryBlobStore::new();
    let repo = Repository::new(store.clone(), secret());
    let client_key = key("p/12/sensitive-client-blob");

    let put = repo
        .put(
            client_key,
            Bytes::from_static(b"hello"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let backend_objects = store.list_prefix("segments/").await;
    let object_ids = must_storage(backend_objects)
        .into_iter()
        .map(|metadata| metadata.object_id.to_string())
        .collect::<Vec<_>>();

    assert_eq!(object_ids.len(), 1);
    assert!(!object_ids[0].contains("sensitive"));
    assert!(!object_ids[0].contains("client-blob"));
}

#[tokio::test]
async fn publish_checkpoint_embeds_index_delta_without_client_key_material() {
    let store = MemoryBlobStore::new();
    let repo = Repository::with_keyring(store.clone(), signing_keyring());
    let anchor = MemoryCheckpointAnchor::new();
    let client_key = key("p/12/sensitive-client-blob");

    let put = repo
        .put(
            client_key,
            Bytes::from_static(b"body"),
            RepositoryPutOptions::default(),
        )
        .await;
    assert!(put.is_ok());

    let position = must(repo.publish_checkpoint(&anchor).await);
    let checkpoint_object_id = must(checkpoint_object_id(&position.checkpoint_id));
    let checkpoint_body = must_storage(
        store
            .get_range(&checkpoint_object_id, ByteRange::Full)
            .await,
    );
    let checkpoint = decode_checkpoint_object(checkpoint_body.clone());
    let delta_objects = must_storage(store.list_prefix("index/").await);
    let manifest_objects = must_storage(store.list_prefix("manifests/").await);

    assert!(checkpoint.record.index_deltas.is_empty());
    assert!(checkpoint.record.inline_index_delta.is_some());
    assert!(delta_objects.is_empty());
    assert!(manifest_objects.is_empty());
    assert_body_does_not_contain(&checkpoint_body, &["sensitive", "client-blob", "p/12"]);
    assert_body_does_not_contain(
        &checkpoint_body,
        &[
            "blind_key",
            "prefix_tokens",
            "content_len",
            "modified_at_ms",
            "generation",
            "sealed_manifest",
        ],
    );
}
