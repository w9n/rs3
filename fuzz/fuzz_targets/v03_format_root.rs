#![no_main]
use libfuzzer_sys::fuzz_target;
use rs3_repository::v3::V3FormatRoot;

fuzz_target!(|data: &[u8]| {
    if let Ok(root) = V3FormatRoot::from_plaintext_bytes(data) {
        let encoded = root
            .to_plaintext_bytes()
            .expect("parsed format root encodes");
        assert_eq!(encoded, data);
    }
});
