#![no_main]
use libfuzzer_sys::fuzz_target;
use rs3_repository::v2::V2FormatRoot;

fuzz_target!(|data: &[u8]| {
    if let Ok(root) = V2FormatRoot::from_plaintext_bytes(data) {
        let encoded = root
            .to_plaintext_bytes()
            .expect("parsed format root encodes");
        assert_eq!(encoded, data);
    }
});
