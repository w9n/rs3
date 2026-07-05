#![no_main]

use libfuzzer_sys::fuzz_target;
use rs3_repository::v2::V2RecoveryBundle;

const MAX_FUZZ_INPUT_LEN: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }

    let Ok(bundle) = serde_json::from_slice::<V2RecoveryBundle>(data) else {
        return;
    };
    let encoded = serde_json::to_vec(&bundle)
        .unwrap_or_else(|error| panic!("parsed restore bundle failed to re-encode: {error}"));
    let decoded = serde_json::from_slice::<V2RecoveryBundle>(&encoded)
        .unwrap_or_else(|error| panic!("re-encoded restore bundle failed to parse: {error}"));
    assert_eq!(decoded, bundle);
});
