#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT_LEN: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }

    if let Ok(envelope) = rs3_crypto::fuzzing::parse_keyring_envelope_object(data) {
        let encoded = envelope
            .to_object_bytes()
            .unwrap_or_else(|error| panic!("parsed keyring envelope failed to re-encode: {error}"));
        let decoded = rs3_crypto::fuzzing::parse_keyring_envelope_object(&encoded)
            .unwrap_or_else(|error| panic!("re-encoded keyring envelope failed to parse: {error}"));
        assert_eq!(decoded, envelope);
    }

    let _ = rs3_crypto::fuzzing::parse_keyring_plaintext(data);
});
