#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT_LEN: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_LEN {
        return;
    }

    for purpose in [
        rs3_crypto::EnvelopePurpose::Keyring,
        rs3_crypto::EnvelopePurpose::Format,
    ] {
        if let Ok(envelope) = rs3_crypto::fuzzing::parse_repository_envelope_object(data, purpose) {
            let encoded = envelope.to_object_bytes().unwrap_or_else(|error| {
                panic!("parsed keyring envelope failed to re-encode: {error}")
            });
            let decoded = rs3_crypto::fuzzing::parse_repository_envelope_object(&encoded, purpose)
                .unwrap_or_else(|error| {
                    panic!("re-encoded keyring envelope failed to parse: {error}")
                });
            assert_eq!(decoded, envelope);
            let context =
                rs3_crypto::RepositoryKeyContext::new(envelope.repository_id.clone(), vec![2; 32])
                    .expect("fixture context");
            let wrapping = rs3_crypto::SecretBytes::new(vec![9; 32]).expect("fixture key");
            match purpose {
                rs3_crypto::EnvelopePurpose::Keyring => {
                    let _ = decoded.open_keyring(&context, "wrap-v1", &wrapping);
                }
                rs3_crypto::EnvelopePurpose::Format => {
                    let _ = decoded.open_format(&context, "wrap-v1", &wrapping);
                }
            }
        }
    }
    let _ = rs3_crypto::fuzzing::parse_keyring_plaintext(data);
});
