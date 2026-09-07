#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rs3_repository::v2::fuzzing::decode_canonical_cbor(data);
});
