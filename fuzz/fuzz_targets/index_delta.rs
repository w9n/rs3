#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rs3_repository::v2::fuzzing::decode_index_delta_object(data);
});
