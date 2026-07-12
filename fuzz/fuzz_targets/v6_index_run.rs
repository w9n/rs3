#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rs3_repository::v2::fuzzing::decode_v6_index_run(data);
});
