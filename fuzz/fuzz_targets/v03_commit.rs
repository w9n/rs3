#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rs3_repository::v3::fuzzing::parse_v03_commit_header_bytes(data);
    rs3_repository::v3::fuzzing::parse_v03_commit_object_bytes(data);
    rs3_repository::v3::fuzzing::round_trip_v03_commit_structure(data);
});
