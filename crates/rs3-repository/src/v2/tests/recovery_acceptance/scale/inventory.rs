//! Signed section-size audit outside measured provider traffic.
use super::*;

impl Scale {
    pub(super) async fn record_inventory(&self, stage: &str) {
        let before = self.counts();
        let reader = self
            .repository
            .commit_store()
            .rebind_store(self.backend.clone());
        let mut sizes = std::collections::BTreeMap::<&str, u64>::new();
        let mut counts = std::collections::BTreeMap::<&str, u64>::new();
        let mut total = 0;
        for metadata in self.backend.inventory() {
            total += metadata.content_len;
            if V2CommitKey::parse(&metadata.object_id).is_err() {
                *sizes.entry("other").or_default() += metadata.content_len;
                continue;
            }
            let header = must_v2(
                reader
                    .read_commit_header_at(&metadata.object_id, metadata.version_id.as_ref())
                    .await,
            );
            let mut accounted = header.sections_start as u64;
            *sizes.entry("header_and_padding").or_default() += accounted;
            for section in &header.header.section_index {
                let name = match section.section_type {
                    V2SectionType::IndexRun => "index_run",
                    V2SectionType::IndexRoot => "index_root",
                    V2SectionType::Recovery => "recovery",
                    V2SectionType::PayloadPack => "payload_pack",
                    _ => panic!("unexpected scale section"),
                };
                *sizes.entry(name).or_default() += section.length;
                *counts.entry(name).or_default() += 1;
                accounted += section.length;
            }
            assert_eq!(
                accounted, metadata.content_len,
                "complete physical byte attribution"
            );
        }
        assert_eq!(sizes.values().sum::<u64>(), total);
        assert_eq!(total, self.backend.occupancy().1);
        assert_eq!(
            self.counts().bytes_read,
            before.bytes_read,
            "audit outside measured I/O"
        );
        println!(
            "HISTORY_SCALE {}",
            json!({"phase":"section_inventory", "stage":stage,
            "mode":self.mode, "bytes":sizes, "section_counts":counts,
            "stored_bytes":total, "audit_io_excluded":true})
        );
    }
}
