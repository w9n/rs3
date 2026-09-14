//! Bounded authenticated history plaintext. Decoding establishes no accepted-head
//! authority: the caller validates the enclosing commit and applies its transition
//! once. Reading a historical page never follows that section's old snapshot.

use super::policy::RecoveryPolicy;
use crate::v3::{
    V3AnchorState, V3CommitKey, V3CommitParentRef, V3FormatError, V3FormatRef, V3Result, cbor,
};
use rs3_types::{BackendObjectId, BackendVersionId, KeyId, Sequence};
use std::fmt;

pub(in crate::v3) const MAX_RECOVERY_SECTION_BYTES: usize = 8 * 1024 * 1024;
pub(in crate::v3) const MAX_RECOVERY_TAIL_RECORDS: usize = 4_096;
pub(in crate::v3) const MAX_RECOVERY_PAGES: usize = 1_024;
pub(in crate::v3) const MAX_RECOVERY_PAGE_RECORDS: usize = 4_096;
const WIRE_VERSION: u64 = 1;
const MAX_OBJECT_ID_BYTES: usize = 1_024;
const MAX_VERSION_ID_BYTES: usize = 1_024;
const MAX_KEY_ID_BYTES: usize = 255;

/// A fixed promise for one superseded accepted point, not an observed backend lock.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::v3) struct RecoveryPoint {
    pub anchor: V3AnchorState,
    pub publish_time_ms: i64,
    pub protected_until_ms: i64,
    pub policy_id: [u8; 32],
}

impl fmt::Debug for RecoveryPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryPoint")
            .field("sequence", &self.anchor.sequence)
            .field("publish_time_ms", &self.publish_time_ms)
            .field("protected_until_ms", &self.protected_until_ms)
            .finish_non_exhaustive()
    }
}

/// Only explicit accepted transitions can expire promises or move the active tail.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::v3) struct RecoveryDelta {
    pub register: Option<RecoveryPoint>,
    pub expire_before_ms: Option<i64>,
    /// Index of a local page containing exactly the surviving prior active tail.
    pub roll_tail: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::v3) struct RecoveryPage {
    pub points: Vec<RecoveryPoint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::v3) struct RecoveryPageClaims {
    pub record_count: u32,
    pub first_sequence: Sequence,
    pub last_sequence: Sequence,
    pub minimum_deadline_ms: i64,
    pub maximum_deadline_ms: i64,
}

/// Exact references locate a signed section descriptor, not an unchecked offset.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::v3) enum RecoveryPageLocation {
    /// Valid only in the authenticated section containing this page.
    ThisSection { page_index: u32 },
    Exact {
        anchor: V3AnchorState,
        section_ordinal: u32,
        page_index: u32,
    },
}

impl fmt::Debug for RecoveryPageLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThisSection { page_index } => {
                f.debug_tuple("ThisSection").field(page_index).finish()
            }
            Self::Exact {
                anchor,
                section_ordinal,
                page_index,
            } => f
                .debug_struct("Exact")
                .field("sequence", &anchor.sequence)
                .field("section_ordinal", section_ordinal)
                .field("page_index", page_index)
                .finish(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::v3) struct RecoveryPageRef {
    pub location: RecoveryPageLocation,
    pub claims: RecoveryPageClaims,
}

/// The post-transition registry at a root. Its authority comes from accepted
/// enclosing state, never merely from decoding or selecting a historical point.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::v3) struct RecoverySnapshot {
    pub pages: Vec<RecoveryPageRef>,
    pub tail: Vec<RecoveryPoint>,
    pub expire_before_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::v3) struct RecoverySection {
    /// Governs the new current point, including its future supersession promise.
    pub current_policy: RecoveryPolicy,
    pub delta: RecoveryDelta,
    pub snapshot: Option<RecoverySnapshot>,
    pub local_pages: Vec<RecoveryPage>,
}

impl RecoveryPage {
    pub fn claims(&self) -> V3Result<RecoveryPageClaims> {
        validate_points(&self.points, MAX_RECOVERY_PAGE_RECORDS)?;
        let first = self
            .points
            .first()
            .ok_or(V3FormatError::InvalidRecoveryHistory)?;
        let last = self
            .points
            .last()
            .ok_or(V3FormatError::InvalidRecoveryHistory)?;
        let mut minimum = first.protected_until_ms;
        let mut maximum = minimum;
        for point in &self.points {
            minimum = minimum.min(point.protected_until_ms);
            maximum = maximum.max(point.protected_until_ms);
        }
        Ok(RecoveryPageClaims {
            record_count: u32::try_from(self.points.len())
                .map_err(|_| V3FormatError::RecoveryHistoryCapacity)?,
            first_sequence: first.anchor.sequence,
            last_sequence: last.anchor.sequence,
            minimum_deadline_ms: minimum,
            maximum_deadline_ms: maximum,
        })
    }
}

impl RecoveryPageRef {
    /// Called after the exact carrier section has authenticated and decoded.
    pub fn verify_page(&self, page: &RecoveryPage) -> V3Result<()> {
        if self.claims != page.claims()? {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        Ok(())
    }
}

impl RecoverySnapshot {
    pub fn validate_normalized(&self) -> V3Result<()> {
        validate_snapshot(self)?;
        if self
            .pages
            .iter()
            .any(|page| matches!(page.location, RecoveryPageLocation::ThisSection { .. }))
        {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        Ok(())
    }
}

impl RecoverySection {
    pub fn encode(&self) -> V3Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::default();
        writer.array(5)?;
        writer.u64(WIRE_VERSION)?;
        writer.array(3)?;
        writer.u64(u64::from(self.current_policy.window_days()))?;
        writer.u64(u64::from(self.current_policy.renewal_margin_seconds()))?;
        writer.u64(u64::from(self.current_policy.clock_uncertainty_ms()))?;
        encode_delta(&mut writer, &self.delta)?;
        if let Some(snapshot) = &self.snapshot {
            encode_snapshot(&mut writer, snapshot)?;
        } else {
            writer.null()?;
        }
        writer.array(self.local_pages.len())?;
        for page in &self.local_pages {
            encode_points(&mut writer, &page.points)?;
        }
        Ok(writer.bytes)
    }

    pub fn decode(bytes: &[u8]) -> V3Result<Self> {
        capacity(bytes.len(), MAX_RECOVERY_SECTION_BYTES)?;
        let mut reader = cbor::Reader::new(bytes);
        fixed_array(&mut reader, 5)?;
        if read(reader.read_u64())? != WIRE_VERSION {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        fixed_array(&mut reader, 3)?;
        let current_policy = RecoveryPolicy::new(
            read_u32(&mut reader)?,
            read_u32(&mut reader)?,
            read_u32(&mut reader)?,
        )?;
        let delta = decode_delta(&mut reader)?;
        let snapshot = if reader.next_is_null() {
            read(reader.read_null())?;
            None
        } else {
            Some(decode_snapshot(&mut reader)?)
        };
        let count = bounded_array(&mut reader, MAX_RECOVERY_PAGES)?;
        let mut local_pages = Vec::with_capacity(count);
        for _ in 0..count {
            local_pages.push(RecoveryPage {
                points: decode_points(&mut reader, MAX_RECOVERY_PAGE_RECORDS)?,
            });
        }
        if !reader.is_finished() {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        let section = Self {
            current_policy,
            delta,
            snapshot,
            local_pages,
        };
        section.validate()?;
        Ok(section)
    }

    /// Validates the authenticated root/chain binding without fetching a historical
    /// predecessor carrier or its old policy. This is the cold-root replay boundary;
    /// its fixed promise is authenticated by the enclosing accepted root.
    pub fn validate_for_header(
        &self,
        parent: Option<&V3CommitParentRef>,
        publish_time_ms: i64,
        is_root: bool,
    ) -> V3Result<()> {
        self.validate()?;
        if publish_time_ms < 0
            || self.snapshot.is_some() != is_root
            || self
                .delta
                .expire_before_ms
                .is_some_and(|cutoff| cutoff > publish_time_ms)
            || self
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.expire_before_ms > publish_time_ms)
        {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        match (parent, self.delta.register.as_ref()) {
            (None, None) if is_root => {
                let snapshot = self
                    .snapshot
                    .as_ref()
                    .ok_or(V3FormatError::InvalidRecoveryHistory)?;
                if !snapshot.pages.is_empty()
                    || !snapshot.tail.is_empty()
                    || snapshot.expire_before_ms != 0
                    || !self.local_pages.is_empty()
                    || self.delta.expire_before_ms.is_some()
                    || self.delta.roll_tail.is_some()
                {
                    return Err(V3FormatError::InvalidRecoveryHistory);
                }
            }
            (Some(parent), Some(point)) => {
                if point.anchor.sequence != parent.sequence
                    || point.anchor.commit_key != parent.commit_key
                    || point.anchor.body_digest != parent.body_digest
                    || point.anchor.version_id != parent.version_id
                    || point.publish_time_ms >= publish_time_ms
                    || point.protected_until_ms <= publish_time_ms
                {
                    return Err(V3FormatError::InvalidRecoveryHistory);
                }
                if let Some(snapshot) = &self.snapshot
                    && (snapshot.tail.last() != Some(point) || snapshot.pages.iter().any(|page| {
                        matches!(&page.location, RecoveryPageLocation::Exact { anchor, .. } if anchor.sequence > parent.sequence)
                    })) {
                        return Err(V3FormatError::InvalidRecoveryHistory);
                }
                if self.local_pages.iter().any(|page| {
                    page.points
                        .iter()
                        .any(|old| old.anchor.sequence >= parent.sequence)
                }) {
                    return Err(V3FormatError::InvalidRecoveryHistory);
                }
            }
            _ => return Err(V3FormatError::InvalidRecoveryHistory),
        }
        Ok(())
    }

    /// Checks the full predecessor policy before publication. `safe_expiry_ms`
    /// comes from the caller's trusted-time uncertainty check, never backend time.
    pub fn validate_for_commit(
        &self,
        parent: Option<(&V3AnchorState, i64, &RecoveryPolicy)>,
        publish_time_ms: i64,
        is_root: bool,
        safe_expiry_ms: i64,
    ) -> V3Result<()> {
        let parent_ref = parent.map(|(anchor, _, _)| V3CommitParentRef {
            sequence: anchor.sequence,
            commit_key: anchor.commit_key.clone(),
            body_digest: anchor.body_digest,
            version_id: anchor.version_id.clone(),
        });
        self.validate_for_header(parent_ref.as_ref(), publish_time_ms, is_root)?;
        if safe_expiry_ms < 0
            || self
                .delta
                .expire_before_ms
                .is_some_and(|cutoff| cutoff > safe_expiry_ms)
        {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        if let Some((anchor, parent_time, policy)) = parent {
            let point = self
                .delta
                .register
                .as_ref()
                .ok_or(V3FormatError::InvalidRecoveryHistory)?;
            let promised = policy.promised_until_ms(publish_time_ms)?;
            if point.anchor != *anchor
                || point.publish_time_ms != parent_time
                || point.protected_until_ms < promised
                || point.policy_id != policy.identity()
            {
                return Err(V3FormatError::InvalidRecoveryHistory);
            }
        }
        Ok(())
    }

    /// Verifies the transition against current accepted state before CAS, then
    /// normalizes against the already verified candidate's exact carrier facts.
    /// The returned value becomes authoritative only after accepted adoption.
    pub fn apply_delta(
        &self,
        previous: &RecoverySnapshot,
        enclosing: &V3AnchorState,
        section_ordinal: u32,
    ) -> V3Result<RecoverySnapshot> {
        self.validate()?;
        previous.validate_normalized()?;
        validate_anchor(enclosing)?;
        validate_ordinal(section_ordinal)?;
        if self
            .delta
            .register
            .as_ref()
            .is_some_and(|point| point.anchor.sequence.checked_next() != Some(enclosing.sequence))
        {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        let mut next = previous.clone();
        if let Some(cutoff) = self.delta.expire_before_ms {
            if cutoff < next.expire_before_ms {
                return Err(V3FormatError::InvalidRecoveryHistory);
            }
            next.expire_before_ms = cutoff;
            next.tail.retain(|point| point.protected_until_ms > cutoff);
            next.pages
                .retain(|page| page.claims.maximum_deadline_ms > cutoff);
        }
        if let Some(index) = self.delta.roll_tail {
            let page = self.page(index)?;
            if page.points != next.tail || next.tail.is_empty() {
                return Err(V3FormatError::InvalidRecoveryHistory);
            }
            capacity(next.pages.len().saturating_add(1), MAX_RECOVERY_PAGES)?;
            next.pages.push(RecoveryPageRef {
                location: RecoveryPageLocation::Exact {
                    anchor: enclosing.clone(),
                    section_ordinal,
                    page_index: index,
                },
                claims: page.claims()?,
            });
            next.tail.clear();
        }
        if let Some(point) = &self.delta.register {
            capacity(next.tail.len().saturating_add(1), MAX_RECOVERY_TAIL_RECORDS)?;
            next.tail.push(point.clone());
        }
        next.validate_normalized()?;
        if let Some(snapshot) = &self.snapshot {
            let normalized = self.normalize_snapshot(snapshot, enclosing, section_ordinal)?;
            if normalized != next {
                return Err(V3FormatError::InvalidRecoveryHistory);
            }
        }
        Ok(next)
    }

    /// Loads only this root's snapshot after its enclosing accepted anchor has
    /// authenticated. Callers must not invoke this while following historical pages.
    pub fn normalized_snapshot(
        &self,
        enclosing: &V3AnchorState,
        section_ordinal: u32,
    ) -> V3Result<Option<RecoverySnapshot>> {
        self.validate()?;
        self.snapshot
            .as_ref()
            .map(|snapshot| self.normalize_snapshot(snapshot, enclosing, section_ordinal))
            .transpose()
    }

    /// Returns page records only; does not inspect or activate the old registry.
    pub fn page(&self, page_index: u32) -> V3Result<&RecoveryPage> {
        self.local_pages
            .get(page_index as usize)
            .ok_or(V3FormatError::InvalidRecoveryHistory)
    }

    fn normalize_snapshot(
        &self,
        snapshot: &RecoverySnapshot,
        enclosing: &V3AnchorState,
        ordinal: u32,
    ) -> V3Result<RecoverySnapshot> {
        validate_anchor(enclosing)?;
        validate_ordinal(ordinal)?;
        let mut normalized = snapshot.clone();
        for reference in &mut normalized.pages {
            if let RecoveryPageLocation::ThisSection { page_index } = reference.location {
                reference.verify_page(self.page(page_index)?)?;
                reference.location = RecoveryPageLocation::Exact {
                    anchor: enclosing.clone(),
                    section_ordinal: ordinal,
                    page_index,
                };
            }
        }
        normalized.validate_normalized()?;
        Ok(normalized)
    }

    fn validate(&self) -> V3Result<()> {
        capacity(self.local_pages.len(), MAX_RECOVERY_PAGES)?;
        if self.delta.expire_before_ms.is_some_and(|cutoff| cutoff < 0) {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        if let Some(point) = &self.delta.register {
            validate_point(point)?;
        }
        let mut previous_page = None;
        for page in &self.local_pages {
            let claims = page.claims()?;
            if previous_page.is_some_and(|last| last >= claims.first_sequence) {
                return Err(V3FormatError::InvalidRecoveryHistory);
            }
            previous_page = Some(claims.last_sequence);
        }
        let mut used = vec![false; self.local_pages.len()];
        if let Some(index) = self.delta.roll_tail {
            self.page(index)?;
            used[index as usize] = true;
        }
        if let Some(snapshot) = &self.snapshot {
            validate_snapshot(snapshot)?;
            if self
                .delta
                .expire_before_ms
                .is_some_and(|cutoff| cutoff != snapshot.expire_before_ms)
            {
                return Err(V3FormatError::InvalidRecoveryHistory);
            }
            for reference in &snapshot.pages {
                if let RecoveryPageLocation::ThisSection { page_index } = reference.location {
                    reference.verify_page(self.page(page_index)?)?;
                    used[page_index as usize] = true;
                }
            }
        }
        if used.iter().any(|used| !used) {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        Ok(())
    }
}

fn validate_point(point: &RecoveryPoint) -> V3Result<()> {
    validate_anchor(&point.anchor)?;
    if point.publish_time_ms < 0 || point.protected_until_ms <= point.publish_time_ms {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    Ok(())
}

fn validate_points(points: &[RecoveryPoint], maximum: usize) -> V3Result<()> {
    capacity(points.len(), maximum)?;
    let mut previous = None;
    for point in points {
        validate_point(point)?;
        if previous.is_some_and(|(sequence, time)| {
            sequence >= point.anchor.sequence || time >= point.publish_time_ms
        }) {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        previous = Some((point.anchor.sequence, point.publish_time_ms));
    }
    Ok(())
}

fn validate_snapshot(snapshot: &RecoverySnapshot) -> V3Result<()> {
    capacity(snapshot.pages.len(), MAX_RECOVERY_PAGES)?;
    validate_points(&snapshot.tail, MAX_RECOVERY_TAIL_RECORDS)?;
    if snapshot.expire_before_ms < 0
        || snapshot
            .tail
            .iter()
            .any(|point| point.protected_until_ms <= snapshot.expire_before_ms)
    {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    let mut previous = None;
    for page in &snapshot.pages {
        validate_claims(&page.claims)?;
        match &page.location {
            RecoveryPageLocation::ThisSection { page_index } => {
                capacity((*page_index as usize).saturating_add(1), MAX_RECOVERY_PAGES)?
            }
            RecoveryPageLocation::Exact {
                anchor,
                section_ordinal,
                page_index,
            } => {
                validate_anchor(anchor)?;
                validate_ordinal(*section_ordinal)?;
                capacity((*page_index as usize).saturating_add(1), MAX_RECOVERY_PAGES)?;
                if page.claims.last_sequence >= anchor.sequence {
                    return Err(V3FormatError::InvalidRecoveryHistory);
                }
            }
        }
        if page.claims.maximum_deadline_ms <= snapshot.expire_before_ms
            || previous.is_some_and(|sequence| sequence >= page.claims.first_sequence)
        {
            return Err(V3FormatError::InvalidRecoveryHistory);
        }
        previous = Some(page.claims.last_sequence);
    }
    if let (Some(sequence), Some(point)) = (previous, snapshot.tail.first())
        && sequence >= point.anchor.sequence
    {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    Ok(())
}

fn validate_claims(claims: &RecoveryPageClaims) -> V3Result<()> {
    capacity(claims.record_count as usize, MAX_RECOVERY_PAGE_RECORDS)?;
    if claims.record_count == 0
        || claims.first_sequence == Sequence::ZERO
        || claims.first_sequence > claims.last_sequence
        || claims.record_count == 1 && claims.first_sequence != claims.last_sequence
        || claims.last_sequence.get() - claims.first_sequence.get()
            < u64::from(claims.record_count - 1)
        || claims.minimum_deadline_ms <= 0
        || claims.minimum_deadline_ms > claims.maximum_deadline_ms
    {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    Ok(())
}

fn validate_anchor(anchor: &V3AnchorState) -> V3Result<()> {
    let key = V3CommitKey::parse(&anchor.commit_key)
        .map_err(|_| V3FormatError::InvalidRecoveryHistory)?;
    if anchor.sequence == Sequence::ZERO || key.sequence != anchor.sequence {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    bounded_text(anchor.commit_key.as_str(), MAX_OBJECT_ID_BYTES)?;
    bounded_text(anchor.signing_key_id.as_str(), MAX_KEY_ID_BYTES)?;
    let version = anchor
        .version_id
        .as_ref()
        .ok_or(V3FormatError::InvalidRecoveryHistory)?;
    bounded_text(version.as_str(), MAX_VERSION_ID_BYTES)?;
    let format = &anchor.format_ref;
    if format.generation == 0 {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    bounded_text(format.object_id.as_str(), MAX_OBJECT_ID_BYTES)?;
    let version = format
        .version_id
        .as_ref()
        .ok_or(V3FormatError::InvalidRecoveryHistory)?;
    bounded_text(version.as_str(), MAX_VERSION_ID_BYTES)?;
    if format.digest.len() != 64 {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    let digest = hex::decode(&format.digest).map_err(|_| V3FormatError::InvalidRecoveryHistory)?;
    if digest.len() != 32 || hex::encode(&digest) != format.digest {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    Ok(())
}

fn validate_ordinal(ordinal: u32) -> V3Result<()> {
    if ordinal as usize >= crate::v3::V3_MAX_COMMIT_SECTIONS {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    Ok(())
}

fn bounded_text(text: &str, maximum: usize) -> V3Result<()> {
    if text.is_empty() {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    capacity(text.len(), maximum)
}

fn capacity(length: usize, maximum: usize) -> V3Result<()> {
    if length > maximum {
        return Err(V3FormatError::RecoveryHistoryCapacity);
    }
    Ok(())
}

fn read<T>(value: Result<T, rs3_types::cbor::CborError>) -> V3Result<T> {
    value.map_err(|_| V3FormatError::InvalidRecoveryHistory)
}

fn fixed_array(reader: &mut cbor::Reader<'_>, expected: usize) -> V3Result<()> {
    if read(reader.read_array_len())? != expected {
        return Err(V3FormatError::InvalidRecoveryHistory);
    }
    Ok(())
}

fn bounded_array(reader: &mut cbor::Reader<'_>, maximum: usize) -> V3Result<usize> {
    let count = read(reader.read_array_len())?;
    capacity(count, maximum)?;
    Ok(count)
}

fn read_u32(reader: &mut cbor::Reader<'_>) -> V3Result<u32> {
    u32::try_from(read(reader.read_u64())?).map_err(|_| V3FormatError::InvalidRecoveryHistory)
}

fn read_digest(reader: &mut cbor::Reader<'_>) -> V3Result<[u8; 32]> {
    read(reader.read_bytes_bounded(32))?
        .try_into()
        .map_err(|_| V3FormatError::InvalidRecoveryHistory)
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn room(&self, additional: usize) -> V3Result<()> {
        capacity(
            self.bytes
                .len()
                .checked_add(additional)
                .ok_or(V3FormatError::RecoveryHistoryCapacity)?,
            MAX_RECOVERY_SECTION_BYTES,
        )
    }
    fn u64(&mut self, value: u64) -> V3Result<()> {
        self.room(cbor_head_len(value))?;
        cbor::write_u64(&mut self.bytes, value);
        Ok(())
    }
    fn i64(&mut self, value: i64) -> V3Result<()> {
        let magnitude = if value >= 0 {
            value as u64
        } else {
            (-1_i128 - i128::from(value)) as u64
        };
        self.room(cbor_head_len(magnitude))?;
        cbor::write_i64(&mut self.bytes, value);
        Ok(())
    }
    fn array(&mut self, len: usize) -> V3Result<()> {
        self.room(cbor_head_len(len as u64))?;
        cbor::write_array_len(&mut self.bytes, len);
        Ok(())
    }
    fn data(&mut self, value: &[u8]) -> V3Result<()> {
        self.room(
            value
                .len()
                .saturating_add(cbor_head_len(value.len() as u64)),
        )?;
        cbor::write_bytes(&mut self.bytes, value);
        Ok(())
    }
    fn text(&mut self, value: &str) -> V3Result<()> {
        self.room(
            value
                .len()
                .saturating_add(cbor_head_len(value.len() as u64)),
        )?;
        cbor::write_text(&mut self.bytes, value);
        Ok(())
    }
    fn null(&mut self) -> V3Result<()> {
        self.room(1)?;
        cbor::write_null(&mut self.bytes);
        Ok(())
    }
}

fn cbor_head_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn encode_anchor(writer: &mut Writer, anchor: &V3AnchorState) -> V3Result<()> {
    writer.array(6)?;
    writer.u64(anchor.sequence.get())?;
    writer.text(anchor.commit_key.as_str())?;
    writer.data(&anchor.body_digest)?;
    writer.text(
        anchor
            .version_id
            .as_ref()
            .ok_or(V3FormatError::InvalidRecoveryHistory)?
            .as_str(),
    )?;
    writer.text(anchor.signing_key_id.as_str())?;
    writer.array(4)?;
    writer.u64(anchor.format_ref.generation)?;
    writer.data(
        &hex::decode(&anchor.format_ref.digest)
            .map_err(|_| V3FormatError::InvalidRecoveryHistory)?,
    )?;
    writer.text(anchor.format_ref.object_id.as_str())?;
    writer.text(
        anchor
            .format_ref
            .version_id
            .as_ref()
            .ok_or(V3FormatError::InvalidRecoveryHistory)?
            .as_str(),
    )
}

fn decode_anchor(reader: &mut cbor::Reader<'_>) -> V3Result<V3AnchorState> {
    fixed_array(reader, 6)?;
    let sequence = Sequence::new(read(reader.read_u64())?);
    let commit_key = BackendObjectId::new(read(reader.read_text_bounded(MAX_OBJECT_ID_BYTES))?)
        .map_err(|_| V3FormatError::InvalidRecoveryHistory)?;
    let body_digest = read_digest(reader)?;
    let version_id = Some(
        BackendVersionId::new(read(reader.read_text_bounded(MAX_VERSION_ID_BYTES))?)
            .map_err(|_| V3FormatError::InvalidRecoveryHistory)?,
    );
    let signing_key_id = KeyId::new(read(reader.read_text_bounded(MAX_KEY_ID_BYTES))?)
        .map_err(|_| V3FormatError::InvalidRecoveryHistory)?;
    fixed_array(reader, 4)?;
    let generation = read(reader.read_u64())?;
    let digest = hex::encode(read_digest(reader)?);
    let object_id = BackendObjectId::new(read(reader.read_text_bounded(MAX_OBJECT_ID_BYTES))?)
        .map_err(|_| V3FormatError::InvalidRecoveryHistory)?;
    let format_version = Some(
        BackendVersionId::new(read(reader.read_text_bounded(MAX_VERSION_ID_BYTES))?)
            .map_err(|_| V3FormatError::InvalidRecoveryHistory)?,
    );
    let anchor = V3AnchorState {
        sequence,
        commit_key,
        body_digest,
        version_id,
        signing_key_id,
        format_ref: V3FormatRef {
            generation,
            digest,
            object_id,
            version_id: format_version,
        },
    };
    validate_anchor(&anchor)?;
    Ok(anchor)
}

fn encode_point(writer: &mut Writer, point: &RecoveryPoint) -> V3Result<()> {
    writer.array(4)?;
    encode_anchor(writer, &point.anchor)?;
    writer.i64(point.publish_time_ms)?;
    writer.i64(point.protected_until_ms)?;
    writer.data(&point.policy_id)
}

fn decode_point(reader: &mut cbor::Reader<'_>) -> V3Result<RecoveryPoint> {
    fixed_array(reader, 4)?;
    let point = RecoveryPoint {
        anchor: decode_anchor(reader)?,
        publish_time_ms: read(reader.read_i64())?,
        protected_until_ms: read(reader.read_i64())?,
        policy_id: read_digest(reader)?,
    };
    validate_point(&point)?;
    Ok(point)
}

fn encode_points(writer: &mut Writer, points: &[RecoveryPoint]) -> V3Result<()> {
    writer.array(points.len())?;
    for point in points {
        encode_point(writer, point)?;
    }
    Ok(())
}

fn decode_points(reader: &mut cbor::Reader<'_>, maximum: usize) -> V3Result<Vec<RecoveryPoint>> {
    let count = bounded_array(reader, maximum)?;
    let mut points = Vec::with_capacity(count);
    for _ in 0..count {
        points.push(decode_point(reader)?);
    }
    validate_points(&points, maximum)?;
    Ok(points)
}

fn encode_delta(writer: &mut Writer, delta: &RecoveryDelta) -> V3Result<()> {
    writer.array(3)?;
    if let Some(point) = &delta.register {
        encode_point(writer, point)?;
    } else {
        writer.null()?;
    }
    if let Some(cutoff) = delta.expire_before_ms {
        writer.i64(cutoff)?;
    } else {
        writer.null()?;
    }
    if let Some(index) = delta.roll_tail {
        writer.u64(u64::from(index))?;
    } else {
        writer.null()?;
    }
    Ok(())
}

fn decode_delta(reader: &mut cbor::Reader<'_>) -> V3Result<RecoveryDelta> {
    fixed_array(reader, 3)?;
    let register = if reader.next_is_null() {
        read(reader.read_null())?;
        None
    } else {
        Some(decode_point(reader)?)
    };
    let expire_before_ms = if reader.next_is_null() {
        read(reader.read_null())?;
        None
    } else {
        Some(read(reader.read_i64())?)
    };
    let roll_tail = if reader.next_is_null() {
        read(reader.read_null())?;
        None
    } else {
        Some(read_u32(reader)?)
    };
    Ok(RecoveryDelta {
        register,
        expire_before_ms,
        roll_tail,
    })
}

fn encode_claims(writer: &mut Writer, claims: RecoveryPageClaims) -> V3Result<()> {
    writer.array(5)?;
    writer.u64(u64::from(claims.record_count))?;
    writer.u64(claims.first_sequence.get())?;
    writer.u64(claims.last_sequence.get())?;
    writer.i64(claims.minimum_deadline_ms)?;
    writer.i64(claims.maximum_deadline_ms)
}

fn decode_claims(reader: &mut cbor::Reader<'_>) -> V3Result<RecoveryPageClaims> {
    fixed_array(reader, 5)?;
    let claims = RecoveryPageClaims {
        record_count: read_u32(reader)?,
        first_sequence: Sequence::new(read(reader.read_u64())?),
        last_sequence: Sequence::new(read(reader.read_u64())?),
        minimum_deadline_ms: read(reader.read_i64())?,
        maximum_deadline_ms: read(reader.read_i64())?,
    };
    validate_claims(&claims)?;
    Ok(claims)
}

fn encode_page_ref(writer: &mut Writer, reference: &RecoveryPageRef) -> V3Result<()> {
    writer.array(2)?;
    match &reference.location {
        RecoveryPageLocation::ThisSection { page_index } => {
            writer.array(2)?;
            writer.u64(0)?;
            writer.u64(u64::from(*page_index))?;
        }
        RecoveryPageLocation::Exact {
            anchor,
            section_ordinal,
            page_index,
        } => {
            writer.array(4)?;
            writer.u64(1)?;
            encode_anchor(writer, anchor)?;
            writer.u64(u64::from(*section_ordinal))?;
            writer.u64(u64::from(*page_index))?;
        }
    }
    encode_claims(writer, reference.claims)
}

fn decode_page_ref(reader: &mut cbor::Reader<'_>) -> V3Result<RecoveryPageRef> {
    fixed_array(reader, 2)?;
    let width = read(reader.read_array_len())?;
    let tag = read(reader.read_u64())?;
    let location = match (tag, width) {
        (0, 2) => RecoveryPageLocation::ThisSection {
            page_index: read_u32(reader)?,
        },
        (1, 4) => RecoveryPageLocation::Exact {
            anchor: decode_anchor(reader)?,
            section_ordinal: read_u32(reader)?,
            page_index: read_u32(reader)?,
        },
        _ => return Err(V3FormatError::InvalidRecoveryHistory),
    };
    Ok(RecoveryPageRef {
        location,
        claims: decode_claims(reader)?,
    })
}

fn encode_snapshot(writer: &mut Writer, snapshot: &RecoverySnapshot) -> V3Result<()> {
    writer.array(3)?;
    writer.array(snapshot.pages.len())?;
    for page in &snapshot.pages {
        encode_page_ref(writer, page)?;
    }
    encode_points(writer, &snapshot.tail)?;
    writer.i64(snapshot.expire_before_ms)
}

fn decode_snapshot(reader: &mut cbor::Reader<'_>) -> V3Result<RecoverySnapshot> {
    fixed_array(reader, 3)?;
    let count = bounded_array(reader, MAX_RECOVERY_PAGES)?;
    let mut pages = Vec::with_capacity(count);
    for _ in 0..count {
        pages.push(decode_page_ref(reader)?);
    }
    let snapshot = RecoverySnapshot {
        pages,
        tail: decode_points(reader, MAX_RECOVERY_TAIL_RECORDS)?,
        expire_before_ms: read(reader.read_i64())?,
    };
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(sequence: u64) -> V3AnchorState {
        V3AnchorState {
            sequence: Sequence::new(sequence),
            commit_key: V3CommitKey::from_parts(Sequence::new(sequence), [0x41; 32])
                .expect("commit key")
                .object_id,
            body_digest: [0x42; 32],
            version_id: Some(
                BackendVersionId::new(format!("version-{sequence}")).expect("version"),
            ),
            signing_key_id: KeyId::new("signing-key").expect("key id"),
            format_ref: V3FormatRef {
                generation: 1,
                digest: hex::encode([0x43; 32]),
                object_id: BackendObjectId::new("format/exact-root").expect("format id"),
                version_id: Some(BackendVersionId::new("format-version").expect("format version")),
            },
        }
    }

    fn point(sequence: u64) -> RecoveryPoint {
        RecoveryPoint {
            anchor: anchor(sequence),
            publish_time_ms: sequence as i64 * 1_000,
            protected_until_ms: 100 * 86_400_000 + sequence as i64 * 1_000,
            policy_id: RecoveryPolicy::PRESET.identity(),
        }
    }

    fn delta(register: Option<RecoveryPoint>) -> RecoverySection {
        RecoverySection {
            current_policy: RecoveryPolicy::PRESET,
            delta: RecoveryDelta {
                register,
                ..RecoveryDelta::default()
            },
            snapshot: None,
            local_pages: Vec::new(),
        }
    }

    fn root_roll() -> (RecoverySnapshot, RecoverySection) {
        let previous = RecoverySnapshot {
            tail: vec![point(1), point(2)],
            ..RecoverySnapshot::default()
        };
        let page = RecoveryPage {
            points: previous.tail.clone(),
        };
        let section = RecoverySection {
            current_policy: RecoveryPolicy::PRESET,
            delta: RecoveryDelta {
                register: Some(point(3)),
                roll_tail: Some(0),
                expire_before_ms: None,
            },
            snapshot: Some(RecoverySnapshot {
                pages: vec![RecoveryPageRef {
                    location: RecoveryPageLocation::ThisSection { page_index: 0 },
                    claims: page.claims().expect("claims"),
                }],
                tail: vec![point(3)],
                expire_before_ms: 0,
            }),
            local_pages: vec![page],
        };
        (previous, section)
    }

    fn parent_ref(anchor: &V3AnchorState) -> V3CommitParentRef {
        V3CommitParentRef {
            sequence: anchor.sequence,
            commit_key: anchor.commit_key.clone(),
            body_digest: anchor.body_digest,
            version_id: anchor.version_id.clone(),
        }
    }

    #[test]
    fn canonical_delta_and_root_round_trip_preserve_exact_promises() {
        for section in [delta(Some(point(1))), root_roll().1] {
            let encoded = section.encode().expect("encode");
            let decoded = RecoverySection::decode(&encoded).expect("decode");
            assert_eq!(decoded, section);
            assert_eq!(decoded.encode().expect("canonical reencode"), encoded);
            assert!(!format!("{decoded:?}").contains("format/exact-root"));
            assert!(!format!("{decoded:?}").contains("commits/v03/"));
        }
        let genesis = RecoverySection {
            snapshot: Some(RecoverySnapshot::default()),
            ..delta(None)
        };
        assert_eq!(
            hex::encode(genesis.encode().expect("genesis encoding")),
            "850183181e1a0001518019ea6083f6f6f68380800080"
        );
        genesis
            .validate_for_header(None, 0, true)
            .expect("genesis binding");
    }

    #[test]
    fn same_commit_page_roll_normalizes_once_and_survives_later_root() {
        let (previous, section) = root_roll();
        let accepted = anchor(4);
        section
            .validate_for_commit(
                Some((&anchor(3), 3_000, &RecoveryPolicy::PRESET)),
                4_000,
                true,
                4_000,
            )
            .expect("root binding");
        let next = section
            .apply_delta(&previous, &accepted, 1)
            .expect("apply roll");
        assert!(
            section.apply_delta(&previous, &anchor(5), 1).is_err(),
            "self page cannot bind to an unrelated successor"
        );
        assert!(
            section
                .apply_delta(
                    &previous,
                    &accepted,
                    crate::v3::V3_MAX_COMMIT_SECTIONS as u32
                )
                .is_err()
        );
        assert_eq!(next.pages.len(), 1);
        assert_eq!(next.tail, vec![point(3)]);
        assert_eq!(
            next.pages[0].location,
            RecoveryPageLocation::Exact {
                anchor: accepted.clone(),
                section_ordinal: 1,
                page_index: 0
            }
        );
        assert_eq!(
            section.normalized_snapshot(&accepted, 1).expect("snapshot"),
            Some(next.clone())
        );
        let later = RecoverySection {
            current_policy: RecoveryPolicy::PRESET,
            delta: RecoveryDelta {
                register: Some(point(4)),
                ..RecoveryDelta::default()
            },
            snapshot: Some(RecoverySnapshot {
                pages: next.pages.clone(),
                tail: vec![point(3), point(4)],
                expire_before_ms: 0,
            }),
            local_pages: Vec::new(),
        };
        let installed = later
            .apply_delta(&next, &anchor(5), 1)
            .expect("later snapshot");
        assert_eq!(
            installed.pages[0].location, next.pages[0].location,
            "old exact page must not be rebound to its new containing root"
        );
        assert!(
            section.apply_delta(&next, &accepted, 1).is_err(),
            "transition cannot apply twice"
        );
    }

    #[test]
    fn changed_roll_promises_false_claims_or_wrong_snapshot_fail_before_install() {
        let (previous, original) = root_roll();
        for case in 0..6 {
            let mut changed = original.clone();
            match case {
                0 => changed.local_pages[0].points[0].protected_until_ms -= 1,
                1 => {
                    changed.snapshot.as_mut().expect("snapshot").pages[0]
                        .claims
                        .record_count += 1
                }
                2 => {
                    changed.snapshot.as_mut().expect("snapshot").pages[0]
                        .claims
                        .minimum_deadline_ms += 1
                }
                3 => changed.snapshot.as_mut().expect("snapshot").tail[0].policy_id[0] ^= 1,
                4 => changed.delta.roll_tail = Some(1),
                _ => changed.local_pages.push(RecoveryPage {
                    points: vec![point(1)],
                }),
            }
            assert!(
                changed.apply_delta(&previous, &anchor(4), 1).is_err(),
                "case {case}"
            );
        }
        assert_eq!(previous.tail, vec![point(1), point(2)]);
    }

    #[test]
    fn predecessor_policy_survives_reduction_and_cold_root_requires_no_old_carrier() {
        let old_policy = RecoveryPolicy::PRESET;
        let new_policy = RecoveryPolicy::new(1, 86_400, 60_000).expect("reduced policy");
        let parent = anchor(3);
        let mut registered = point(3);
        registered.protected_until_ms = old_policy.promised_until_ms(4_000).expect("old promise");
        let section = RecoverySection {
            current_policy: new_policy,
            snapshot: Some(RecoverySnapshot {
                tail: vec![registered.clone()],
                ..RecoverySnapshot::default()
            }),
            ..delta(Some(registered))
        };
        section
            .validate_for_commit(Some((&parent, 3_000, &old_policy)), 4_000, true, 4_000)
            .expect("old policy binding");
        let decoded =
            RecoverySection::decode(&section.encode().expect("encode")).expect("cold decode");
        decoded
            .validate_for_header(Some(&parent_ref(&parent)), 4_000, true)
            .expect("root without old carrier or policy fetch");
        assert_eq!(decoded.current_policy, new_policy);
        for case in 0..5 {
            let mut invalid = section.clone();
            let record = invalid.delta.register.as_mut().expect("registration");
            match case {
                0 => {
                    record.protected_until_ms = new_policy
                        .promised_until_ms(4_000)
                        .expect("shorter deadline")
                }
                1 => record.policy_id = new_policy.identity(),
                2 => {
                    record.anchor.version_id =
                        Some(BackendVersionId::new("different-version").expect("version"))
                }
                3 => record.publish_time_ms = 4_000,
                _ => record.anchor.body_digest[0] ^= 1,
            }
            invalid.snapshot.as_mut().expect("snapshot").tail[0] =
                invalid.delta.register.clone().expect("point");
            assert!(
                invalid
                    .validate_for_commit(Some((&parent, 3_000, &old_policy)), 4_000, true, 4_000)
                    .is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn explicit_monotonic_expiry_releases_only_elapsed_pages_and_does_not_reactivate_old_snapshot()
    {
        let (previous, root) = root_roll();
        let before = root
            .apply_delta(&previous, &anchor(4), 1)
            .expect("old root");
        let cutoff = point(2).protected_until_ms;
        let mut expiry = delta(Some(point(4)));
        expiry.delta.expire_before_ms = Some(cutoff);
        let after = expiry.apply_delta(&before, &anchor(5), 1).expect("expiry");
        assert!(after.pages.is_empty());
        assert_eq!(after.tail, vec![point(3), point(4)]);
        assert_eq!(after.expire_before_ms, cutoff);
        let old_section =
            RecoverySection::decode(&root.encode().expect("old bytes")).expect("old section");
        before.pages[0]
            .verify_page(old_section.page(0).expect("historical page only"))
            .expect("claims");
        assert!(
            after.pages.is_empty(),
            "page access has no registry side effects"
        );
        let mut backward = delta(Some(point(5)));
        backward.delta.expire_before_ms = Some(cutoff - 1);
        assert_eq!(
            backward.apply_delta(&after, &anchor(6), 1),
            Err(V3FormatError::InvalidRecoveryHistory)
        );
        let mut no_expiry = delta(Some(point(4)));
        no_expiry.current_policy = RecoveryPolicy::new(1, 86_400, 60_000).expect("reduced policy");
        let retained = no_expiry
            .apply_delta(&before, &anchor(5), 1)
            .expect("no expiry");
        assert_eq!(
            retained.pages, before.pages,
            "new configuration alone cannot expire history"
        );
        assert!(
            expiry
                .validate_for_header(Some(&parent_ref(&anchor(4))), 5_000, false)
                .is_err(),
            "future cutoff cannot be authorized by a signed old timestamp"
        );
    }

    #[test]
    fn tail_limit_backpressures_without_eviction_and_explicit_roll_preserves_every_point() {
        let previous = RecoverySnapshot {
            tail: (1..=MAX_RECOVERY_TAIL_RECORDS as u64).map(point).collect(),
            ..RecoverySnapshot::default()
        };
        let predecessor = MAX_RECOVERY_TAIL_RECORDS as u64 + 1;
        let mut section = delta(Some(point(predecessor)));
        assert_eq!(
            section.apply_delta(&previous, &anchor(predecessor + 1), 1),
            Err(V3FormatError::RecoveryHistoryCapacity)
        );
        assert_eq!(previous.tail.len(), MAX_RECOVERY_TAIL_RECORDS);
        section.delta.roll_tail = Some(0);
        section.local_pages.push(RecoveryPage {
            points: previous.tail.clone(),
        });
        let next = section
            .apply_delta(&previous, &anchor(predecessor + 1), 1)
            .expect("bounded roll");
        assert_eq!(
            next.pages[0].claims.record_count as usize,
            MAX_RECOVERY_TAIL_RECORDS
        );
        assert_eq!(next.tail, vec![point(predecessor)]);
        let encoded = section.encode().expect("page fits section");
        let decoded = RecoverySection::decode(&encoded).expect("page decode");
        assert_eq!(decoded.local_pages[0].points, previous.tail);
    }

    #[test]
    fn page_catalog_limit_and_reference_ancestry_fail_closed() {
        let mut previous = RecoverySnapshot::default();
        for sequence in 1..=MAX_RECOVERY_PAGES as u64 {
            let page = RecoveryPage {
                points: vec![point(sequence)],
            };
            previous.pages.push(RecoveryPageRef {
                location: RecoveryPageLocation::Exact {
                    anchor: anchor(sequence + 1),
                    section_ordinal: 1,
                    page_index: 0,
                },
                claims: page.claims().expect("claims"),
            });
        }
        previous.tail.push(point(MAX_RECOVERY_PAGES as u64 + 1));
        let mut section = delta(Some(point(MAX_RECOVERY_PAGES as u64 + 2)));
        section.delta.roll_tail = Some(0);
        section.local_pages.push(RecoveryPage {
            points: previous.tail.clone(),
        });
        assert_eq!(
            section.apply_delta(&previous, &anchor(MAX_RECOVERY_PAGES as u64 + 3), 1),
            Err(V3FormatError::RecoveryHistoryCapacity)
        );
        let mut invalid = previous;
        invalid.pages[0].location = RecoveryPageLocation::Exact {
            anchor: anchor(1),
            section_ordinal: 1,
            page_index: 0,
        };
        assert_eq!(
            invalid.validate_normalized(),
            Err(V3FormatError::InvalidRecoveryHistory)
        );
    }

    #[test]
    fn bounded_decoder_rejects_noncanonical_truncated_and_oversized_inputs() {
        let encoded = delta(Some(point(1))).encode().expect("encode");
        for end in 0..encoded.len() {
            assert!(
                RecoverySection::decode(&encoded[..end]).is_err(),
                "truncation at {end}"
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(RecoverySection::decode(&trailing).is_err());
        let mut nonminimal = encoded.clone();
        nonminimal.splice(1..2, [0x18, 0x01]);
        assert!(RecoverySection::decode(&nonminimal).is_err());
        let mut indefinite = encoded.clone();
        indefinite[0] = 0x9f;
        assert!(RecoverySection::decode(&indefinite).is_err());
        let mut unknown = encoded;
        unknown[1] = 2;
        assert!(RecoverySection::decode(&unknown).is_err());
        assert_eq!(
            RecoverySection::decode(&vec![0; MAX_RECOVERY_SECTION_BYTES + 1]),
            Err(V3FormatError::RecoveryHistoryCapacity)
        );
        for count in [MAX_RECOVERY_PAGE_RECORDS + 1, usize::MAX] {
            let mut raw = Vec::new();
            cbor::write_array_len(&mut raw, count);
            assert_eq!(
                decode_points(&mut cbor::Reader::new(&raw), MAX_RECOVERY_PAGE_RECORDS),
                Err(V3FormatError::RecoveryHistoryCapacity)
            );
        }
        let mut raw = Vec::new();
        cbor::write_array_len(&mut raw, 3);
        cbor::write_array_len(&mut raw, MAX_RECOVERY_PAGES + 1);
        assert_eq!(
            decode_snapshot(&mut cbor::Reader::new(&raw)),
            Err(V3FormatError::RecoveryHistoryCapacity)
        );
    }

    #[test]
    fn encoder_enforces_total_bytes_not_only_record_counts() {
        let mut section = delta(None);
        let points: Vec<_> = (1..=MAX_RECOVERY_PAGE_RECORDS as u64)
            .map(|sequence| {
                let mut record = point(sequence);
                record.anchor.version_id = Some(
                    BackendVersionId::new("v".repeat(MAX_VERSION_ID_BYTES)).expect("long version"),
                );
                record.anchor.format_ref.version_id = Some(
                    BackendVersionId::new("f".repeat(MAX_VERSION_ID_BYTES))
                        .expect("long format version"),
                );
                record
            })
            .collect();
        section.delta.roll_tail = Some(0);
        section.local_pages.push(RecoveryPage { points });
        assert_eq!(
            section.encode(),
            Err(V3FormatError::RecoveryHistoryCapacity)
        );
    }

    #[test]
    fn malformed_exact_points_and_overlapping_catalog_claims_are_rejected() {
        for case in 0..6 {
            let mut record = point(1);
            match case {
                0 => record.anchor.version_id = None,
                1 => record.anchor.format_ref.version_id = None,
                2 => record.anchor.sequence = Sequence::new(2),
                3 => record.publish_time_ms = -1,
                4 => record.protected_until_ms = record.publish_time_ms,
                _ => record.anchor.format_ref.digest = "AA".repeat(32),
            }
            assert!(delta(Some(record)).encode().is_err(), "case {case}");
        }
        let (_, mut root) = root_roll();
        let reference = root.snapshot.as_ref().expect("snapshot").pages[0].clone();
        root.snapshot
            .as_mut()
            .expect("snapshot")
            .pages
            .push(reference);
        assert!(root.encode().is_err());
    }
}
