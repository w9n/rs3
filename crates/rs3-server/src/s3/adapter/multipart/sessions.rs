//! Bounded ephemeral upload ownership; accepted results live in repository state.

use super::*;
use std::collections::BTreeMap;
use tokio::sync::{Mutex as AsyncMutex, Notify, RwLock};

const MAX_SESSIONS: usize = 128;
const MAX_PART_ENTRIES: usize = 65_536;
const SESSION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone)]
pub(in crate::s3::adapter) struct MultipartSessions(Arc<Inner>);
struct Inner {
    entries: Mutex<BTreeMap<MultipartUploadId, Arc<Session>>>,
    sessions: Arc<Semaphore>,
    parts: Arc<Semaphore>,
    lifetime: Duration,
}

pub(super) struct Session {
    pub(super) upload: RwLock<Option<V3ClientMultipartUpload>>,
    expires: tokio::time::Instant,
    parts: Mutex<BTreeMap<u32, Arc<PartSlot>>>,
    part_budget: Arc<Semaphore>,
    done: Notify,
    _permit: OwnedSemaphorePermit,
}

pub(super) struct PartSlot {
    pub(super) lock: AsyncMutex<()>,
    _permit: OwnedSemaphorePermit,
}

impl MultipartSessions {
    pub(in crate::s3::adapter) fn new() -> Self {
        Self::with_limits(MAX_SESSIONS, MAX_PART_ENTRIES, SESSION_LIFETIME)
    }

    pub(in crate::s3::adapter) fn with_limits(
        sessions: usize,
        parts: usize,
        lifetime: Duration,
    ) -> Self {
        Self(Arc::new(Inner {
            entries: Mutex::new(BTreeMap::new()),
            sessions: Arc::new(Semaphore::new(sessions)),
            parts: Arc::new(Semaphore::new(parts)),
            lifetime,
        }))
    }

    pub(super) fn reserve(&self) -> S3Result<OwnedSemaphorePermit> {
        Arc::clone(&self.0.sessions)
            .try_acquire_owned()
            .map_err(|_| s3s::s3_error!(SlowDown, "multipart session limit reached"))
    }

    pub(super) async fn insert(
        &self,
        upload: V3ClientMultipartUpload,
        permit: OwnedSemaphorePermit,
    ) -> S3Result<MultipartUploadId> {
        let id = upload.id();
        let entry = Arc::new(Session {
            upload: RwLock::new(Some(upload)),
            expires: tokio::time::Instant::now() + self.0.lifetime,
            parts: Mutex::new(BTreeMap::new()),
            part_budget: Arc::clone(&self.0.parts),
            done: Notify::new(),
            _permit: permit,
        });
        let inserted = {
            let mut entries = self.0.entries.lock().map_err(|_| internal())?;
            if let std::collections::btree_map::Entry::Vacant(slot) = entries.entry(id) {
                slot.insert(Arc::clone(&entry));
                true
            } else {
                false
            }
        };
        if !inserted {
            if let Some(upload) = entry.upload.write().await.take() {
                let _ = upload.abort().await;
            }
            return Err(internal());
        }
        let owner = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            tokio::select! {
                () = entry.done.notified() => (),
                () = tokio::time::sleep_until(entry.expires) => {
                    // Remove before waiting for active writers, so new lookups
                    // cannot start work in an expired session.
                    if let Some(owner) = owner.upgrade() {
                        MultipartSessions(owner).remove(&id, &entry);
                    }
                    if let Some(upload) = entry.upload.write().await.take() {
                        let _ = upload.abort().await;
                    }
                }
            }
        });
        Ok(id)
    }

    pub(super) fn get(&self, id: &MultipartUploadId) -> S3Result<Arc<Session>> {
        let entries = self.0.entries.lock().map_err(|_| internal())?;
        let session = entries.get(id).cloned().ok_or_else(no_upload)?;
        session.ensure_live()?;
        Ok(session)
    }

    pub(super) fn remove(&self, id: &MultipartUploadId, entry: &Arc<Session>) {
        if let Ok(mut entries) = self.0.entries.lock()
            && entries
                .get(id)
                .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            entries.remove(id);
        }
        entry.done.notify_one();
    }
}

impl Session {
    pub(super) fn ensure_live(&self) -> S3Result<()> {
        if tokio::time::Instant::now() >= self.expires {
            Err(no_upload())
        } else {
            Ok(())
        }
    }

    pub(super) fn part_slot(&self, number: u32) -> S3Result<Arc<PartSlot>> {
        if !(1..=10_000).contains(&number) {
            return Err(s3s::s3_error!(
                InvalidArgument,
                "invalid multipart part number"
            ));
        }
        let mut parts = self.parts.lock().map_err(|_| internal())?;
        if let Some(slot) = parts.get(&number) {
            return Ok(Arc::clone(slot));
        }
        let permit = Arc::clone(&self.part_budget)
            .try_acquire_owned()
            .map_err(|_| s3s::s3_error!(SlowDown, "multipart part-entry limit reached"))?;
        let slot = Arc::new(PartSlot {
            lock: AsyncMutex::new(()),
            _permit: permit,
        });
        parts.insert(number, Arc::clone(&slot));
        Ok(slot)
    }
}
