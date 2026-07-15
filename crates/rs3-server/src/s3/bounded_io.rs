use super::{S3BoundaryError, repository_init};
use bytes::Bytes;
use rs3_storage::{BlobList, BlobListMode, BlobListPage, BlobStore, read_bounded_full_at};
use rs3_types::{BackendObjectId, BackendVersionId};
use std::num::NonZeroUsize;

pub(super) const CONTROL_LIST_BUDGET: ListBudget = ListBudget {
    page_items: 1_000,
    max_pages: 4_096,
    max_items: 2_000_000,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ListBudget {
    pub(super) page_items: usize,
    pub(super) max_pages: usize,
    pub(super) max_items: usize,
}

impl ListBudget {
    pub(super) const fn new(page_items: usize, max_pages: usize, max_items: usize) -> Self {
        Self {
            page_items,
            max_pages,
            max_items,
        }
    }
}

pub(super) async fn prefix_has_any_object<S>(
    store: &S,
    prefix: &str,
    mode: BlobListMode,
) -> Result<bool, S3BoundaryError>
where
    S: BlobStore + ?Sized,
{
    let mut listing =
        BoundedListing::open(store, prefix, mode, ListBudget::new(1, 4_096, 1)).await?;
    while let Some(page) = listing.next_page().await? {
        if page.consumed_items != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) struct BoundedListing {
    inner: Box<dyn BlobList>,
    budget: ListBudget,
    pages_read: usize,
    items_read: usize,
    complete: bool,
}

impl BoundedListing {
    pub(super) async fn open<S>(
        store: &S,
        prefix: &str,
        mode: BlobListMode,
        budget: ListBudget,
    ) -> Result<Self, S3BoundaryError>
    where
        S: BlobStore + ?Sized,
    {
        validate_budget(budget)?;
        let inner = store
            .open_bounded_list(prefix, mode)
            .await
            .map_err(repository_init)?;
        Ok(Self {
            inner,
            budget,
            pages_read: 0,
            items_read: 0,
            complete: false,
        })
    }

    pub(super) async fn next_page(&mut self) -> Result<Option<BlobListPage>, S3BoundaryError> {
        if self.complete {
            return Ok(None);
        }
        let remaining_pages = self.budget.max_pages.saturating_sub(self.pages_read);
        let remaining_items = self.budget.max_items.saturating_sub(self.items_read);
        if remaining_pages == 0 || remaining_items == 0 {
            return Err(list_budget_exceeded(self.budget));
        }
        let requested_items = self.budget.page_items.min(remaining_items);
        let requested_items =
            NonZeroUsize::new(requested_items).ok_or_else(|| list_budget_exceeded(self.budget))?;
        let page = self
            .inner
            .next_page(requested_items)
            .await
            .map_err(repository_init)?;
        if page.consumed_items < page.entries.len() || page.consumed_items > requested_items.get() {
            return Err(repository_init(
                "provider returned a listing page outside the requested member bound",
            ));
        }
        self.pages_read = self.pages_read.saturating_add(1);
        self.items_read = self.items_read.saturating_add(page.consumed_items);
        self.complete = page.is_complete;
        Ok(Some(page))
    }
}

pub(super) async fn read_bounded_object_at<S>(
    store: &S,
    object_id: &BackendObjectId,
    version_id: Option<&BackendVersionId>,
    max_bytes: u64,
) -> Result<Bytes, S3BoundaryError>
where
    S: BlobStore + ?Sized,
{
    read_bounded_full_at(store, object_id, version_id, max_bytes)
        .await
        .map_err(repository_init)
}

fn validate_budget(budget: ListBudget) -> Result<(), S3BoundaryError> {
    if budget.page_items == 0 || budget.max_pages == 0 || budget.max_items == 0 {
        return Err(repository_init(
            "bounded backend listing requires positive page and total limits",
        ));
    }
    Ok(())
}

fn list_budget_exceeded(budget: ListBudget) -> S3BoundaryError {
    repository_init(format!(
        "backend listing exceeded the fixed control-path budget of {} pages or {} provider members",
        budget.max_pages, budget.max_items,
    ))
}

#[cfg(test)]
mod tests {
    use super::{BoundedListing, ListBudget};
    use bytes::Bytes;
    use rs3_storage::{BlobListMode, BlobStore, MemoryBlobStore, PutOptions};
    use rs3_types::BackendObjectId;

    async fn store_with_objects(count: usize) -> MemoryBlobStore {
        let store = MemoryBlobStore::new();
        for index in 0..count {
            let object_id = BackendObjectId::new(format!("objects/opaque-{index:04}"))
                .unwrap_or_else(|error| panic!("{error}"));
            store
                .put(
                    &object_id,
                    Bytes::from_static(b"body"),
                    PutOptions::default(),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }
        store
    }

    #[tokio::test]
    async fn bounded_listing_fails_closed_at_total_item_limit() {
        let store = store_with_objects(3).await;
        let mut listing = BoundedListing::open(
            &store,
            "objects/",
            BlobListMode::Current,
            ListBudget::new(1, 3, 2),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            listing
                .next_page()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .map(|page| page.entries.len()),
            Some(1)
        );
        assert_eq!(
            listing
                .next_page()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .map(|page| page.entries.len()),
            Some(1)
        );
        let error = listing
            .next_page()
            .await
            .expect_err("third page must exceed the total item budget");
        assert!(error.to_string().contains("fixed control-path budget"));
    }

    #[tokio::test]
    async fn bounded_listing_reports_verified_completion() {
        let store = store_with_objects(1).await;
        let mut listing = BoundedListing::open(
            &store,
            "objects/",
            BlobListMode::Current,
            ListBudget::new(2, 1, 2),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let page = listing
            .next_page()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing page"));
        assert!(page.is_complete);
        assert_eq!(listing.next_page().await, Ok(None));
    }
}
