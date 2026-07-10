use crate::{ByteRange, Result, StorageError};

pub(super) fn sdk_range_header(range: ByteRange) -> Result<Option<String>> {
    match range {
        ByteRange::Full => Ok(None),
        ByteRange::Slice { offset, len } => {
            let end = offset.checked_add(len).ok_or(StorageError::InvalidRange)?;
            if end <= offset {
                return Err(StorageError::InvalidRange);
            }
            Ok(Some(format!("bytes={offset}-{}", end - 1)))
        }
    }
}
