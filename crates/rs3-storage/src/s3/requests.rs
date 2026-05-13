use crate::{ByteRange, PutOptions, Result, StorageError};
use object_store::path::Path as ObjectPath;
use object_store::{Attribute, Attributes, GetOptions, PutMode, PutOptions as ObjectPutOptions};

pub(super) fn object_put_options(options: &PutOptions) -> ObjectPutOptions {
    let mode = if options.do_not_recreate {
        PutMode::Create
    } else {
        PutMode::Overwrite
    };
    let mut attributes = Attributes::new();
    if let Some(content_type) = options.content_type.clone() {
        attributes.insert(Attribute::ContentType, content_type.into());
    }

    ObjectPutOptions {
        mode,
        attributes,
        ..ObjectPutOptions::default()
    }
}

pub(super) fn object_get_options(range: ByteRange) -> Result<GetOptions> {
    let options = match range {
        ByteRange::Full => GetOptions::default(),
        ByteRange::Slice { offset, len } => {
            let end = offset.checked_add(len).ok_or(StorageError::InvalidRange)?;
            if end <= offset {
                return Err(StorageError::InvalidRange);
            }
            GetOptions::new().with_range(Some(offset..end))
        }
    };
    Ok(options)
}

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

pub(super) fn object_path(value: &str) -> Result<ObjectPath> {
    ObjectPath::parse(value).map_err(|error| StorageError::Provider(error.to_string()))
}
