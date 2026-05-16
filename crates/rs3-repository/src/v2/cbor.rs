//! Minimal canonical CBOR support for the fixed v2 header schema.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CborError {
    Invalid,
}

pub(super) type CborResult<T> = std::result::Result<T, CborError>;

pub(super) fn write_u64(out: &mut Vec<u8>, value: u64) {
    write_type_len(out, 0, value);
}

pub(super) fn write_i64(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        write_type_len(out, 0, value as u64);
    } else {
        write_type_len(out, 1, (-1_i128 - i128::from(value)) as u64);
    }
}

pub(super) fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_type_len(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub(super) fn write_text(out: &mut Vec<u8>, text: &str) {
    write_type_len(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

pub(super) fn write_array_len(out: &mut Vec<u8>, len: usize) {
    write_type_len(out, 4, len as u64);
}

pub(super) fn write_map_len(out: &mut Vec<u8>, len: usize) {
    write_type_len(out, 5, len as u64);
}

pub(super) fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(if value { 0xf5 } else { 0xf4 });
}

pub(super) fn write_null(out: &mut Vec<u8>) {
    out.push(0xf6);
}

fn write_type_len(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => {
            out.push(prefix | 24);
            out.push(value as u8);
        }
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

pub(super) struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(super) const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    pub(super) fn is_finished(&self) -> bool {
        self.pos == self.input.len()
    }

    pub(super) fn read_u64(&mut self) -> CborResult<u64> {
        let (major, additional) = self.read_initial()?;
        if major != 0 {
            return Err(CborError::Invalid);
        }
        self.read_len(additional)
    }

    pub(super) fn read_i64(&mut self) -> CborResult<i64> {
        let (major, additional) = self.read_initial()?;
        let value = self.read_len(additional)?;
        match major {
            0 => i64::try_from(value).map_err(|_| CborError::Invalid),
            1 => {
                let negative = -1_i128 - i128::from(value);
                i64::try_from(negative).map_err(|_| CborError::Invalid)
            }
            _ => Err(CborError::Invalid),
        }
    }

    pub(super) fn read_bytes(&mut self) -> CborResult<Vec<u8>> {
        let len = self.read_len_for_major(2)?;
        let bytes = self.take(len)?;
        Ok(bytes.to_vec())
    }

    pub(super) fn read_text(&mut self) -> CborResult<String> {
        let len = self.read_len_for_major(3)?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CborError::Invalid)
    }

    pub(super) fn read_array_len(&mut self) -> CborResult<usize> {
        self.read_len_for_major(4)
    }

    pub(super) fn read_map_len(&mut self) -> CborResult<usize> {
        self.read_len_for_major(5)
    }

    pub(super) fn read_bool(&mut self) -> CborResult<bool> {
        match self.read_byte()? {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(CborError::Invalid),
        }
    }

    pub(super) fn read_null(&mut self) -> CborResult<()> {
        match self.read_byte()? {
            0xf6 => Ok(()),
            _ => Err(CborError::Invalid),
        }
    }

    pub(super) fn next_is_null(&self) -> bool {
        self.input.get(self.pos).copied() == Some(0xf6)
    }

    fn read_len_for_major(&mut self, expected_major: u8) -> CborResult<usize> {
        let (major, additional) = self.read_initial()?;
        if major != expected_major {
            return Err(CborError::Invalid);
        }
        usize::try_from(self.read_len(additional)?).map_err(|_| CborError::Invalid)
    }

    fn read_initial(&mut self) -> CborResult<(u8, u8)> {
        let byte = self.read_byte()?;
        Ok((byte >> 5, byte & 0x1f))
    }

    fn read_len(&mut self, additional: u8) -> CborResult<u64> {
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => {
                let value = u64::from(self.read_byte()?);
                if value < 24 {
                    return Err(CborError::Invalid);
                }
                Ok(value)
            }
            25 => {
                let bytes = self.take(2)?;
                let value = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                if value <= 0xff {
                    return Err(CborError::Invalid);
                }
                Ok(value)
            }
            26 => {
                let bytes = self.take(4)?;
                let value = u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                if value <= 0xffff {
                    return Err(CborError::Invalid);
                }
                Ok(value)
            }
            27 => {
                let bytes = self.take(8)?;
                let value = u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                if value <= 0xffff_ffff {
                    return Err(CborError::Invalid);
                }
                Ok(value)
            }
            _ => Err(CborError::Invalid),
        }
    }

    fn read_byte(&mut self) -> CborResult<u8> {
        let byte = *self.input.get(self.pos).ok_or(CborError::Invalid)?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> CborResult<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(CborError::Invalid)?;
        if end > self.input.len() {
            return Err(CborError::Invalid);
        }
        let bytes = &self.input[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
}
