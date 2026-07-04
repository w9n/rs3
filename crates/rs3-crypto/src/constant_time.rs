use subtle::ConstantTimeEq;

/// Constant-time byte comparison for secret material.
pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        let _ = left.ct_eq(left);
        return false;
    }
    left.ct_eq(right).into()
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn ct_eq_accepts_equal_slices() {
        assert!(ct_eq(b"same-secret", b"same-secret"));
    }

    #[test]
    fn ct_eq_rejects_same_length_difference() {
        assert!(!ct_eq(b"same-secret", b"same-secreu"));
    }

    #[test]
    fn ct_eq_rejects_length_mismatch() {
        assert!(!ct_eq(b"same-secret", b"same-secret-longer"));
    }
}
