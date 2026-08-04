use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// Compute SHA-256 digest of data, return as [u8; 32].
pub(crate) fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256_digest(data);
    hex::encode(digest)
}

/// FNV-1a 32-bit hash.
pub fn fnv1a_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Compute all 4 detection hashes for a secret value.
pub fn compute_detection_hashes(secret: &[u8]) -> Vec<String> {
    // [0] raw
    let raw = sha256_hex(secret);

    // [1] base64
    let b64 = BASE64.encode(secret);
    let b64_hash = sha256_hex(b64.as_bytes());

    // [2] hex
    let hex_str = hex::encode(secret);
    let hex_hash = sha256_hex(hex_str.as_bytes());

    // [3] trimmed (leading/trailing whitespace only, like Python strip())
    let start = secret.iter().position(|&c| c != b' ' && c != b'\t' && c != b'\n' && c != b'\r').unwrap_or(secret.len());
    let end = secret.iter().rposition(|&c| c != b' ' && c != b'\t' && c != b'\n' && c != b'\r').map(|i| i + 1).unwrap_or(0);
    let trimmed = &secret[start..end];
    let trimmed_hash = if trimmed.len() < secret.len() {
        sha256_hex(trimmed)
    } else {
        raw.clone()
    };

    if trimmed.len() < secret.len() {
        vec![raw, b64_hash, hex_hash, trimmed_hash]
    } else {
        vec![raw, b64_hash, hex_hash]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hex = sha256_hex(b"");
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_known_value() {
        let hex = sha256_hex(b"hello");
        assert_eq!(
            hex,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_fnv1a_empty() {
        assert_eq!(fnv1a_hash(b""), 0x811c9dc5);
    }

    #[test]
    fn test_fnv1a_foobar() {
        assert_eq!(fnv1a_hash(b"foobar"), 0xbf9cf968);
    }

    #[test]
    fn test_compute_detection_hashes_count() {
        let hashes = compute_detection_hashes(b"test-secret");
        assert_eq!(hashes.len(), 3);
    }

    #[test]
    fn test_compute_detection_hashes_raw() {
        let hashes = compute_detection_hashes(b"test");
        let expected_raw = sha256_hex(b"test");
        assert_eq!(hashes[0], expected_raw);
    }

    #[test]
    fn test_compute_detection_hashes_base64() {
        let hashes = compute_detection_hashes(b"test");
        let b64 = BASE64.encode(b"test");
        let expected_b64 = sha256_hex(b64.as_bytes());
        assert_eq!(hashes[1], expected_b64);
    }

    #[test]
    fn test_compute_detection_hashes_hex() {
        let hashes = compute_detection_hashes(b"\x01\x02\x03");
        let hex_str = hex::encode(b"\x01\x02\x03");
        let expected_hex = sha256_hex(hex_str.as_bytes());
        assert_eq!(hashes[2], expected_hex);
    }

    #[test]
    fn test_compute_detection_hashes_trimmed() {
        let secret = b"  hello  ";
        let hashes = compute_detection_hashes(secret);
        let trimmed_hash = sha256_hex(b"hello");
        assert_eq!(hashes[3], trimmed_hash);
    }

    #[test]
    fn test_compute_detection_hashes_no_trim() {
        let secret = b"no-whitespace";
        let hashes = compute_detection_hashes(secret);
        assert_eq!(hashes.len(), 3);
    }

    #[test]
    fn test_base64_encoding() {
        assert_eq!(BASE64.encode(b""), "");
        assert_eq!(BASE64.encode(b"foo"), "Zm9v");
        assert_eq!(BASE64.encode(b"foob"), "Zm9vYg==");
        assert_eq!(BASE64.encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(BASE64.encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_hex_encoding() {
        assert_eq!(hex::encode(b""), "");
        assert_eq!(hex::encode(b"foo"), "666f6f");
        assert_eq!(hex::encode(&[0x01, 0x02, 0x03]), "010203");
    }

    #[test]
    fn test_computed_hashes_are_unique() {
        let hashes = compute_detection_hashes(b"  unique secret value 12345  ");
        let mut unique = hashes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 4, "all 4 hashes should be unique");
    }

    #[test]
    fn test_hash_consistency() {
        let secret = b"consistency-test";
        let hashes1 = compute_detection_hashes(secret);
        let hashes2 = compute_detection_hashes(secret);
        assert_eq!(hashes1, hashes2);
    }
}
