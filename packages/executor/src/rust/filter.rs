use std::collections::{HashMap, HashSet};

use base64::Engine;

use crate::hashes::{sha256_digest, fnv1a_hash};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SecretEntry {
    pub secret_id: String,
    pub hashes: Vec<String>,
    pub secret_value: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FilterEntry {
    pub key: [u8; 32],
    pub sid: [u8; 64],
    pub len: usize,
    pub first_byte: u8,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FnvEntry {
    pub hash: u32,
    pub len: usize,
    pub sid: [u8; 64],
    pub next: Option<usize>,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct FnvTable {
    pub buckets: Vec<Option<usize>>,
    pub entries: Vec<FnvEntry>,
    capacity: usize,
}

#[derive(Debug)]
pub struct FilterState {
    pub hash_map: HashMap<[u8; 32], [u8; 64]>,
    pub filter_entries: Vec<FilterEntry>,
    pub fnv_table: FnvTable,
    pub first_byte_filter_idx: [Vec<usize>; 256],
}

impl FnvTable {
    pub fn new(capacity: usize) -> Self {
        Self {
            buckets: vec![None; capacity],
            entries: Vec::with_capacity(capacity),
            capacity,
        }
    }

    pub fn add(&mut self, hash: u32, data: &[u8], sid: &[u8; 64]) {
        for entry in &self.entries {
            if entry.hash == hash && entry.len == data.len() && entry.data == data {
                return;
            }
        }

        let idx = self.entries.len();
        let entry = FnvEntry {
            hash,
            len: data.len(),
            sid: *sid,
            next: None,
            data: data.to_vec(),
        };

        let bucket = (hash as usize) % self.capacity;
        let old_first = self.buckets[bucket];
        self.entries.push(entry);
        self.entries[idx].next = old_first;
        self.buckets[bucket] = Some(idx);
    }

    pub fn get(&self, data: &[u8], len: usize) -> Option<&FnvEntry> {
        use crate::hashes::fnv1a_hash;
        let hash = fnv1a_hash(data);
        let bucket = (hash as usize) % self.capacity;

        let mut current = self.buckets[bucket];
        while let Some(idx) = current {
            let entry = &self.entries[idx];
            if entry.hash == hash && entry.len == len {
                return Some(entry);
            }
            current = entry.next;
        }
        None
    }
}

impl FilterState {
    pub fn new(entries: &[SecretEntry]) -> Self {
        let mut state = Self {
            hash_map: HashMap::with_capacity(entries.len() * 4),
            filter_entries: Vec::with_capacity(entries.len() * 4),
            fnv_table: FnvTable::new(4096),
            first_byte_filter_idx: std::array::from_fn(|_| Vec::new()),
        };

        for entry in entries {
            state.add_entry(entry);
        }

        state.filter_entries.sort_by(|a, b| b.len.cmp(&a.len));
        state.rebuild_first_byte_index();

        state
    }

    fn add_entry(&mut self, entry: &SecretEntry) {
        let sid_bytes = entry.secret_id.as_bytes();
        let mut sid = [0u8; 64];
        sid[..sid_bytes.len()].copy_from_slice(sid_bytes);

        self.add_variant(&entry.secret_value, &sid);

        let b64 = base64::engine::general_purpose::STANDARD.encode(&entry.secret_value);
        self.add_variant(b64.as_bytes(), &sid);

        let hex_str = hex::encode(&entry.secret_value);
        self.add_variant(hex_str.as_bytes(), &sid);

        let trimmed: Vec<u8> = entry
            .secret_value
            .iter()
            .copied()
            .filter(|&c| c != b' ' && c != b'\t' && c != b'\n' && c != b'\r')
            .collect();
        if trimmed.len() < entry.secret_value.len() {
            self.add_variant(&trimmed, &sid);
        }
    }

    fn add_variant(&mut self, value: &[u8], sid: &[u8; 64]) {
        if value.is_empty() {
            return;
        }

        let hash = sha256_digest(value);
        let len = value.len();

        self.hash_map.insert(hash, *sid);

        self.filter_entries.push(FilterEntry {
            key: hash,
            sid: *sid,
            len,
            first_byte: value[0],
        });

        self.fnv_table.add(fnv1a_hash(value), value, sid);
    }

    fn rebuild_first_byte_index(&mut self) {
        for idx in 0..256 {
            self.first_byte_filter_idx[idx].clear();
        }
        for (idx, fe) in self.filter_entries.iter().enumerate() {
            self.first_byte_filter_idx[fe.first_byte as usize].push(idx);
        }
    }
}

pub fn redact(result: &mut Vec<u8>, sid: &[u8; 64], max: usize) {
    let truncated = &sid[..8];
    let trimmed = truncated.split(|&b| b == 0).next().unwrap_or(truncated);
    let marker = format!("[REDACTED:{}]", String::from_utf8_lossy(trimmed));
    let marker_len = marker.len();

    if result.len() + marker_len <= max || max == 0 {
        result.extend_from_slice(marker.as_bytes());
    }
}

pub fn extract_ids(result: &[u8]) -> Vec<String> {
    const MARKER_START: &[u8] = b"[REDACTED:";
    const MARKER_START_LEN: usize = MARKER_START.len();
    let len = result.len();
    let mut seen = HashSet::new();

    let mut p = 0;
    while p + MARKER_START_LEN <= len {
        if result[p..p + MARKER_START_LEN] == MARKER_START[..] {
            let bracket_end = p + MARKER_START_LEN..len;
            if let Some(end) = result[bracket_end].iter().position(|&b| b == b']') {
                let id_bytes = &result[p + MARKER_START_LEN..p + MARKER_START_LEN + end];
                if let Ok(id) = String::from_utf8(id_bytes.to_vec()) {
                    seen.insert(id);
                }
                p = p + MARKER_START_LEN + end + 1;
                continue;
            }
        }
        p += 1;
    }

    let mut ids: Vec<String> = seen.into_iter().collect();
    ids.sort();
    ids
}

/// Check all known secrets at position `i`. Returns new position if match found.
/// Checks longest secrets first to handle nested/prefix cases correctly.
fn scan_at_position(
    output: &[u8],
    state: &FilterState,
    i: usize,
    max_output: usize,
    result: &mut Vec<u8>,
    last_sid: &mut [u8; 64],
) -> Option<usize> {
    let first_byte = output[i];
    for &entry_idx in &state.first_byte_filter_idx[first_byte as usize] {
        let fe = &state.filter_entries[entry_idx];
        if i + fe.len > output.len() {
            continue;
        }

        if state.fnv_table.get(&output[i..i + fe.len], fe.len).is_none() {
            continue;
        }

        let digest = sha256_digest(&output[i..i + fe.len]);
        if let Some(sid) = state.hash_map.get(&digest) {
            redact(result, sid, max_output);
            *last_sid = *sid;
            return Some(i + fe.len);
        }
    }
    None
}

pub fn filter_output(
    output: &[u8],
    state: &FilterState,
) -> (Vec<u8>, Vec<String>) {
    if output.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut result = Vec::with_capacity(output.len() + 2048);
    let mut last_sid: [u8; 64] = [0u8; 64];
    let mut i = 0;
    let max_output = output.len() + 2048;

    while i < output.len() {
        if let Some(new_i) = scan_at_position(output, state, i, max_output, &mut result, &mut last_sid) {
            i = new_i;
            continue;
        }

        if result.len() < max_output - 1 {
            result.push(output[i]);
        }
        i += 1;
    }

    let ids = extract_ids(&result);
    (result, ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv_table_add_and_get() {
        let mut table = FnvTable::new(4096);
        let sid = [0u8; 64];
        let hash = fnv1a_hash(b"test");
        table.add(hash, b"test", &sid);
        assert!(table.get(b"test", 4).is_some());
        assert!(table.get(b"notfound", 8).is_none());
    }

    #[test]
    fn test_fnv_table_duplicate_prevention() {
        let mut table = FnvTable::new(4096);
        let sid1 = [0u8; 64];
        let sid2 = [1u8; 64];
        let hash = fnv1a_hash(b"test");
        table.add(hash, b"test", &sid1);
        table.add(hash, b"test", &sid2);
        assert_eq!(table.entries.len(), 1);
    }

    #[test]
    fn test_fnv_table_chaining() {
        let mut table = FnvTable::new(4096);
        let sid = [0u8; 64];
        let hash_aaa = fnv1a_hash(b"aaa");
        let hash_bbb = fnv1a_hash(b"bbb");
        let hash_ccc = fnv1a_hash(b"ccc");
        table.add(hash_aaa, b"aaa", &sid);
        table.add(hash_bbb, b"bbb", &sid);
        table.add(hash_ccc, b"ccc", &sid);
        assert_eq!(table.entries.len(), 3);
        assert!(table.get(b"aaa", 3).is_some());
        assert!(table.get(b"bbb", 3).is_some());
        assert!(table.get(b"ccc", 3).is_some());
    }

    #[test]
    fn test_filter_state_new_empty() {
        let state = FilterState::new(&[]);
        assert!(state.hash_map.is_empty());
        assert!(state.filter_entries.is_empty());
    }

    #[test]
    fn test_filter_state_add_entry() {
        let entries = vec![SecretEntry {
            secret_id: "test".to_string(),
            hashes: vec![],
            secret_value: b"hello".to_vec(),
        }];
        let state = FilterState::new(&entries);
        assert!(state.hash_map.len() >= 1);
    }

    #[test]
    fn test_filter_output_stub_empty() {
        let state = FilterState::new(&[]);
        let (result, ids) = filter_output(b"test", &state);
        assert_eq!(result, b"test");
        assert!(ids.is_empty());
    }

    #[test]
    fn test_redact_inserts_marker() {
        let mut result = b"some data here".to_vec();
        let mut sid = [0u8; 64];
        let id_bytes = b"abcdef12";
        sid[..id_bytes.len()].copy_from_slice(id_bytes);
        redact(&mut result, &sid, 0);
        let output = String::from_utf8_lossy(&result);
        assert!(output.contains("[REDACTED:abcdef12]"));
    }

    #[test]
    fn test_redact_truncates_sid_to_8_chars() {
        let mut result = Vec::new();
        let mut sid = [0u8; 64];
        sid[..24].copy_from_slice(b"this-is-a-long-secret-id");
        redact(&mut result, &sid, 0);
        let output = String::from_utf8_lossy(&result);
        assert_eq!(output, "[REDACTED:this-is-]");
    }

    #[test]
    fn test_redact_max_zero_includes_marker() {
        let mut result = b"data".to_vec();
        let sid = [0u8; 64];
        redact(&mut result, &sid, 0);
        assert!(result.len() > 4);
    }

    #[test]
    fn test_extract_ids_finds_markers_anywhere() {
        let mut result = b"start ".to_vec();
        let mut sid = [0u8; 64];
        sid[..8].copy_from_slice(b"12345678");
        redact(&mut result, &sid, 0);
        result.extend_from_slice(b" middle ");
        let mut sid2 = [0u8; 64];
        sid2[..8].copy_from_slice(b"abcdefgh");
        redact(&mut result, &sid2, 0);
        result.extend_from_slice(b" end");

        let ids = extract_ids(&result);
        assert_eq!(ids, vec!["12345678", "abcdefgh"]);
    }

    #[test]
    fn test_extract_ids_deduplicates() {
        let mut result = b"before ".to_vec();
        let mut sid = [0u8; 64];
        sid[..8].copy_from_slice(b"sameid12");
        redact(&mut result, &sid, 0);
        result.extend_from_slice(b" between ");
        redact(&mut result, &sid, 0);
        result.extend_from_slice(b" after");

        let ids = extract_ids(&result);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "sameid12");
    }

    #[test]
    fn test_extract_ids_empty_on_no_markers() {
        let result = b"no redaction markers here".to_vec();
        let ids = extract_ids(&result);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_extract_ids_adjacent_markers() {
        let result = b"[REDACTED:aaaa1111][REDACTED:bbbb2222]".to_vec();
        let ids = extract_ids(&result);
        assert_eq!(ids.len(), 2);
        assert_eq!(ids, vec!["aaaa1111", "bbbb2222"]);
    }

    #[test]
    fn test_extract_ids_short_buffer() {
        let result = b"[REDA".to_vec();
        let ids = extract_ids(&result);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_extract_ids_empty_buffer() {
        let result: Vec<u8> = Vec::new();
        let ids = extract_ids(&result);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_filter_output_stub_with_redaction() {
        let entries = vec![SecretEntry {
            secret_id: "test-secret".to_string(),
            hashes: vec![],
            secret_value: b"secret-value".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let (result, ids) = filter_output(b"before secret-value after", &state);
        let output = String::from_utf8_lossy(&result);
        assert!(output.contains("[REDACTED:"));
        assert!(!ids.is_empty());
    }

    #[test]
    fn test_filter_output_stub_empty_input() {
        let state = FilterState::new(&[]);
        let (result, ids) = filter_output(b"", &state);
        assert!(result.is_empty());
        assert!(ids.is_empty());
    }

    #[test]
    fn test_bug1_prefix_loss_processing_secret() {
        let entries = vec![SecretEntry {
            secret_id: "beta".to_string(),
            hashes: vec![],
            secret_value: b"secret-beta".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let (result, ids) = filter_output(
            b"Processing secret-beta for user",
            &state,
        );
        assert_eq!(
            result,
            b"Processing [REDACTED:beta] for user",
            "prefix bytes before secret must be preserved"
        );
        assert_eq!(ids, vec!["beta"]);
    }

    #[test]
    fn test_bug1_prefix_loss_hello_world() {
        let entries = vec![
            SecretEntry {
                secret_id: "a".to_string(),
                hashes: vec![],
                secret_value: b"hello".to_vec(),
            },
            SecretEntry {
                secret_id: "b".to_string(),
                hashes: vec![],
                secret_value: b"world".to_vec(),
            },
        ];
        let state = FilterState::new(&entries);
        let (result, ids) = filter_output(
            b"say hello and world today",
            &state,
        );
        assert_eq!(
            result,
            b"say [REDACTED:a] and [REDACTED:b] today",
            "prefix bytes before each secret must be preserved"
        );
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_bug1_prefix_loss_secret_at_zero() {
        let entries = vec![SecretEntry {
            secret_id: "x".to_string(),
            hashes: vec![],
            secret_value: b"start".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let (result, ids) = filter_output(b"start here", &state);
        assert_eq!(result, b"[REDACTED:x] here");
        assert_eq!(ids, vec!["x"]);
    }

    #[test]
    fn test_bug1_prefix_loss_secret_at_end() {
        let entries = vec![SecretEntry {
            secret_id: "y".to_string(),
            hashes: vec![],
            secret_value: b"end-here".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let (result, ids) = filter_output(b"the end-here", &state);
        assert_eq!(result, b"the [REDACTED:y]");
        assert_eq!(ids, vec!["y"]);
    }

    #[test]
    fn test_full_length_match_secret_longer_than_window() {
        let entries = vec![SecretEntry {
            secret_id: "long".to_string(),
            hashes: vec![],
            secret_value: b"this-is-a-very-long-secret-value".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let input = b"before this-is-a-very-long-secret-value after";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(output.contains("[REDACTED:long]"), "long secret should be redacted");
        assert!(output.contains("before "), "prefix before long secret must be preserved");
        assert!(output.contains(" after"), "suffix after long secret must be preserved");
        assert_eq!(ids, vec!["long"]);
    }

    #[test]
    fn test_full_length_match_secret_at_start_longer_than_window() {
        let entries = vec![SecretEntry {
            secret_id: "s".to_string(),
            hashes: vec![],
            secret_value: b"this-is-a-very-long-secret-value".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let (result, ids) = filter_output(b"this-is-a-very-long-secret-value after", &state);
        assert_eq!(result, b"[REDACTED:s] after");
        assert_eq!(ids, vec!["s"]);
    }

    #[test]
    fn test_full_length_match_secret_at_end_longer_than_window() {
        let entries = vec![SecretEntry {
            secret_id: "e".to_string(),
            hashes: vec![],
            secret_value: b"this-is-a-very-long-secret-value".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let (result, ids) = filter_output(b"before this-is-a-very-long-secret-value", &state);
        assert_eq!(result, b"before [REDACTED:e]");
        assert_eq!(ids, vec!["e"]);
    }

    #[test]
    fn test_repeated_secrets_all_redacted() {
        let entries = vec![SecretEntry {
            secret_id: "dup".to_string(),
            hashes: vec![],
            secret_value: b"dup".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let input = b"dup dup dup dup dup";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        let redact_count = output.matches("[REDACTED:dup]").count();
        assert_eq!(redact_count, 5, "all 5 occurrences of 'dup' should be redacted");
        let raw_dup_count = output.matches("dup").count() - output.matches("[REDACTED:dup]").count();
        assert_eq!(raw_dup_count, 0, "no raw 'dup' should remain in output");
        assert_eq!(ids, vec!["dup"]);
    }

    #[test]
    fn test_repeated_secrets_with_other_text() {
        let entries = vec![
            SecretEntry {
                secret_id: "aaa".to_string(),
                hashes: vec![],
                secret_value: b"secret-alpha".to_vec(),
            },
            SecretEntry {
                secret_id: "bbb".to_string(),
                hashes: vec![],
                secret_value: b"secret-beta".to_vec(),
            },
        ];
        let state = FilterState::new(&entries);
        let input = b"secret-alpha more secret-alpha end";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        let redact_count = output.matches("[REDACTED:aaa]").count();
        assert_eq!(redact_count, 2, "both occurrences of secret-alpha should be redacted");
        assert_eq!(ids, vec!["aaa"]);
    }

    #[test]
    fn test_full_length_match_prefix_preserved_exact_boundary() {
        let entries = vec![SecretEntry {
            secret_id: "b".to_string(),
            hashes: vec![],
            secret_value: b"this-is-a-very-long-secret-value".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let (result, ids) = filter_output(
            b"this-is-a-very-long-secret-value after",
            &state,
        );
        assert_eq!(result, b"[REDACTED:b] after");
        assert_eq!(ids, vec!["b"]);
    }

    #[test]
    fn test_full_length_match_prefix_preserved_with_text_before() {
        let entries = vec![SecretEntry {
            secret_id: "c".to_string(),
            hashes: vec![],
            secret_value: b"this-is-a-very-long-secret-value".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let (result, ids) = filter_output(
            b"the this-is-a-very-long-secret-value after",
            &state,
        );
        assert_eq!(result, b"the [REDACTED:c] after");
        assert_eq!(ids, vec!["c"]);
    }

    #[test]
    fn test_full_length_match_no_prefix_needed() {
        let entries = vec![SecretEntry {
            secret_id: "d".to_string(),
            hashes: vec![],
            secret_value: b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let (result, ids) = filter_output(
            b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            &state,
        );
        assert_eq!(result, b"[REDACTED:d]");
        assert_eq!(ids, vec!["d"]);
    }

    #[test]
    fn test_full_length_match_mixed_with_window() {
        let entries = vec![
            SecretEntry {
                secret_id: "short".to_string(),
                hashes: vec![],
                secret_value: b"SHORT".to_vec(),
            },
            SecretEntry {
                secret_id: "long".to_string(),
                hashes: vec![],
                secret_value: b"THIS-IS-A-LONG-SECRET-VALUE-THAT-EXCEEDS-TEN".to_vec(),
            },
        ];
        let state = FilterState::new(&entries);
        let input = b"before SHORT after THIS-IS-A-LONG-SECRET-VALUE-THAT-EXCEEDS-TEN end";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(output.contains("[REDACTED:short]"), "short secret should be redacted");
        assert!(output.contains("[REDACTED:long]"), "long secret should be redacted");
        assert!(output.contains("before "), "prefix before short secret must be preserved");
        assert!(output.contains(" end"), "suffix after long secret must be preserved");
        assert_eq!(ids, vec!["long", "short"]);
    }

    fn sorted_ids(ids: &[String]) -> Vec<String> {
        let mut s = ids.to_vec();
        s.sort();
        s
    }

    #[test]
    fn test_bug3_same_prefix_three_secrets() {
        let entries = vec![
            SecretEntry { secret_id: "alpha".to_string(), hashes: vec![], secret_value: b"x-secret-alpha-x-1234567890".to_vec() },
            SecretEntry { secret_id: "beta".to_string(), hashes: vec![], secret_value: b"x-secret-beta-x-abcdefghij".to_vec() },
            SecretEntry { secret_id: "gamma".to_string(), hashes: vec![], secret_value: b"x-secret-gamma-x-0987654321".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let input = b"x-secret-alpha-x-1234567890 x-secret-beta-x-abcdefghij x-secret-gamma-x-0987654321";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.contains("x-secret-alpha-x-1234567890"), "alpha secret must be fully redacted");
        assert!(!output.contains("x-secret-beta-x-abcdefghij"), "beta secret must be fully redacted");
        assert!(!output.contains("x-secret-gamma-x-0987654321"), "gamma secret must be fully redacted");
        assert!(output.contains("[REDACTED:alpha]"), "alpha redaction marker missing");
        assert!(output.contains("[REDACTED:beta]"), "beta redaction marker missing");
        assert!(output.contains("[REDACTED:gamma]"), "gamma redaction marker missing");
        assert_eq!(sorted_ids(&ids), vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()]);
    }

    #[test]
    fn test_bug3_same_prefix_shared_prefix_numbers() {
        let entries = vec![
            SecretEntry { secret_id: "s1".to_string(), hashes: vec![], secret_value: b"SHARED_PREFIX_001".to_vec() },
            SecretEntry { secret_id: "s2".to_string(), hashes: vec![], secret_value: b"SHARED_PREFIX_002".to_vec() },
            SecretEntry { secret_id: "s3".to_string(), hashes: vec![], secret_value: b"SHARED_PREFIX_003".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let input = b"SHARED_PREFIX_001 SHARED_PREFIX_002 SHARED_PREFIX_003";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.contains("SHARED_PREFIX_001"), "s1 must be redacted");
        assert!(!output.contains("SHARED_PREFIX_002"), "s2 must be redacted");
        assert!(!output.contains("SHARED_PREFIX_003"), "s3 must be redacted");
        assert_eq!(sorted_ids(&ids), vec!["s1".to_string(), "s2".to_string(), "s3".to_string()]);
    }

    #[test]
    fn test_bug3_identical_values_different_ids() {
        let entries = vec![
            SecretEntry { secret_id: "id1".to_string(), hashes: vec![], secret_value: b"same-value".to_vec() },
            SecretEntry { secret_id: "id2".to_string(), hashes: vec![], secret_value: b"same-value".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let input = b"same-value and same-value";
        let (result, _ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(output.matches("same-value").count() == 0, "no raw 'same-value' should remain");
        assert!(output.matches("[REDACTED:").count() >= 2, "both instances should be redacted");
    }

    #[test]
    fn test_bug3_same_length_same_prefix_all_masked() {
        let entries = vec![
            SecretEntry { secret_id: "aaa".to_string(), hashes: vec![], secret_value: b"SHARED_PREFIX_AAA".to_vec() },
            SecretEntry { secret_id: "bbb".to_string(), hashes: vec![], secret_value: b"SHARED_PREFIX_BBB".to_vec() },
            SecretEntry { secret_id: "ccc".to_string(), hashes: vec![], secret_value: b"SHARED_PREFIX_CCC".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let sha_a = sha256_digest(b"SHARED_PREFIX_AAA");
        let sha_b = sha256_digest(b"SHARED_PREFIX_BBB");
        let sha_c = sha256_digest(b"SHARED_PREFIX_CCC");
        assert_ne!(sha_a, sha_b);
        assert_ne!(sha_b, sha_c);
        assert_ne!(sha_a, sha_c);
        let raw_count = state.filter_entries.iter().filter(|fe| fe.len == 17 && fe.sid != [0u8; 64]).count();
        assert!(raw_count >= 3, "filter_entries must have at least 3 entries of length 17, got {}", raw_count);
        let input = b"SHARED_PREFIX_AAA and SHARED_PREFIX_BBB and SHARED_PREFIX_CCC";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.contains("SHARED_PREFIX_AAA"), "AAA must be redacted");
        assert!(!output.contains("SHARED_PREFIX_BBB"), "BBB must be redacted");
        assert!(!output.contains("SHARED_PREFIX_CCC"), "CCC must be redacted");
        assert_eq!(sorted_ids(&ids), vec!["aaa".to_string(), "bbb".to_string(), "ccc".to_string()]);
    }

    #[test]
    fn test_bug3_fnv_collision_sha256_verification() {
        let data_a = b"AAAAAAAABBBBCCCC";
        let data_b = b"1111111122223333";
        let entries = vec![
            SecretEntry { secret_id: "collision_a".to_string(), hashes: vec![], secret_value: data_a.to_vec() },
            SecretEntry { secret_id: "collision_b".to_string(), hashes: vec![], secret_value: data_b.to_vec() },
        ];
        let state = FilterState::new(&entries);
        assert_ne!(data_a, data_b);
        assert!(state.fnv_table.get(data_a, data_a.len()).is_some());
        assert!(state.fnv_table.get(data_b, data_b.len()).is_some());
        let sha_a = sha256_digest(data_a);
        let sha_b = sha256_digest(data_b);
        assert!(state.hash_map.contains_key(&sha_a));
        assert!(state.hash_map.contains_key(&sha_b));
        let input = b"test AAAAAAAAABBBBCCCC end 1111111122223333 done";
        let (result, _ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.contains("AAAAAAAABBBBCCCC"), "collision_a must be redacted");
        assert!(!output.contains("1111111122223333"), "collision_b must be redacted");
        let redact_count = output.matches("[REDACTED:collisio]").count();
        assert_eq!(redact_count, 2, "both secrets should be redacted");
    }

    #[test]
    fn test_bug3_many_same_prefix_secrets() {
        let mut entries = Vec::new();
        let mut input_parts = Vec::new();
        for i in 0..20 {
            let id = format!("sec{:02}", i);
            let value = format!("common-prefix-unique-identifier-{:04}", i);
            entries.push(SecretEntry { secret_id: id.clone(), hashes: vec![], secret_value: value.as_bytes().to_vec() });
            input_parts.push(value);
        }
        let state = FilterState::new(&entries);
        let input_str = input_parts.join(" ");
        let input = input_str.as_bytes();
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        for i in 0..20 {
            let value = format!("common-prefix-unique-identifier-{:04}", i);
            assert!(!output.contains(&value), "secret {:02} must be redacted", i);
        }
        assert_eq!(ids.len(), 20, "all 20 same-prefix secret IDs must be extracted");
    }

    #[test]
    fn test_bug3_prefix_variants_all_detected() {
        let entries = vec![
            SecretEntry { secret_id: "v1".to_string(), hashes: vec![], secret_value: b"prefix-ApI-key-0001".to_vec() },
            SecretEntry { secret_id: "v2".to_string(), hashes: vec![], secret_value: b"prefix-ApI-key-0002".to_vec() },
            SecretEntry { secret_id: "v3".to_string(), hashes: vec![], secret_value: b"prefix-ApI-key-0003".to_vec() },
            SecretEntry { secret_id: "v4".to_string(), hashes: vec![], secret_value: b"prefix-ApI-key-0004".to_vec() },
            SecretEntry { secret_id: "v5".to_string(), hashes: vec![], secret_value: b"prefix-ApI-key-0005".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let input = b"prefix-ApI-key-0001 text prefix-ApI-key-0002 text prefix-ApI-key-0003 text prefix-ApI-key-0004 text prefix-ApI-key-0005 text";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        for i in 1..=5 {
            let value = format!("prefix-ApI-key-000{}", i);
            assert!(!output.contains(&value), "{} must be redacted", value);
        }
        let expected = vec!["v1", "v2", "v3", "v4", "v5"].into_iter().map(String::from).collect::<Vec<_>>();
        assert_eq!(sorted_ids(&ids), expected);
    }

    #[test]
    fn test_bug3_consecutive_same_prefix() {
        let entries = vec![
            SecretEntry { secret_id: "x1".to_string(), hashes: vec![], secret_value: b"common-AAAA".to_vec() },
            SecretEntry { secret_id: "x2".to_string(), hashes: vec![], secret_value: b"common-BBBB".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let input = b"common-AAAAcommon-BBBB";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.contains("common-AAAA"), "x1 must be redacted");
        assert!(!output.contains("common-BBBB"), "x2 must be redacted");
        assert_eq!(sorted_ids(&ids), vec!["x1".to_string(), "x2".to_string()]);
    }

    #[test]
    fn test_bug3_nested_prefix_substring() {
        let entries = vec![
            SecretEntry { secret_id: "short".to_string(), hashes: vec![], secret_value: b"token-ABC".to_vec() },
            SecretEntry { secret_id: "long".to_string(), hashes: vec![], secret_value: b"token-ABCDEF".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let input = b"token-ABCDEF and token-ABC";
        let (result, _ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.contains("token-ABCDEF"), "long secret must be redacted");
        assert!(output.contains("[REDACTED:") && output.matches("[REDACTED:").count() >= 1, "at least one redaction marker");
    }

    #[test]
    fn test_bug3_fnv_table_stores_all_different_data() {
        let mut table = FnvTable::new(4096);
        let sid1 = [1u8; 64];
        let sid2 = [2u8; 64];
        let sid3 = [3u8; 64];
        let data1 = b"SHARED_PREFIX_AAA";
        let data2 = b"SHARED_PREFIX_BBB";
        let data3 = b"SHARED_PREFIX_CCC";
        table.add(fnv1a_hash(data1), data1, &sid1);
        table.add(fnv1a_hash(data2), data2, &sid2);
        table.add(fnv1a_hash(data3), data3, &sid3);
        assert_eq!(table.entries.len(), 3);
        assert!(table.get(data1, data1.len()).is_some());
        assert!(table.get(data2, data2.len()).is_some());
        assert!(table.get(data3, data3.len()).is_some());
    }

    #[test]
    fn test_bug3_fnv_table_duplicate_data_same_hash_same_length() {
        let mut table = FnvTable::new(4096);
        let sid1 = [1u8; 64];
        let sid2 = [2u8; 64];
        let data = b"SHARED_PREFIX_AAA";
        let hash = fnv1a_hash(data);
        table.add(hash, data, &sid1);
        table.add(hash, data, &sid2);
        assert_eq!(table.entries.len(), 1, "duplicate entries should be rejected");
    }

    #[test]
    fn test_bug3_hash_map_different_sha256_for_different_values() {
        let entries = vec![
            SecretEntry { secret_id: "h1".to_string(), hashes: vec![], secret_value: b"prefix-unique-A".to_vec() },
            SecretEntry { secret_id: "h2".to_string(), hashes: vec![], secret_value: b"prefix-unique-B".to_vec() },
            SecretEntry { secret_id: "h3".to_string(), hashes: vec![], secret_value: b"prefix-unique-C".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let sha_a = sha256_digest(b"prefix-unique-A");
        let sha_b = sha256_digest(b"prefix-unique-B");
        let sha_c = sha256_digest(b"prefix-unique-C");
        assert_ne!(sha_a, sha_b);
        assert_ne!(sha_b, sha_c);
        assert_ne!(sha_a, sha_c);
        assert!(state.hash_map.contains_key(&sha_a));
        assert!(state.hash_map.contains_key(&sha_b));
        assert!(state.hash_map.contains_key(&sha_c));
    }

    #[test]
    fn test_bug3_mixed_prefix_and_non_prefix_secrets() {
        let entries = vec![
            SecretEntry { secret_id: "p1".to_string(), hashes: vec![], secret_value: b"shared-prefix-AAAA".to_vec() },
            SecretEntry { secret_id: "p2".to_string(), hashes: vec![], secret_value: b"shared-prefix-BBBB".to_vec() },
            SecretEntry { secret_id: "unrelated".to_string(), hashes: vec![], secret_value: b"completely-different-secret".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let input = b"shared-prefix-AAAA and shared-prefix-BBBB and completely-different-secret";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.contains("shared-prefix-AAAA"));
        assert!(!output.contains("shared-prefix-BBBB"));
        assert!(!output.contains("completely-different-secret"));
        let expected = vec!["p1".to_string(), "p2".to_string(), "unrelate".to_string()];
        assert_eq!(sorted_ids(&ids), expected);
    }

    #[test]
    fn test_bug3_same_prefix_with_base64_variants() {
        let entries = vec![
            SecretEntry { secret_id: "b64a".to_string(), hashes: vec![], secret_value: b"api-key-0001".to_vec() },
            SecretEntry { secret_id: "b64b".to_string(), hashes: vec![], secret_value: b"api-key-0002".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let b64_a = base64::engine::general_purpose::STANDARD.encode(b"api-key-0001");
        let b64_b = base64::engine::general_purpose::STANDARD.encode(b"api-key-0002");
        let input = b"api-key-0001 and api-key-0002";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.contains("api-key-0001"));
        assert!(!output.contains("api-key-0002"));
        assert_eq!(sorted_ids(&ids), vec!["b64a".to_string(), "b64b".to_string()]);
        let input_b64_str = format!("encoded: {} and {}", b64_a, b64_b);
        let input_b64 = input_b64_str.as_bytes();
        let (result_b64, _ids_b64) = filter_output(input_b64, &state);
        let output_b64 = String::from_utf8_lossy(&result_b64);
        assert!(!output_b64.contains(&b64_a));
        assert!(!output_b64.contains(&b64_b));
    }

    #[test]
    fn test_bug3_fnv_collision_same_hash_different_data() {
        // Test that entries with different data are stored independently.
        // In practice, different data produces different FNV hashes, so they
        // go in different buckets. This verifies the basic add/get behavior.
        let mut table = FnvTable::new(4096);
        let sid1 = [1u8; 64];
        let sid2 = [2u8; 64];
        let data1 = b"COLLISION_AAAA";
        let data2 = b"COLLISION_BBBB";
        table.add(fnv1a_hash(data1), data1, &sid1);
        table.add(fnv1a_hash(data2), data2, &sid2);
        assert_eq!(table.entries.len(), 2, "different data should be stored independently");
        assert!(table.get(data1, data1.len()).is_some());
        assert!(table.get(data2, data2.len()).is_some());
    }

    #[test]
    fn test_hash_functions_fnv1a_consistent() {
        assert_eq!(fnv1a_hash(b"test"), fnv1a_hash(b"test"));
        assert_ne!(fnv1a_hash(b"test"), fnv1a_hash(b"other"));
    }

    #[test]
    fn test_hash_functions_sha256_consistent() {
        assert_eq!(sha256_digest(b"test"), sha256_digest(b"test"));
        assert_ne!(sha256_digest(b"test"), sha256_digest(b"other"));
    }

    #[test]
    fn test_hash_functions_sha256_output_size() {
        let digest = sha256_digest(b"test");
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_hash_functions_base64_encode() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"hello");
        assert_eq!(encoded, "aGVsbG8=");
    }

    #[test]
    fn test_hash_functions_hex_encode() {
        let encoded = hex::encode(b"hello");
        assert_eq!(encoded, "68656c6c6f");
    }

    #[test]
    fn test_filter_output_multiple_different_secrets() {
        let entries = vec![
            SecretEntry { secret_id: "a".to_string(), hashes: vec![], secret_value: b"SECRET_A".to_vec() },
            SecretEntry { secret_id: "b".to_string(), hashes: vec![], secret_value: b"SECRET_B".to_vec() },
            SecretEntry { secret_id: "c".to_string(), hashes: vec![], secret_value: b"SECRET_C".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let input = b"before SECRET_A middle SECRET_B after SECRET_C end";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.contains("SECRET_A"));
        assert!(!output.contains("SECRET_B"));
        assert!(!output.contains("SECRET_C"));
        assert_eq!(sorted_ids(&ids), vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn test_filter_output_secret_at_start_and_end() {
        let entries = vec![
            SecretEntry { secret_id: "first".to_string(), hashes: vec![], secret_value: b"START".to_vec() },
            SecretEntry { secret_id: "last".to_string(), hashes: vec![], secret_value: b"END".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let input = b"START middle END";
        let (result, ids) = filter_output(input, &state);
        assert_eq!(result, b"[REDACTED:first] middle [REDACTED:last]");
        assert_eq!(sorted_ids(&ids), vec!["first".to_string(), "last".to_string()]);
    }

    #[test]
    fn test_filter_output_overlapping_secrets_longer_first() {
        let entries = vec![
            SecretEntry { secret_id: "long".to_string(), hashes: vec![], secret_value: b"ABCDEFGHIJ".to_vec() },
            SecretEntry { secret_id: "short".to_string(), hashes: vec![], secret_value: b"CDEF".to_vec() },
        ];
        let state = FilterState::new(&entries);
        let input = b"ABCDEFGHIJ";
        let (result, _ids) = filter_output(input, &state);
        // Longer secret should match first (it's checked first due to insertion order)
        let output = String::from_utf8_lossy(&result);
        assert!(output.contains("[REDACTED:"));
        assert!(!output.contains("ABCDEFGHIJ"));
    }

    #[test]
    fn test_filter_output_binary_data() {
        let entries = vec![SecretEntry {
            secret_id: "bin".to_string(),
            hashes: vec![],
            secret_value: b"\x80\x81\x82\x83".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let input = b"prefix \x80\x81\x82\x83 suffix";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(output.contains("[REDACTED:bin]"));
        assert_eq!(ids, vec!["bin"]);
    }

    #[test]
    fn test_filter_output_whitespace_in_secret() {
        let entries = vec![SecretEntry {
            secret_id: "ws".to_string(),
            hashes: vec![],
            secret_value: b"hello world".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let input = b"before hello world after";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        assert!(output.contains("[REDACTED:ws]"));
        assert!(!output.contains("hello world"), "raw secret should be redacted");
        assert_eq!(ids, vec!["ws"]);
    }

    #[test]
    fn test_filter_output_repeated_same_secret() {
        let entries = vec![SecretEntry {
            secret_id: "dup".to_string(),
            hashes: vec![],
            secret_value: b"AAAAAA".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let input = b"AAAAAA AAAAAA AAAAAA";
        let (result, ids) = filter_output(input, &state);
        let output = String::from_utf8_lossy(&result);
        let count = output.matches("[REDACTED:dup]").count();
        assert_eq!(count, 3, "all 3 occurrences should be redacted");
        assert_eq!(ids.len(), 1, "only one unique ID");
        assert_eq!(ids[0], "dup");
    }

    #[test]
    fn test_filter_output_no_match() {
        let entries = vec![SecretEntry {
            secret_id: "x".to_string(),
            hashes: vec![],
            secret_value: b"notpresent".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let input = b"nothing matches here";
        let (result, ids) = filter_output(input, &state);
        assert_eq!(result, input);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_filter_output_empty_secret_value() {
        let entries = vec![SecretEntry {
            secret_id: "empty".to_string(),
            hashes: vec![],
            secret_value: b"".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let input = b"some text";
        let (result, ids) = filter_output(input, &state);
        assert_eq!(result, input);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_filter_output_long_secret_at_various_positions() {
        let secret = b"this-is-a-very-long-secret-that-exceeds-twenty-bytes";
        let entries = vec![SecretEntry {
            secret_id: "long".to_string(),
            hashes: vec![],
            secret_value: secret.to_vec(),
        }];
        let state = FilterState::new(&entries);
        // Secret at position 0
        let (r1, _) = filter_output(secret, &state);
        assert_eq!(r1, b"[REDACTED:long]");
        // Secret at end
        let _r2 = filter_output(b"prefix ", &state);
        let full_input = [b"prefix ".as_slice(), secret].concat();
        let (r3, ids) = filter_output(&full_input, &state);
        let output = String::from_utf8_lossy(&r3);
        assert!(output.contains("[REDACTED:long]"));
        assert!(output.contains("prefix "));
        assert_eq!(ids, vec!["long"]);
    }

    #[test]
    fn test_fnv_table_empty() {
        let table = FnvTable::new(4096);
        assert_eq!(table.buckets.len(), 4096);
        assert_eq!(table.entries.len(), 0);
    }

    #[test]
    fn test_fnv_table_single_entry() {
        let mut table = FnvTable::new(4096);
        let sid = [42u8; 64];
        table.add(fnv1a_hash(b"test"), b"test", &sid);
        assert_eq!(table.entries.len(), 1);
        assert!(table.get(b"test", 4).is_some());
        assert!(table.get(b"other", 5).is_none());
    }

    #[test]
    fn test_fnv_table_bucket_distribution() {
        for i in 0..100 {
            let data = format!("secret-{}", i);
            let hash = fnv1a_hash(data.as_bytes());
            let _bucket = hash % 4096; // Just verify it computes without panic
        }
    }

    #[test]
    fn test_filter_output_truncated_output() {
        let entries = vec![SecretEntry {
            secret_id: "x".to_string(),
            hashes: vec![],
            secret_value: b"x".to_vec(),
        }];
        let state = FilterState::new(&entries);
        let input = b"xxxxxxxxxx";
        let (result, _ids) = filter_output(input, &state);
        // All x's should be redacted
        let output = String::from_utf8_lossy(&result);
        let redact_count = output.matches("[REDACTED:x]").count();
        assert_eq!(redact_count, 10);
    }

    #[test]
    fn test_bug5_scale_leak_debug() {
        // Reproduce the scale leak: 25 secrets, secret 15 leaks
        let n = 25;
        let entries: Vec<SecretEntry> = (0..n)
            .map(|i| SecretEntry {
                secret_id: format!("s-{:05}", i),
                hashes: vec![],
                secret_value: format!("multi-secret-value-{:04}-xyz", i).into_bytes(),
            })
            .collect();

        let mut parts: Vec<Vec<u8>> = Vec::new();
        for i in 0..n {
            if !parts.is_empty() {
                parts.push(vec![b' '; 90]);
            }
            parts.push(format!("multi-secret-value-{:04}-xyz", i).into_bytes());
        }
        let output: Vec<u8> = parts.concat();

        let state = FilterState::new(&entries);

        // Debug: check filter_entries count and lengths
        eprintln!("filter_entries count: {}", state.filter_entries.len());
        let s15_len = format!("multi-secret-value-{:04}-xyz", 15).len();
        eprintln!("s-00015 raw len: {}", s15_len);

        // Find filter_entries for s-00015
        for (idx, fe) in state.filter_entries.iter().enumerate() {
            let sid_str = String::from_utf8_lossy(&fe.sid[..fe.sid.iter().position(|&b| b == 0).unwrap_or(64)]);
            if sid_str.starts_with("s-00015") {
                eprintln!("  filter_entries[{}] sid={} len={}", idx, sid_str, fe.len);
            }
        }

        // Find where s-00015 appears in output
        let s15_bytes = format!("multi-secret-value-{:04}-xyz", 15).into_bytes();
        let mut found_pos = None;
        for pos in 0..=output.len().saturating_sub(s15_bytes.len()) {
            if output[pos..pos + s15_bytes.len()] == s15_bytes {
                found_pos = Some(pos);
                break;
            }
        }
        eprintln!("s-00015 found at output position: {:?}", found_pos);

        if let Some(pos) = found_pos {
            use crate::hashes::sha256_digest;
            let test_data = &output[pos..pos + s15_len];
            let computed_hash = fnv1a_hash(test_data);
            let bucket = (computed_hash as usize) % state.fnv_table.capacity;
            eprintln!("Computed FNV hash: 0x{:08x}, bucket: {}, table capacity: {}", computed_hash, bucket, state.fnv_table.capacity);
            eprintln!("Bucket entries: {}", state.fnv_table.buckets.len());
            eprintln!("Total FNV entries: {}", state.fnv_table.entries.len());
            
            // Check what's in the bucket
            if let Some(idx) = state.fnv_table.buckets[bucket] {
                eprintln!("Bucket {} points to entry index: {}", bucket, idx);
                let mut chain_len = 0;
                let mut current = Some(idx);
                while let Some(ci) = current {
                    let entry = &state.fnv_table.entries[ci];
                    chain_len += 1;
                    eprintln!("  Chain[{}] hash=0x{:08x} len={} sid={}", chain_len, entry.hash, entry.len, String::from_utf8_lossy(&entry.sid[..entry.sid.iter().position(|&b| b == 0).unwrap_or(64)]));
                    current = entry.next;
                }
                eprintln!("  Total chain length: {}", chain_len);
            } else {
                eprintln!("Bucket {} is EMPTY!", bucket);
            }

            // Test FNV lookup at this position
            let fnv_match = state.fnv_table.get(test_data, s15_len);
            eprintln!("FNV table match at pos {}: {:?}", pos, fnv_match.is_some());

            // Test SHA-256 lookup
            let digest = sha256_digest(test_data);
            let sha_match = state.hash_map.get(&digest);
            eprintln!("SHA-256 hash map match at pos {}: {:?}", pos, sha_match.is_some());
            if let Some(sid) = sha_match {
                let sid_str = String::from_utf8_lossy(&sid[..sid.iter().position(|&b| b == 0).unwrap_or(64)]);
                eprintln!("  SHA-256 matched sid: {}", sid_str);
            }
        }

        let (result, ids) = filter_output(&output, &state);
        let leaked = result.windows(s15_bytes.len()).any(|w| w == s15_bytes);
        eprintln!("Result contains s-00015 raw data: {}", leaked);
        eprintln!("IDs count: {}/{}", ids.len(), n);

        let s15_marker = b"[REDACTED:s-00015]";
        eprintln!("Result contains s-00015 redaction marker: {}", result.windows(s15_marker.len()).any(|w| w == s15_marker));

        assert!(!leaked, "s-00015 should be redacted but leaked");
        assert_eq!(ids.len(), n, "All {} IDs should be extracted", n);
    }

    #[test]
    fn test_random_secrets_ids() {
        // Simulate random secrets with known values
        let secrets = vec![
            (b"gTpigTHKbfoLISRABr1V".to_vec(), "s0"),
            (b"LYTH8xIZM1JRcoreogr".to_vec(), "s1"),
            (b"ZkwPRQeNHpCq5QnuVdYXye4JSnE2".to_vec(), "s2"),
        ];

        let entries: Vec<SecretEntry> = secrets.iter().map(|(val, id)| {
            SecretEntry {
                secret_id: id.to_string(),
                hashes: vec![],
                secret_value: val.clone(),
            }
        }).collect();

        let state = FilterState::new(&entries);
        let output = b"gTpigTHKbfoLISRABr1V LYTH8xIZM1JRcoreogr ZkwPRQeNHpCq5QnuVdYXye4JSnE2";

        let (result, ids) = filter_output(output, &state);
        let output_str = String::from_utf8_lossy(&result);

        eprintln!("Result: {}", output_str);
        eprintln!("IDs: {:?}", ids);
        eprintln!("Redacted count: {}", result.windows(b"[REDACTED:".len()).filter(|w| *w == b"[REDACTED:").count());

        // Check each secret is redacted with correct ID
        assert!(output_str.contains("[REDACTED:s0]"), "s0 should be redacted");
        assert!(output_str.contains("[REDACTED:s1]"), "s1 should be redacted");
        assert!(output_str.contains("[REDACTED:s2]"), "s2 should be redacted");
        assert_eq!(ids.len(), 3, "Should have 3 unique IDs");
    }
}
