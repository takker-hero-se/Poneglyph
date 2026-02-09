pub mod user;
pub mod computer;
pub mod group;
pub mod gpo;
pub mod trust;

use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::Cursor;

use crate::ese::NtdsDatabase;
use crate::schema;

// ==================== SID Parsing ====================

/// Parse a binary SID into its string representation (e.g., S-1-5-21-...-1001).
///
/// Note: In NTDS.dit ESE databases, the last sub-authority (RID) is stored in
/// big-endian byte order, while other sub-authorities use little-endian.
/// This function handles this mixed-endian format.
pub fn parse_sid(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }

    let revision = data[0];
    let sub_authority_count = data[1] as usize;

    // Authority: 6 bytes big-endian
    let mut authority: u64 = 0;
    for &b in &data[2..8] {
        authority = (authority << 8) | (b as u64);
    }

    let expected_len = 8 + sub_authority_count * 4;
    if data.len() < expected_len {
        return None;
    }

    let mut sid = format!("S-{}-{}", revision, authority);

    // Sub-authorities: 4 bytes each
    // All sub-authorities except the last use little-endian byte order.
    // The last sub-authority (RID) uses big-endian byte order in NTDS.dit ESE databases.
    for i in 0..sub_authority_count {
        let offset = 8 + i * 4;
        let bytes = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
        let sub = if i == sub_authority_count - 1 {
            u32::from_be_bytes(bytes) // RID: big-endian
        } else {
            u32::from_le_bytes(bytes) // Others: little-endian
        };
        sid.push_str(&format!("-{}", sub));
    }

    Some(sid)
}

/// Extract the RID (Relative Identifier) from a binary SID.
/// The RID is the last sub-authority value, stored in big-endian in NTDS.dit.
pub fn extract_rid(data: &[u8]) -> Option<u32> {
    if data.len() < 8 {
        return None;
    }

    let sub_authority_count = data[1] as usize;
    if sub_authority_count == 0 {
        return None;
    }

    let rid_offset = 8 + (sub_authority_count - 1) * 4;
    if data.len() < rid_offset + 4 {
        return None;
    }

    Some(u32::from_be_bytes([
        data[rid_offset],
        data[rid_offset + 1],
        data[rid_offset + 2],
        data[rid_offset + 3],
    ]))
}

/// Extract the domain SID portion (SID without the RID).
pub fn domain_sid(sid: &str) -> Option<String> {
    let parts: Vec<&str> = sid.rsplitn(2, '-').collect();
    if parts.len() == 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

// ==================== Timestamp Conversion ====================

/// Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
/// to a human-readable UTC datetime string.
pub fn filetime_to_string(filetime: i64) -> Option<String> {
    if filetime <= 0 || filetime == 0x7FFFFFFFFFFFFFFF {
        return None; // Never or not set
    }

    const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: i64 = 10_000_000;

    let unix_ticks = filetime - FILETIME_UNIX_DIFF;
    if unix_ticks < 0 {
        return None;
    }

    let secs = unix_ticks / TICKS_PER_SECOND;
    let nanos = ((unix_ticks % TICKS_PER_SECOND) * 100) as u32;

    chrono::DateTime::from_timestamp(secs, nanos)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

/// Convert FILETIME to Unix timestamp (seconds since epoch).
pub fn filetime_to_epoch(filetime: i64) -> Option<i64> {
    if filetime <= 0 || filetime == 0x7FFFFFFFFFFFFFFF {
        return None;
    }

    const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: i64 = 10_000_000;

    let unix_ticks = filetime - FILETIME_UNIX_DIFF;
    if unix_ticks < 0 {
        return None;
    }

    Some(unix_ticks / TICKS_PER_SECOND)
}

// ==================== UAC Flag Interpretation ====================

/// Interpret a UAC (userAccountControl) bitmask value.
pub fn describe_uac(uac: u32) -> Vec<&'static str> {
    use crate::schema::uac::*;

    let mut flags = Vec::new();
    if uac & ACCOUNTDISABLE != 0       { flags.push("DISABLED"); }
    if uac & LOCKOUT != 0              { flags.push("LOCKED"); }
    if uac & PASSWD_NOTREQD != 0       { flags.push("PASSWD_NOT_REQUIRED"); }
    if uac & NORMAL_ACCOUNT != 0       { flags.push("NORMAL_ACCOUNT"); }
    if uac & WORKSTATION_TRUST_ACCOUNT != 0 { flags.push("WORKSTATION_TRUST"); }
    if uac & SERVER_TRUST_ACCOUNT != 0 { flags.push("SERVER_TRUST (DC)"); }
    if uac & DONT_EXPIRE_PASSWORD != 0 { flags.push("DONT_EXPIRE_PASSWORD"); }
    if uac & SMARTCARD_REQUIRED != 0   { flags.push("SMARTCARD_REQUIRED"); }
    if uac & TRUSTED_FOR_DELEGATION != 0 { flags.push("TRUSTED_FOR_DELEGATION"); }
    if uac & NOT_DELEGATED != 0        { flags.push("NOT_DELEGATED"); }
    if uac & DONT_REQ_PREAUTH != 0     { flags.push("DONT_REQ_PREAUTH"); }
    if uac & PASSWORD_EXPIRED != 0     { flags.push("PASSWORD_EXPIRED"); }
    if uac & TRUSTED_TO_AUTH_FOR_DELEGATION != 0 { flags.push("TRUSTED_TO_AUTH_FOR_DELEG"); }
    flags
}

// ==================== Shared Record Helpers ====================
// These are used by user.rs, computer.rs, group.rs, gpo.rs, trust.rs

pub fn get_string_value(record: &libesedb::Record, col_idx: Option<i32>) -> Option<String> {
    let idx = col_idx?;
    match record.value(idx) {
        Ok(val) => {
            let s = val.to_string();
            if s.is_empty() || s == "NULL" {
                None
            } else {
                Some(s)
            }
        }
        Err(_) => None,
    }
}

pub fn get_i32_value(record: &libesedb::Record, col_idx: Option<i32>) -> Option<i32> {
    let idx = col_idx?;
    match record.value(idx) {
        Ok(val) => {
            let s = val.to_string();
            s.parse::<i32>().ok()
        }
        Err(_) => None,
    }
}

pub fn get_i64_value(record: &libesedb::Record, col_idx: Option<i32>) -> Option<i64> {
    let idx = col_idx?;
    match record.value(idx) {
        Ok(val) => {
            let s = val.to_string();
            s.parse::<i64>().ok()
        }
        Err(_) => None,
    }
}

pub fn get_binary_value(record: &libesedb::Record, col_idx: Option<i32>) -> Option<Vec<u8>> {
    let idx = col_idx?;
    match record.value(idx) {
        Ok(libesedb::Value::Binary(data)) if !data.is_empty() => Some(data),
        Ok(libesedb::Value::LargeBinary(data)) if !data.is_empty() => Some(data),
        Ok(libesedb::Value::Guid(data)) if !data.is_empty() => Some(data),
        _ => None,
    }
}

pub fn get_multi_string_value(record: &libesedb::Record, col_idx: Option<i32>) -> Vec<String> {
    let idx = match col_idx {
        Some(i) => i,
        None => return Vec::new(),
    };
    match record.value(idx) {
        Ok(val) => {
            let s = val.to_string();
            if s.is_empty() || s == "NULL" {
                Vec::new()
            } else {
                s.split(|c: char| c == '\0' || c == ';')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            }
        }
        Err(_) => Vec::new(),
    }
}

// ==================== DNT → SID Map ====================

/// Build a mapping from DNT (Distinguished Name Tag) to SID string.
/// This scans the entire datatable once and is used to resolve
/// link_table relationships (which use DNTs) to SIDs.
pub fn build_dnt_sid_map(db: &NtdsDatabase) -> Result<HashMap<i32, String>> {
    let table = db.datatable()
        .context("Failed to open datatable")?;

    let record_count = table.count_records()
        .context("Failed to count records")?;

    let dnt_col = schema::find_column_index(&table, "DNT_col");
    let sid_col = schema::find_column_index(&table, "ATTr589970");

    if dnt_col.is_none() || sid_col.is_none() {
        log::warn!("DNT or SID column not found — DNT→SID map will be empty");
        return Ok(HashMap::new());
    }

    let mut map = HashMap::new();

    for i in 0..record_count {
        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let dnt = match get_i32_value(&record, dnt_col) {
            Some(d) => d,
            None => continue,
        };

        if let Some(sid_data) = get_binary_value(&record, sid_col) {
            if let Some(sid_str) = parse_sid(&sid_data) {
                map.insert(dnt, sid_str);
            }
        }
    }

    log::info!("Built DNT→SID map with {} entries", map.len());
    Ok(map)
}

/// Build a mapping from DNT to sAMAccountName.
pub fn build_dnt_name_map(db: &NtdsDatabase) -> Result<HashMap<i32, String>> {
    let table = db.datatable()
        .context("Failed to open datatable")?;

    let record_count = table.count_records()
        .context("Failed to count records")?;

    let dnt_col = schema::find_column_index(&table, "DNT_col");
    let sam_col = schema::find_column_index(&table, "ATTm590045");
    let name_col = schema::find_column_index(&table, "ATTm589825"); // RDN name fallback

    let mut map = HashMap::new();

    for i in 0..record_count {
        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let dnt = match get_i32_value(&record, dnt_col) {
            Some(d) => d,
            None => continue,
        };

        // Prefer sAMAccountName, fall back to RDN name
        let name = get_string_value(&record, sam_col)
            .or_else(|| get_string_value(&record, name_col));

        if let Some(n) = name {
            map.insert(dnt, n);
        }
    }

    log::info!("Built DNT→Name map with {} entries", map.len());
    Ok(map)
}
