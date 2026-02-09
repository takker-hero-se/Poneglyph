use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::ese::NtdsDatabase;
use crate::schema;
use crate::objects::{parse_sid, get_string_value, get_i32_value, get_i64_value, get_binary_value, filetime_to_string};

/// Represents a domain trust relationship extracted from NTDS.dit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdTrust {
    pub trust_partner: String,
    pub trust_direction: i32,
    pub trust_direction_str: String,
    pub trust_type: i32,
    pub trust_type_str: String,
    pub trust_attributes: i32,
    pub sid: Option<String>,
    pub when_created: Option<String>,
}

fn trust_direction_str(dir: i32) -> String {
    match dir {
        0 => "Disabled".to_string(),
        1 => "Inbound".to_string(),
        2 => "Outbound".to_string(),
        3 => "Bidirectional".to_string(),
        _ => format!("Unknown({})", dir),
    }
}

fn trust_type_str(tt: i32) -> String {
    match tt {
        1 => "Downlevel (NT4)".to_string(),
        2 => "Uplevel (AD)".to_string(),
        3 => "MIT (Kerberos)".to_string(),
        4 => "DCE".to_string(),
        _ => format!("Unknown({})", tt),
    }
}

/// Extract all trust relationships from the datatable.
pub fn extract_trusts(db: &NtdsDatabase) -> Result<Vec<AdTrust>> {
    let table = db.datatable()
        .context("Failed to open datatable")?;

    let record_count = table.count_records()
        .context("Failed to count records")?;

    let partner_col = schema::find_column_index(&table, "ATTm590295");    // trustPartner
    let direction_col = schema::find_column_index(&table, "ATTj590294");  // trustDirection
    let type_col = schema::find_column_index(&table, "ATTj590293");       // trustType
    let attr_col = schema::find_column_index(&table, "ATTj590296");       // trustAttributes
    let sid_col = schema::find_column_index(&table, "ATTr589970");        // objectSid
    let created_col = schema::find_column_index(&table, "ATTl131074");

    if partner_col.is_none() {
        log::warn!("trustPartner column not found — no trusts will be extracted");
        return Ok(Vec::new());
    }

    let mut trusts = Vec::new();

    for i in 0..record_count {
        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let partner = match get_string_value(&record, partner_col) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let direction = get_i32_value(&record, direction_col).unwrap_or(0);
        let trust_type = get_i32_value(&record, type_col).unwrap_or(0);
        let attributes = get_i32_value(&record, attr_col).unwrap_or(0);

        let sid = get_binary_value(&record, sid_col)
            .as_ref()
            .and_then(|d| parse_sid(d));

        trusts.push(AdTrust {
            trust_partner: partner,
            trust_direction: direction,
            trust_direction_str: trust_direction_str(direction),
            trust_type,
            trust_type_str: trust_type_str(trust_type),
            trust_attributes: attributes,
            sid,
            when_created: get_i64_value(&record, created_col).and_then(filetime_to_string),
        });
    }

    log::info!("Found {} trust relationships", trusts.len());
    Ok(trusts)
}
