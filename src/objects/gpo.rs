use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::ese::NtdsDatabase;
use crate::schema;
use crate::objects::{get_string_value, get_i32_value, get_i64_value, filetime_to_string};

/// Represents a Group Policy Object extracted from NTDS.dit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGpo {
    pub name: String,
    pub display_name: Option<String>,
    pub gpc_file_sys_path: Option<String>,
    pub flags: Option<i32>,
    pub version_number: Option<i32>,
    pub when_created: Option<String>,
    pub when_changed: Option<String>,

    #[serde(skip_serializing)]
    pub dnt: Option<i32>,
}

/// Extract all Group Policy Objects from the datatable.
pub fn extract_gpos(db: &NtdsDatabase) -> Result<Vec<AdGpo>> {
    let table = db.datatable()
        .context("Failed to open datatable")?;

    let record_count = table.count_records()
        .context("Failed to count records")?;

    let name_col = schema::find_column_index(&table, "ATTm589825");      // name (RDN)
    let display_col = schema::find_column_index(&table, "ATTm131085");   // displayName
    let gpc_col = schema::find_column_index(&table, "ATTm590164");       // gPCFileSysPath
    let flags_col = schema::find_column_index(&table, "ATTj590155");     // flags
    let version_col = schema::find_column_index(&table, "ATTj590154");   // versionNumber
    let created_col = schema::find_column_index(&table, "ATTl131074");
    let changed_col = schema::find_column_index(&table, "ATTl131075");
    let dnt_col = schema::find_column_index(&table, "DNT_col");

    if gpc_col.is_none() {
        log::warn!("gPCFileSysPath column not found — no GPOs will be extracted");
        return Ok(Vec::new());
    }

    let mut gpos = Vec::new();

    for i in 0..record_count {
        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // GPOs must have gPCFileSysPath
        let gpc_path = match get_string_value(&record, gpc_col) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let name = get_string_value(&record, name_col).unwrap_or_default();

        gpos.push(AdGpo {
            name,
            display_name: get_string_value(&record, display_col),
            gpc_file_sys_path: Some(gpc_path),
            flags: get_i32_value(&record, flags_col),
            version_number: get_i32_value(&record, version_col),
            when_created: get_i64_value(&record, created_col).and_then(filetime_to_string),
            when_changed: get_i64_value(&record, changed_col).and_then(filetime_to_string),
            dnt: get_i32_value(&record, dnt_col),
        });
    }

    log::info!("Found {} GPOs", gpos.len());
    Ok(gpos)
}
