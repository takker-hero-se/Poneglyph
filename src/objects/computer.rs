use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};

use crate::ese::NtdsDatabase;
use crate::schema;
use crate::objects::{parse_sid, extract_rid, filetime_to_string, describe_uac,
                     get_string_value, get_i32_value, get_i64_value, get_binary_value};

/// Represents an Active Directory computer account extracted from NTDS.dit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdComputer {
    pub sam_account_name: String,
    pub dns_hostname: Option<String>,
    pub sid: Option<String>,
    pub rid: Option<u32>,
    pub description: Option<String>,
    pub enabled: bool,
    pub user_account_control: u32,
    pub uac_flags: Vec<String>,
    pub operating_system: Option<String>,
    pub os_version: Option<String>,
    pub os_service_pack: Option<String>,
    pub when_created: Option<String>,
    pub when_changed: Option<String>,
    pub last_logon: Option<String>,
    pub last_logon_timestamp: Option<String>,
    pub primary_group_id: Option<i32>,
    pub is_dc: bool,

    #[serde(skip_serializing)]
    pub dnt: Option<i32>,
}

struct ComputerColumnIndices {
    sam_account_name: Option<i32>,
    dns_hostname: Option<i32>,
    object_sid: Option<i32>,
    description: Option<i32>,
    uac: Option<i32>,
    operating_system: Option<i32>,
    os_version: Option<i32>,
    os_service_pack: Option<i32>,
    when_created: Option<i32>,
    when_changed: Option<i32>,
    last_logon: Option<i32>,
    last_logon_timestamp: Option<i32>,
    primary_group_id: Option<i32>,
    dnt: Option<i32>,
}

impl ComputerColumnIndices {
    fn resolve(table: &libesedb::Table) -> Self {
        Self {
            sam_account_name: schema::find_column_index(table, "ATTm590045"),
            dns_hostname: schema::find_column_index(table, "ATTm589918"),
            object_sid: schema::find_column_index(table, "ATTr589970"),
            description: schema::find_column_index(table, "ATTm13"),
            uac: schema::find_column_index(table, "ATTj589832"),
            operating_system: schema::find_column_index(table, "ATTm590187"),
            os_version: schema::find_column_index(table, "ATTm590188"),
            os_service_pack: schema::find_column_index(table, "ATTm590189"),
            when_created: schema::find_column_index(table, "ATTl131074"),
            when_changed: schema::find_column_index(table, "ATTl131075"),
            last_logon: schema::find_column_index(table, "ATTq589876"),
            last_logon_timestamp: schema::find_column_index(table, "ATTq591520"),
            primary_group_id: schema::find_column_index(table, "ATTj589922"),
            dnt: schema::find_column_index(table, "DNT_col"),
        }
    }
}

/// Extract all computer accounts from the datatable.
pub fn extract_computers(db: &NtdsDatabase) -> Result<Vec<AdComputer>> {
    let table = db.datatable()
        .context("Failed to open datatable")?;

    let record_count = table.count_records()
        .context("Failed to count records")?;

    log::info!("Scanning {} datatable records for computer accounts...", record_count);

    let cols = ComputerColumnIndices::resolve(&table);

    let pb = ProgressBar::new(record_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.blue/dark_gray} {pos}/{len} records ({per_sec})")
            .unwrap()
            .progress_chars("=> "),
    );

    let mut computers = Vec::new();

    for i in 0..record_count {
        pb.inc(1);

        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let sam = match get_string_value(&record, cols.sam_account_name) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let uac_value = get_i32_value(&record, cols.uac).unwrap_or(0) as u32;

        // Computer accounts have WORKSTATION_TRUST_ACCOUNT or SERVER_TRUST_ACCOUNT
        let is_workstation = uac_value & schema::uac::WORKSTATION_TRUST_ACCOUNT != 0;
        let is_dc = uac_value & schema::uac::SERVER_TRUST_ACCOUNT != 0;

        if !is_workstation && !is_dc {
            continue;
        }

        let enabled = uac_value & schema::uac::ACCOUNTDISABLE == 0;

        let sid_data = get_binary_value(&record, cols.object_sid);
        let sid = sid_data.as_ref().and_then(|d| parse_sid(d));
        let rid = sid_data.as_ref().and_then(|d| extract_rid(d));

        let uac_flags: Vec<String> = describe_uac(uac_value)
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        computers.push(AdComputer {
            sam_account_name: sam,
            dns_hostname: get_string_value(&record, cols.dns_hostname),
            sid,
            rid,
            description: get_string_value(&record, cols.description),
            enabled,
            user_account_control: uac_value,
            uac_flags,
            operating_system: get_string_value(&record, cols.operating_system),
            os_version: get_string_value(&record, cols.os_version),
            os_service_pack: get_string_value(&record, cols.os_service_pack),
            when_created: get_i64_value(&record, cols.when_created).and_then(filetime_to_string),
            when_changed: get_i64_value(&record, cols.when_changed).and_then(filetime_to_string),
            last_logon: get_i64_value(&record, cols.last_logon).and_then(filetime_to_string),
            last_logon_timestamp: get_i64_value(&record, cols.last_logon_timestamp).and_then(filetime_to_string),
            primary_group_id: get_i32_value(&record, cols.primary_group_id),
            is_dc,
            dnt: get_i32_value(&record, cols.dnt),
        });
    }

    pb.finish_with_message(format!("Found {} computer accounts", computers.len()));
    Ok(computers)
}
