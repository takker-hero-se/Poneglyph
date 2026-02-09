use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};

use crate::ese::NtdsDatabase;
use crate::schema;
use crate::objects::{parse_sid, extract_rid,
                     get_string_value, get_i32_value, get_i64_value, get_binary_value,
                     filetime_to_string};

// groupType flag constants
pub const GROUP_TYPE_BUILTIN_LOCAL: i32 = 0x00000001;
pub const GROUP_TYPE_GLOBAL: i32        = 0x00000002;
pub const GROUP_TYPE_DOMAIN_LOCAL: i32  = 0x00000004;
pub const GROUP_TYPE_UNIVERSAL: i32     = 0x00000008;
pub const GROUP_TYPE_SECURITY: i32      = -2147483648_i32; // 0x80000000

// Well-known high-value group RIDs
const HIGH_VALUE_RIDS: &[u32] = &[
    512,  // Domain Admins
    516,  // Domain Controllers
    518,  // Schema Admins
    519,  // Enterprise Admins
    498,  // Enterprise Read-only Domain Controllers
    520,  // Group Policy Creator Owners
    544,  // Administrators (builtin)
];

/// Represents an Active Directory group extracted from NTDS.dit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroup {
    pub sam_account_name: String,
    pub sid: Option<String>,
    pub rid: Option<u32>,
    pub description: Option<String>,
    pub group_type: i32,
    pub group_type_flags: Vec<String>,
    pub admin_count: Option<i32>,
    pub when_created: Option<String>,
    pub when_changed: Option<String>,
    pub high_value: bool,

    #[serde(skip_serializing)]
    pub dnt: Option<i32>,

    /// Member SIDs — populated after link_table resolution
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
}

pub fn describe_group_type(gt: i32) -> Vec<String> {
    let mut flags = Vec::new();

    if gt & GROUP_TYPE_SECURITY != 0 {
        flags.push("Security".to_string());
    } else {
        flags.push("Distribution".to_string());
    }

    if gt & GROUP_TYPE_BUILTIN_LOCAL != 0 { flags.push("BuiltinLocal".to_string()); }
    if gt & GROUP_TYPE_GLOBAL != 0        { flags.push("Global".to_string()); }
    if gt & GROUP_TYPE_DOMAIN_LOCAL != 0  { flags.push("DomainLocal".to_string()); }
    if gt & GROUP_TYPE_UNIVERSAL != 0     { flags.push("Universal".to_string()); }

    flags
}

// sAMAccountType values for group objects
const SAM_GROUP_OBJECT: i32              = 0x10000000; // 268435456 - domain global group
const SAM_NON_SECURITY_GROUP_OBJECT: i32 = 0x10000001; // 268435457
const SAM_ALIAS_OBJECT: i32              = 0x20000000; // 536870912 - domain local group
const SAM_NON_SECURITY_ALIAS_OBJECT: i32 = 0x20000001; // 536870913

fn is_group_sam_account_type(sat: i32) -> bool {
    matches!(sat, SAM_GROUP_OBJECT | SAM_NON_SECURITY_GROUP_OBJECT
                | SAM_ALIAS_OBJECT | SAM_NON_SECURITY_ALIAS_OBJECT)
}

struct GroupColumnIndices {
    sam_account_name: Option<i32>,
    object_sid: Option<i32>,
    description: Option<i32>,
    group_type: Option<i32>,
    sam_account_type: Option<i32>,
    admin_count: Option<i32>,
    when_created: Option<i32>,
    when_changed: Option<i32>,
    dnt: Option<i32>,
}

impl GroupColumnIndices {
    fn resolve(table: &libesedb::Table) -> Self {
        Self {
            sam_account_name: schema::find_column_index(table, "ATTm590045"),
            object_sid: schema::find_column_index(table, "ATTr589970"),
            description: schema::find_column_index(table, "ATTm13"),
            group_type: schema::find_column_index(table, "ATTj590574"),
            sam_account_type: schema::find_column_index(table, "ATTj590126"),
            admin_count: schema::find_column_index(table, "ATTj589974"),
            when_created: schema::find_column_index(table, "ATTl131074"),
            when_changed: schema::find_column_index(table, "ATTl131075"),
            dnt: schema::find_column_index(table, "DNT_col"),
        }
    }
}

/// Extract all group objects from the datatable.
pub fn extract_groups(db: &NtdsDatabase) -> Result<Vec<AdGroup>> {
    let table = db.datatable()
        .context("Failed to open datatable")?;

    let record_count = table.count_records()
        .context("Failed to count records")?;

    log::info!("Scanning {} datatable records for groups...", record_count);

    let cols = GroupColumnIndices::resolve(&table);

    if cols.group_type.is_none() {
        log::warn!("groupType column (ATTj590574) not found — using sAMAccountType fallback");
    }

    let pb = ProgressBar::new(record_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.yellow/dark_gray} {pos}/{len} records ({per_sec})")
            .unwrap()
            .progress_chars("=> "),
    );

    let mut groups = Vec::new();

    for i in 0..record_count {
        pb.inc(1);

        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Groups: identified by groupType or sAMAccountType
        let group_type = if let Some(gt) = get_i32_value(&record, cols.group_type) {
            gt
        } else if let Some(sat) = get_i32_value(&record, cols.sam_account_type) {
            if !is_group_sam_account_type(sat) {
                continue;
            }
            // Synthesize groupType from sAMAccountType
            match sat {
                SAM_GROUP_OBJECT => GROUP_TYPE_SECURITY | GROUP_TYPE_GLOBAL,
                SAM_NON_SECURITY_GROUP_OBJECT => GROUP_TYPE_GLOBAL,
                SAM_ALIAS_OBJECT => GROUP_TYPE_SECURITY | GROUP_TYPE_DOMAIN_LOCAL,
                SAM_NON_SECURITY_ALIAS_OBJECT => GROUP_TYPE_DOMAIN_LOCAL,
                _ => continue,
            }
        } else {
            continue;
        };

        let sam = match get_string_value(&record, cols.sam_account_name) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let sid_data = get_binary_value(&record, cols.object_sid);
        let sid = sid_data.as_ref().and_then(|d| parse_sid(d));
        let rid = sid_data.as_ref().and_then(|d| extract_rid(d));

        let high_value = rid.map(|r| HIGH_VALUE_RIDS.contains(&r)).unwrap_or(false);

        groups.push(AdGroup {
            sam_account_name: sam,
            sid,
            rid,
            description: get_string_value(&record, cols.description),
            group_type,
            group_type_flags: describe_group_type(group_type),
            admin_count: get_i32_value(&record, cols.admin_count),
            when_created: get_i64_value(&record, cols.when_created).and_then(filetime_to_string),
            when_changed: get_i64_value(&record, cols.when_changed).and_then(filetime_to_string),
            high_value,
            dnt: get_i32_value(&record, cols.dnt),
            members: Vec::new(),
        });
    }

    pb.finish_with_message(format!("Found {} groups", groups.len()));
    Ok(groups)
}
