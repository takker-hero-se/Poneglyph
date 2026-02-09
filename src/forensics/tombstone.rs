use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Serialize, Deserialize};

use crate::ese::NtdsDatabase;
use crate::schema;
use crate::objects::{parse_sid, extract_rid, filetime_to_string, describe_uac,
                     get_string_value, get_i32_value, get_i64_value, get_binary_value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedObject {
    pub object_type: DeletedObjectType,
    pub sam_account_name: Option<String>,
    pub name: Option<String>,
    pub sid: Option<String>,
    pub rid: Option<u32>,
    pub description: Option<String>,
    pub when_created: Option<String>,
    pub when_changed: Option<String>,
    pub user_account_control: Option<u32>,
    pub uac_flags: Vec<String>,
    pub dnt: Option<i32>,
    pub pdnt: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeletedObjectType {
    User,
    Computer,
    Group,
    Other,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeletedObjects {
    pub users: Vec<DeletedObject>,
    pub computers: Vec<DeletedObject>,
    pub groups: Vec<DeletedObject>,
    pub other: Vec<DeletedObject>,
}

struct TombstoneColumnIndices {
    is_deleted: Option<i32>,
    sam_account_name: Option<i32>,
    name: Option<i32>,
    object_sid: Option<i32>,
    description: Option<i32>,
    uac: Option<i32>,
    sam_account_type: Option<i32>,
    group_type: Option<i32>,
    when_created: Option<i32>,
    when_changed: Option<i32>,
    dnt: Option<i32>,
    pdnt: Option<i32>,
}

impl TombstoneColumnIndices {
    fn resolve(table: &libesedb::Table) -> Self {
        Self {
            is_deleted: schema::find_column_index(table, "ATTb590605"),
            sam_account_name: schema::find_column_index(table, "ATTm590045"),
            name: schema::find_column_index(table, "ATTm589825"),
            object_sid: schema::find_column_index(table, "ATTr589970"),
            description: schema::find_column_index(table, "ATTm13"),
            uac: schema::find_column_index(table, "ATTj589832"),
            sam_account_type: schema::find_column_index(table, "ATTj590126"),
            group_type: schema::find_column_index(table, "ATTj590574"),
            when_created: schema::find_column_index(table, "ATTl131074"),
            when_changed: schema::find_column_index(table, "ATTl131075"),
            dnt: schema::find_column_index(table, "DNT_col"),
            pdnt: schema::find_column_index(table, "PDNT_col"),
        }
    }
}

/// Scan the entire datatable for records with isDeleted=TRUE.
pub fn extract_deleted_objects(db: &NtdsDatabase) -> Result<DeletedObjects> {
    let table = db.datatable()
        .context("Failed to open datatable")?;
    let record_count = table.count_records()
        .context("Failed to count records")?;

    let cols = TombstoneColumnIndices::resolve(&table);

    if cols.is_deleted.is_none() {
        log::warn!("isDeleted column (ATTb590605) not found — cannot recover tombstones");
        return Ok(DeletedObjects {
            users: Vec::new(),
            computers: Vec::new(),
            groups: Vec::new(),
            other: Vec::new(),
        });
    }

    let pb = ProgressBar::new(record_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.red/dark_gray} {pos}/{len} tombstone scan ({per_sec})")
            .unwrap()
            .progress_chars("=> "),
    );

    let mut result = DeletedObjects {
        users: Vec::new(),
        computers: Vec::new(),
        groups: Vec::new(),
        other: Vec::new(),
    };

    for i in 0..record_count {
        pb.inc(1);

        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Check isDeleted flag — stored as integer boolean in ESE
        let is_deleted = get_i32_value(&record, cols.is_deleted)
            .map(|v| v != 0)
            .unwrap_or(false);

        if !is_deleted {
            continue;
        }

        let uac_value = get_i32_value(&record, cols.uac).map(|v| v as u32);
        let uac_flags: Vec<String> = uac_value
            .map(|u| describe_uac(u).into_iter().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        let sid_data = get_binary_value(&record, cols.object_sid);
        let sid = sid_data.as_ref().and_then(|d| parse_sid(d));
        let rid = sid_data.as_ref().and_then(|d| extract_rid(d));

        let raw_name = get_string_value(&record, cols.name);
        // Strip tombstone suffix (e.g., "John Doe\0DEL:a1b2c3...")
        let clean_name = raw_name.as_ref().map(|n| {
            n.split('\0').next().unwrap_or(n).to_string()
        });

        let obj = DeletedObject {
            object_type: classify_deleted_object(
                uac_value,
                get_i32_value(&record, cols.group_type),
                get_i32_value(&record, cols.sam_account_type),
            ),
            sam_account_name: get_string_value(&record, cols.sam_account_name),
            name: clean_name,
            sid,
            rid,
            description: get_string_value(&record, cols.description),
            when_created: get_i64_value(&record, cols.when_created).and_then(filetime_to_string),
            when_changed: get_i64_value(&record, cols.when_changed).and_then(filetime_to_string),
            user_account_control: uac_value,
            uac_flags,
            dnt: get_i32_value(&record, cols.dnt),
            pdnt: get_i32_value(&record, cols.pdnt),
        };

        match obj.object_type {
            DeletedObjectType::User => result.users.push(obj),
            DeletedObjectType::Computer => result.computers.push(obj),
            DeletedObjectType::Group => result.groups.push(obj),
            DeletedObjectType::Other => result.other.push(obj),
        }
    }

    let total = result.users.len() + result.computers.len() + result.groups.len() + result.other.len();
    pb.finish_with_message(format!(
        "Recovered {} deleted objects ({} users, {} computers, {} groups, {} other)",
        total, result.users.len(), result.computers.len(), result.groups.len(), result.other.len(),
    ));

    Ok(result)
}

/// Classify a deleted object by its UAC flags, groupType, and sAMAccountType.
fn classify_deleted_object(
    uac: Option<u32>,
    group_type: Option<i32>,
    sam_account_type: Option<i32>,
) -> DeletedObjectType {
    // Groups have groupType set
    if group_type.is_some() {
        return DeletedObjectType::Group;
    }

    // Check UAC for computer vs user
    if let Some(u) = uac {
        if u & schema::uac::WORKSTATION_TRUST_ACCOUNT != 0
            || u & schema::uac::SERVER_TRUST_ACCOUNT != 0
        {
            return DeletedObjectType::Computer;
        }
        if u & schema::uac::NORMAL_ACCOUNT != 0 {
            return DeletedObjectType::User;
        }
    }

    // Fallback: check sAMAccountType
    if let Some(sat) = sam_account_type {
        match sat {
            0x30000000 => return DeletedObjectType::User,
            0x10000000 | 0x10000001 | 0x20000000 | 0x20000001 => {
                return DeletedObjectType::Group;
            }
            _ => {}
        }
    }

    DeletedObjectType::Other
}
