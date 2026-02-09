use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};

use crate::ese::NtdsDatabase;
use crate::schema;
use crate::objects::{parse_sid, extract_rid, filetime_to_string, get_string_value, get_i32_value, get_i64_value, get_binary_value};

/// Raw encrypted hash data for a user, ready for PEK + DES decryption.
pub struct RawUserHash {
    pub sam_account_name: String,
    pub rid: u32,
    pub encrypted_nt_hash: Option<Vec<u8>>,
    pub encrypted_lm_hash: Option<Vec<u8>>,
}

/// Represents an Active Directory user account extracted from NTDS.dit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdUser {
    pub sam_account_name: String,
    pub display_name: Option<String>,
    pub user_principal_name: Option<String>,
    pub sid: Option<String>,
    pub rid: Option<u32>,
    pub description: Option<String>,
    pub enabled: bool,
    pub user_account_control: u32,
    pub uac_flags: Vec<String>,
    pub admin_count: Option<i32>,
    pub primary_group_id: Option<i32>,
    pub when_created: Option<String>,
    pub when_changed: Option<String>,
    pub pwd_last_set: Option<String>,
    pub last_logon: Option<String>,
    pub last_logon_timestamp: Option<String>,
    pub logon_count: Option<i32>,
    pub bad_pwd_count: Option<i32>,
    pub spns: Vec<String>,

    /// Whether sIDHistory is present on this account
    pub has_sid_history: bool,
    /// Whether msDS-KeyCredentialLink is present
    pub has_key_credential_link: bool,

    /// DNT (internal database key) - used for relationship resolution
    #[serde(skip_serializing)]
    pub dnt: Option<i32>,

    /// Whether this account has encrypted NT hash data
    pub has_nt_hash: bool,
    /// Whether this account has encrypted LM hash data
    pub has_lm_hash: bool,
}

/// Column indices cache for efficient record access.
struct ColumnIndices {
    sam_account_name: Option<i32>,
    display_name: Option<i32>,
    upn: Option<i32>,
    object_sid: Option<i32>,
    description: Option<i32>,
    uac: Option<i32>,
    admin_count: Option<i32>,
    primary_group_id: Option<i32>,
    when_created: Option<i32>,
    when_changed: Option<i32>,
    pwd_last_set: Option<i32>,
    last_logon: Option<i32>,
    last_logon_timestamp: Option<i32>,
    logon_count: Option<i32>,
    bad_pwd_count: Option<i32>,
    spn: Option<i32>,
    object_category: Option<i32>,
    unicode_pwd: Option<i32>,
    dbcs_pwd: Option<i32>,
    sid_history: Option<i32>,
    key_credential_link: Option<i32>,
    dnt: Option<i32>,
}

impl ColumnIndices {
    fn resolve(table: &libesedb::Table) -> Self {
        Self {
            sam_account_name: schema::find_column_index(table, "ATTm590045"),  // sAMAccountName (OID .221)
            display_name: schema::find_column_index(table, "ATTm131085"),      // displayName
            upn: schema::find_column_index(table, "ATTm590480"),               // userPrincipalName (OID .656)
            object_sid: schema::find_column_index(table, "ATTr589970"),
            description: schema::find_column_index(table, "ATTm13"),           // description (OID 2.5.4.13)
            uac: schema::find_column_index(table, "ATTj589832"),
            admin_count: schema::find_column_index(table, "ATTj589974"),       // adminCount (OID .150)
            primary_group_id: schema::find_column_index(table, "ATTj589922"),  // primaryGroupID (OID .98)
            when_created: schema::find_column_index(table, "ATTl131074"),
            when_changed: schema::find_column_index(table, "ATTl131075"),
            pwd_last_set: schema::find_column_index(table, "ATTq589920"),      // pwdLastSet (OID .96)
            last_logon: schema::find_column_index(table, "ATTq589876"),        // lastLogon (OID .52)
            last_logon_timestamp: schema::find_column_index(table, "ATTq591520"),
            logon_count: schema::find_column_index(table, "ATTj589993"),
            bad_pwd_count: schema::find_column_index(table, "ATTj589836"),
            spn: schema::find_column_index(table, "ATTm590443"),  // servicePrincipalName (OID .619)
            object_category: schema::find_column_index(table, "ATTb590606"),
            unicode_pwd: schema::find_column_index(table, "ATTk589914"),
            dbcs_pwd: schema::find_column_index(table, "ATTk589879"),
            sid_history: schema::find_column_index(table, "ATTr590433"),
            key_credential_link: schema::find_column_index(table, "ATTk590516"),
            dnt: schema::find_column_index(table, "DNT_col"),
        }
    }
}

/// Extract all user accounts from the datatable.
pub fn extract_users(db: &NtdsDatabase, include_disabled: bool) -> Result<Vec<AdUser>> {
    let table = db.datatable()
        .context("Failed to open datatable")?;

    let record_count = table.count_records()
        .context("Failed to count records")?;

    log::info!("Scanning {} datatable records for user accounts...", record_count);

    let cols = ColumnIndices::resolve(&table);

    if cols.sam_account_name.is_none() {
        anyhow::bail!("Cannot find sAMAccountName column (ATTm589825) in datatable. Is this a valid NTDS.dit?");
    }

    let pb = ProgressBar::new(record_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.green/dark_gray} {pos}/{len} records ({per_sec})")
            .unwrap()
            .progress_chars("=> "),
    );

    let mut users = Vec::new();

    for i in 0..record_count {
        pb.inc(1);

        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Check if this is a user object by examining objectCategory
        // Users have objectCategory pointing to "Person" class
        // We also check for sAMAccountName presence as a simpler heuristic
        let sam = match get_string_value(&record, cols.sam_account_name) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        // Check UAC to determine if this is a user account (not computer/trust)
        let uac_value = get_i32_value(&record, cols.uac).unwrap_or(0) as u32;

        // Skip computer accounts (WORKSTATION_TRUST_ACCOUNT or SERVER_TRUST_ACCOUNT)
        if uac_value & schema::uac::WORKSTATION_TRUST_ACCOUNT != 0
            || uac_value & schema::uac::SERVER_TRUST_ACCOUNT != 0
            || uac_value & schema::uac::INTERDOMAIN_TRUST_ACCOUNT != 0
        {
            continue;
        }

        // Must be a NORMAL_ACCOUNT (or at least not a machine account)
        // Some service accounts might not have NORMAL_ACCOUNT set
        // so we rely on the absence of machine flags above

        let enabled = uac_value & schema::uac::ACCOUNTDISABLE == 0;
        if !include_disabled && !enabled {
            continue;
        }

        // Parse SID
        let sid_data = get_binary_value(&record, cols.object_sid);
        let sid = sid_data.as_ref().and_then(|d| parse_sid(d));
        let rid = sid_data.as_ref().and_then(|d| extract_rid(d));

        // Parse timestamps (FILETIME format: 64-bit integer)
        let pwd_last_set = get_i64_value(&record, cols.pwd_last_set)
            .and_then(filetime_to_string);
        let last_logon = get_i64_value(&record, cols.last_logon)
            .and_then(filetime_to_string);
        let last_logon_ts = get_i64_value(&record, cols.last_logon_timestamp)
            .and_then(filetime_to_string);
        let when_created = get_i64_value(&record, cols.when_created)
            .and_then(filetime_to_string);
        let when_changed = get_i64_value(&record, cols.when_changed)
            .and_then(filetime_to_string);

        // Check for password hashes
        let has_nt = get_binary_value(&record, cols.unicode_pwd)
            .map(|d| !d.is_empty())
            .unwrap_or(false);
        let has_lm = get_binary_value(&record, cols.dbcs_pwd)
            .map(|d| !d.is_empty())
            .unwrap_or(false);

        let uac_flags: Vec<String> = super::describe_uac(uac_value)
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        users.push(AdUser {
            sam_account_name: sam,
            display_name: get_string_value(&record, cols.display_name),
            user_principal_name: get_string_value(&record, cols.upn),
            sid,
            rid,
            description: get_string_value(&record, cols.description),
            enabled,
            user_account_control: uac_value,
            uac_flags,
            admin_count: get_i32_value(&record, cols.admin_count),
            primary_group_id: get_i32_value(&record, cols.primary_group_id),
            when_created,
            when_changed,
            pwd_last_set,
            last_logon,
            last_logon_timestamp: last_logon_ts,
            logon_count: get_i32_value(&record, cols.logon_count),
            bad_pwd_count: get_i32_value(&record, cols.bad_pwd_count),
            spns: super::get_multi_string_value(&record, cols.spn),
            has_sid_history: get_binary_value(&record, cols.sid_history).is_some(),
            has_key_credential_link: get_binary_value(&record, cols.key_credential_link).is_some(),
            dnt: get_i32_value(&record, cols.dnt),
            has_nt_hash: has_nt,
            has_lm_hash: has_lm,
        });
    }

    pb.finish_with_message(format!("Found {} user accounts", users.len()));

    Ok(users)
}

// ==================== Hash Extraction ====================

/// Extract raw encrypted hash data for all user accounts.
/// This extracts sAMAccountName, RID, and encrypted NT/LM hashes
/// for subsequent PEK + DES decryption.
pub fn extract_user_hashes(db: &NtdsDatabase) -> Result<Vec<RawUserHash>> {
    let table = db.datatable()
        .context("Failed to open datatable")?;

    let record_count = table.count_records()
        .context("Failed to count records")?;

    log::info!("Scanning {} records for user hashes...", record_count);

    let sam_col = schema::find_column_index(&table, "ATTm590045");  // sAMAccountName
    let sid_col = schema::find_column_index(&table, "ATTr589970");
    let uac_col = schema::find_column_index(&table, "ATTj589832");
    let nt_col = schema::find_column_index(&table, "ATTk589914");
    let lm_col = schema::find_column_index(&table, "ATTk589879");

    if sam_col.is_none() {
        anyhow::bail!("sAMAccountName column (ATTm590045) not found in datatable");
    }

    let pb = ProgressBar::new(record_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/dark_gray} {pos}/{len} ({per_sec})")
            .unwrap()
            .progress_chars("=> "),
    );

    let mut hashes = Vec::new();

    for i in 0..record_count {
        pb.inc(1);

        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Must have sAMAccountName
        let sam = match get_string_value(&record, sam_col) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        // Must have a SID to extract RID
        let sid_data = get_binary_value(&record, sid_col);

        // Debug: dump first few SID binaries
        if hashes.len() < 3 {
            if let Some(ref data) = sid_data {
                if let Some(sid_str) = crate::objects::parse_sid(data) {
                    log::debug!("SID for '{}': {} ({} bytes)", sam, sid_str, data.len());
                }
            }
        }

        let rid = match sid_data.as_ref().and_then(|d| extract_rid(d)) {
            Some(r) => r,
            None => continue,
        };

        // Skip computer/trust accounts via UAC
        let uac_value = get_i32_value(&record, uac_col).unwrap_or(0) as u32;
        if uac_value & schema::uac::WORKSTATION_TRUST_ACCOUNT != 0
            || uac_value & schema::uac::SERVER_TRUST_ACCOUNT != 0
            || uac_value & schema::uac::INTERDOMAIN_TRUST_ACCOUNT != 0
        {
            continue;
        }

        let encrypted_nt = get_binary_value(&record, nt_col);
        let encrypted_lm = get_binary_value(&record, lm_col);

        // Only include if there's at least one hash
        if encrypted_nt.is_some() || encrypted_lm.is_some() {
            hashes.push(RawUserHash {
                sam_account_name: sam,
                rid,
                encrypted_nt_hash: encrypted_nt,
                encrypted_lm_hash: encrypted_lm,
            });
        }
    }

    pb.finish_with_message(format!("Found {} accounts with hashes", hashes.len()));
    Ok(hashes)
}
