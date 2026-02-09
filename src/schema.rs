use std::collections::HashMap;
use std::sync::LazyLock;

/// Static mapping of ATT codes to LDAP attribute names.
/// Format in ESE: ATT + <syntax_code> + <attribute_id>
///   syntax codes: j=Integer(32), m=String, k/r=Binary, q/l=LargeInt(64), b=Boolean
static ATT_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    // ===================== Identity & Naming =====================
    // OID-to-attributeID: 2.5.4.x → base 0, 1.2.840.113556.1.2.x → base 131072, 1.2.840.113556.1.4.x → base 589824
    m.insert("ATTm3",           "cn");                    // Common Name (OID 2.5.4.3)
    m.insert("ATTm589825",      "name");                  // Object RDN (OID 1.2.840.113556.1.4.1)
    m.insert("ATTm590045",      "sAMAccountName");        // Logon name (OID 1.2.840.113556.1.4.221)
    m.insert("ATTm131085",      "displayName");           // Display name (OID 1.2.840.113556.1.2.13)
    m.insert("ATTm590480",      "userPrincipalName");     // UPN (OID 1.2.840.113556.1.4.656)
    m.insert("ATTm590443",      "servicePrincipalName");  // SPN (OID 1.2.840.113556.1.4.619)
    m.insert("ATTm131532",      "givenName");             // First name
    m.insert("ATTm131536",      "sn");                    // Surname
    m.insert("ATTm13",          "description");           // Description (OID 2.5.4.13)
    m.insert("ATTm131218",      "distinguishedName");     // DN
    m.insert("ATTm589918",      "dNSHostName");           // DNS host name

    // ===================== Security Identifiers =====================
    m.insert("ATTr589970",      "objectSid");             // SID (binary)
    m.insert("ATTr590433",      "sidHistory");            // SID history

    // ===================== Object Classification =====================
    m.insert("ATTc0",           "objectClass");           // Object class
    m.insert("ATTb590606",      "objectCategory");        // Object category DN
    m.insert("ATTj131442",      "instanceType");          // Instance type

    // ===================== Account Control =====================
    m.insert("ATTj589832",      "userAccountControl");    // UAC flags
    m.insert("ATTj589836",      "badPwdCount");           // Bad password count
    m.insert("ATTq589876",      "lastLogon");             // Last logon, not replicated (OID 1.2.840.113556.1.4.52)
    m.insert("ATTq589920",      "pwdLastSet");            // Password last set (OID 1.2.840.113556.1.4.96)
    m.insert("ATTq591520",      "lastLogonTimestamp");    // Last logon, replicated (OID 1.2.840.113556.1.4.1696)
    m.insert("ATTq589983",      "accountExpires");        // Account expiration
    m.insert("ATTj589993",      "logonCount");            // Logon count
    m.insert("ATTj589922",      "primaryGroupID");        // Primary group RID (OID 1.2.840.113556.1.4.98)
    m.insert("ATTj590126",      "sAMAccountType");        // SAM account type (OID 1.2.840.113556.1.4.302)
    m.insert("ATTj589974",      "adminCount");            // Admin count flag (OID 1.2.840.113556.1.4.150)

    // ===================== Password Hashes (Encrypted) =====================
    m.insert("ATTk589879",      "dBCSPwd");               // LM hash (encrypted)
    m.insert("ATTk589914",      "unicodePwd");            // NT hash (encrypted)
    m.insert("ATTk589918",      "ntPwdHistory");          // NT password history
    m.insert("ATTk589984",      "lmPwdHistory");          // LM password history
    m.insert("ATTk590689",      "pekList");               // PEK (encrypted key)
    m.insert("ATTk589949",      "supplementalCredentials"); // Supplemental credentials

    // ===================== Timestamps =====================
    m.insert("ATTl131074",      "whenCreated");           // Creation time
    m.insert("ATTl131075",      "whenChanged");           // Last modification time
    m.insert("ATTq589921",      "lockoutTime");           // Account lockout time

    // ===================== Group Attributes =====================
    m.insert("ATTj590574",      "groupType");             // Group type flags (OID 1.2.840.113556.1.4.750)
    m.insert("ATTb590607",      "member");                // Group members (link)
    m.insert("ATTb590608",      "memberOf");              // Group membership (backlink)

    // ===================== Computer Attributes =====================
    m.insert("ATTm590187",      "operatingSystem");       // OS name
    m.insert("ATTm590188",      "operatingSystemVersion"); // OS version
    m.insert("ATTm590189",      "operatingSystemServicePack"); // OS service pack

    // ===================== GPO =====================
    m.insert("ATTm590164",      "gPCFileSysPath");        // GPO file system path
    m.insert("ATTj590155",      "flags");                 // GPO flags
    m.insert("ATTj590154",      "versionNumber");         // GPO version

    // ===================== Trust =====================
    m.insert("ATTm590295",      "trustPartner");          // Trust partner domain
    m.insert("ATTj590294",      "trustDirection");        // Trust direction
    m.insert("ATTj590293",      "trustType");             // Trust type
    m.insert("ATTj590296",      "trustAttributes");       // Trust attributes

    // ===================== Delegation =====================
    m.insert("ATTm590513",      "msDS-AllowedToDelegateTo"); // Constrained delegation

    // ===================== LAPS =====================
    m.insert("ATTm591734",      "ms-Mcs-AdmPwd");        // LAPS v1 password
    m.insert("ATTq591735",      "ms-Mcs-AdmPwdExpirationTime"); // LAPS expiration

    // ===================== Replication & Internal =====================
    m.insert("ATTb590605",      "isDeleted");             // Tombstone flag
    m.insert("ATTb131108",      "isCriticalSystemObject"); // Critical system object
    m.insert("ATTq131091",      "uSNChanged");            // USN changed
    m.insert("ATTq131090",      "uSNCreated");            // USN created
    m.insert("ATTk590516",      "msDS-KeyCredentialLink"); // Shadow credentials

    // ===================== DNT/PDNT (internal) =====================
    m.insert("DNT_col",         "DNT");                   // Distinguished Name Tag
    m.insert("PDNT_col",        "PDNT");                  // Parent DNT
    m.insert("NCDNT_col",       "NCDNT");                 // Naming Context DNT

    m
});

/// Resolve an ATT column name to its LDAP attribute name.
pub fn resolve_att_name(att_code: &str) -> Option<&'static str> {
    ATT_MAP.get(att_code).copied()
}

/// Get the full ATT code mapping.
pub fn att_map() -> &'static HashMap<&'static str, &'static str> {
    &ATT_MAP
}

/// Find the column index in a table for a given ATT code.
pub fn find_column_index(table: &libesedb::Table, att_code: &str) -> Option<i32> {
    let col_count = table.count_columns().ok()?;
    for i in 0..col_count {
        if let Ok(col) = table.column(i) {
            if let Ok(name) = col.name() {
                if name == att_code {
                    return Some(i);
                }
            }
        }
    }
    None
}

/// Find column index by LDAP attribute name (searches through ATT mapping).
pub fn find_column_by_ldap_name(table: &libesedb::Table, ldap_name: &str) -> Option<i32> {
    // Find the ATT code for this LDAP name
    for (att, ldap) in ATT_MAP.iter() {
        if *ldap == ldap_name {
            if let Some(idx) = find_column_index(table, att) {
                return Some(idx);
            }
        }
    }
    None
}

// ==================== UAC Flag Constants ====================

/// userAccountControl bit flags
pub mod uac {
    pub const SCRIPT: u32                         = 0x0001;
    pub const ACCOUNTDISABLE: u32                 = 0x0002;
    pub const HOMEDIR_REQUIRED: u32               = 0x0008;
    pub const LOCKOUT: u32                        = 0x0010;
    pub const PASSWD_NOTREQD: u32                 = 0x0020;
    pub const PASSWD_CANT_CHANGE: u32             = 0x0040;
    pub const ENCRYPTED_TEXT_PWD_ALLOWED: u32     = 0x0080;
    pub const NORMAL_ACCOUNT: u32                 = 0x0200;
    pub const INTERDOMAIN_TRUST_ACCOUNT: u32      = 0x0800;
    pub const WORKSTATION_TRUST_ACCOUNT: u32      = 0x1000;
    pub const SERVER_TRUST_ACCOUNT: u32           = 0x2000;
    pub const DONT_EXPIRE_PASSWORD: u32           = 0x10000;
    pub const MNS_LOGON_ACCOUNT: u32              = 0x20000;
    pub const SMARTCARD_REQUIRED: u32             = 0x40000;
    pub const TRUSTED_FOR_DELEGATION: u32         = 0x80000;
    pub const NOT_DELEGATED: u32                  = 0x100000;
    pub const USE_DES_KEY_ONLY: u32               = 0x200000;
    pub const DONT_REQ_PREAUTH: u32               = 0x400000;
    pub const PASSWORD_EXPIRED: u32               = 0x800000;
    pub const TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x1000000;
    pub const PARTIAL_SECRETS_ACCOUNT: u32        = 0x4000000;
}
