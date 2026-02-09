use anyhow::{Result, bail};
use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

use crate::objects::parse_sid;

// ACE type constants
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;

// ACE flags
const INHERITED_ACE: u8 = 0x10;

// Access mask bits
const ADS_RIGHT_GENERIC_ALL: u32         = 0x10000000;
const ADS_RIGHT_WRITE_DAC: u32           = 0x00040000;
const ADS_RIGHT_WRITE_OWNER: u32         = 0x00080000;
const ADS_RIGHT_DS_WRITE_PROP: u32       = 0x00000020;
const ADS_RIGHT_DS_CONTROL_ACCESS: u32   = 0x00000100;

// Well-known extended rights GUIDs (as bytes, little-endian GUID format)
// DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
const GUID_DS_REPL_GET_CHANGES: [u8; 16] = [
    0xaa, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11,
    0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2
];
// DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
const GUID_DS_REPL_GET_CHANGES_ALL: [u8; 16] = [
    0xad, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11,
    0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2
];
// User-Force-Change-Password: 00299570-246d-11d0-a768-00aa006e0529
const GUID_FORCE_CHANGE_PWD: [u8; 16] = [
    0x70, 0x95, 0x29, 0x00, 0x6d, 0x24, 0xd0, 0x11,
    0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29
];
// member attribute: bf9679c0-0de6-11d0-a285-00aa003049e2
const GUID_MEMBER_ATTR: [u8; 16] = [
    0xc0, 0x79, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11,
    0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2
];

/// A parsed ACE entry suitable for BloodHound output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AceEntry {
    pub principal_sid: String,
    pub principal_type: String,  // User, Group, Computer (populated later)
    pub right_name: String,
    pub ace_type: String,
    pub is_inherited: bool,
}

/// Parse a binary Security Descriptor and extract interesting ACEs.
/// Returns only ACEs that represent BloodHound-relevant edges.
pub fn parse_security_descriptor(data: &[u8]) -> Result<Vec<AceEntry>> {
    if data.len() < 20 {
        bail!("Security descriptor too short ({} bytes)", data.len());
    }

    let mut cursor = Cursor::new(data);

    let _revision = cursor.read_u8()?;
    let _sbz1 = cursor.read_u8()?;
    let control = cursor.read_u16::<LittleEndian>()?;
    let _offset_owner = cursor.read_u32::<LittleEndian>()?;
    let _offset_group = cursor.read_u32::<LittleEndian>()?;
    let _offset_sacl = cursor.read_u32::<LittleEndian>()?;
    let offset_dacl = cursor.read_u32::<LittleEndian>()?;

    // SE_DACL_PRESENT = 0x0004
    if control & 0x0004 == 0 || offset_dacl == 0 {
        return Ok(Vec::new());
    }

    if offset_dacl as usize >= data.len() {
        return Ok(Vec::new());
    }

    parse_dacl(&data[offset_dacl as usize..])
}

fn parse_dacl(data: &[u8]) -> Result<Vec<AceEntry>> {
    if data.len() < 8 {
        return Ok(Vec::new());
    }

    let mut cursor = Cursor::new(data);
    let _acl_revision = cursor.read_u8()?;
    let _sbz1 = cursor.read_u8()?;
    let _acl_size = cursor.read_u16::<LittleEndian>()?;
    let ace_count = cursor.read_u16::<LittleEndian>()?;
    let _sbz2 = cursor.read_u16::<LittleEndian>()?;

    let mut entries = Vec::new();
    let mut offset = 8usize;

    for _ in 0..ace_count {
        if offset + 4 > data.len() {
            break;
        }

        let ace_type = data[offset];
        let ace_flags = data[offset + 1];
        let ace_size = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if ace_size < 4 || offset + ace_size > data.len() {
            break;
        }

        let is_inherited = ace_flags & INHERITED_ACE != 0;

        // Only process ACCESS_ALLOWED_ACE and ACCESS_ALLOWED_OBJECT_ACE
        if ace_type == ACCESS_ALLOWED_ACE_TYPE {
            if let Some(entry) = parse_allowed_ace(&data[offset..offset + ace_size], is_inherited) {
                entries.push(entry);
            }
        } else if ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE {
            if let Some(mut aces) = parse_allowed_object_ace(&data[offset..offset + ace_size], is_inherited) {
                entries.append(&mut aces);
            }
        }

        offset += ace_size;
    }

    Ok(entries)
}

fn parse_allowed_ace(data: &[u8], is_inherited: bool) -> Option<AceEntry> {
    // ACCESS_ALLOWED_ACE: Type(1) + Flags(1) + Size(2) + Mask(4) + SID(variable)
    if data.len() < 8 {
        return None;
    }

    let mask = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let sid = parse_sid(&data[8..])?;

    let right_name = if mask & ADS_RIGHT_GENERIC_ALL != 0 {
        "GenericAll"
    } else if mask & ADS_RIGHT_WRITE_DAC != 0 {
        "WriteDacl"
    } else if mask & ADS_RIGHT_WRITE_OWNER != 0 {
        "WriteOwner"
    } else {
        return None; // Not an interesting edge
    };

    Some(AceEntry {
        principal_sid: sid,
        principal_type: String::new(),
        right_name: right_name.to_string(),
        ace_type: "Allow".to_string(),
        is_inherited,
    })
}

fn parse_allowed_object_ace(data: &[u8], is_inherited: bool) -> Option<Vec<AceEntry>> {
    // ACCESS_ALLOWED_OBJECT_ACE: Type(1) + Flags(1) + Size(2) + Mask(4) +
    //   ObjectFlags(4) + [ObjectType GUID(16)] + [InheritedObjectType GUID(16)] + SID
    if data.len() < 12 {
        return None;
    }

    let mask = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let object_flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    let mut offset = 12usize;
    let mut object_type_guid: Option<[u8; 16]> = None;

    // ACE_OBJECT_TYPE_PRESENT = 0x01
    if object_flags & 0x01 != 0 {
        if offset + 16 > data.len() {
            return None;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[offset..offset + 16]);
        object_type_guid = Some(guid);
        offset += 16;
    }

    // ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02
    if object_flags & 0x02 != 0 {
        offset += 16; // Skip inherited object type
    }

    if offset >= data.len() {
        return None;
    }

    let sid = parse_sid(&data[offset..])?;

    let mut entries = Vec::new();

    // Check for GenericAll/WriteDacl/WriteOwner even on object ACEs
    if mask & ADS_RIGHT_GENERIC_ALL != 0 {
        entries.push(AceEntry {
            principal_sid: sid.clone(),
            principal_type: String::new(),
            right_name: "GenericAll".to_string(),
            ace_type: "Allow".to_string(),
            is_inherited,
        });
    }
    if mask & ADS_RIGHT_WRITE_DAC != 0 {
        entries.push(AceEntry {
            principal_sid: sid.clone(),
            principal_type: String::new(),
            right_name: "WriteDacl".to_string(),
            ace_type: "Allow".to_string(),
            is_inherited,
        });
    }
    if mask & ADS_RIGHT_WRITE_OWNER != 0 {
        entries.push(AceEntry {
            principal_sid: sid.clone(),
            principal_type: String::new(),
            right_name: "WriteOwner".to_string(),
            ace_type: "Allow".to_string(),
            is_inherited,
        });
    }

    // Check extended rights (DS_CONTROL_ACCESS)
    if mask & ADS_RIGHT_DS_CONTROL_ACCESS != 0 {
        if let Some(guid) = object_type_guid {
            if guid == GUID_DS_REPL_GET_CHANGES {
                entries.push(AceEntry {
                    principal_sid: sid.clone(),
                    principal_type: String::new(),
                    right_name: "GetChanges".to_string(),
                    ace_type: "Allow".to_string(),
                    is_inherited,
                });
            } else if guid == GUID_DS_REPL_GET_CHANGES_ALL {
                entries.push(AceEntry {
                    principal_sid: sid.clone(),
                    principal_type: String::new(),
                    right_name: "GetChangesAll".to_string(),
                    ace_type: "Allow".to_string(),
                    is_inherited,
                });
            } else if guid == GUID_FORCE_CHANGE_PWD {
                entries.push(AceEntry {
                    principal_sid: sid.clone(),
                    principal_type: String::new(),
                    right_name: "ForceChangePassword".to_string(),
                    ace_type: "Allow".to_string(),
                    is_inherited,
                });
            }
        } else {
            // No specific GUID = AllExtendedRights
            entries.push(AceEntry {
                principal_sid: sid.clone(),
                principal_type: String::new(),
                right_name: "AllExtendedRights".to_string(),
                ace_type: "Allow".to_string(),
                is_inherited,
            });
        }
    }

    // Check WriteProperty for member attribute (AddMembers)
    if mask & ADS_RIGHT_DS_WRITE_PROP != 0 {
        if let Some(guid) = object_type_guid {
            if guid == GUID_MEMBER_ATTR {
                entries.push(AceEntry {
                    principal_sid: sid.clone(),
                    principal_type: String::new(),
                    right_name: "AddMembers".to_string(),
                    ace_type: "Allow".to_string(),
                    is_inherited,
                });
            }
        }
    }

    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}
