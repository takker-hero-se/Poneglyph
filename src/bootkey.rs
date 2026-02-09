use anyhow::{Context, Result, bail};
use std::path::Path;

/// Permutation table applied to the raw concatenated bytes to derive BootKey.
const BOOTKEY_PERMUTATION: [usize; 16] = [
    0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
    0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7,
];

/// LSA subkey names whose class names form the scrambled BootKey.
const LSA_KEY_NAMES: [&str; 4] = ["JD", "Skew1", "GBG", "Data"];

/// Extract the BootKey (System Key) from a SYSTEM registry hive file.
///
/// Algorithm:
/// 1. Open SYSTEM hive, find CurrentControlSet number from Select\Default
/// 2. Navigate to ControlSetXXX\Control\Lsa
/// 3. Read class names of JD, Skew1, GBG, Data subkeys
/// 4. Concatenate hex strings, decode to bytes, apply permutation
pub fn extract_bootkey(system_hive_path: &Path) -> Result<[u8; 16]> {
    let data = std::fs::read(system_hive_path)
        .context(format!("Failed to read SYSTEM hive: {}", system_hive_path.display()))?;

    let hive = nt_hive::Hive::new(data.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to parse SYSTEM hive: {:?}", e))?;

    let root_key = hive.root_key_node()
        .map_err(|e| anyhow::anyhow!("Failed to get root key: {:?}", e))?;

    // Find current control set number from Select\Default
    let default_cs = read_select_default(&root_key)?;
    let cs_name = format!("ControlSet{:03}", default_cs);
    log::info!("Using {} (Select\\Default = {})", cs_name, default_cs);

    // Navigate to ControlSetXXX\Control\Lsa
    let cs_key = find_subkey(&root_key, &cs_name)?;
    let control_key = find_subkey(&cs_key, "Control")?;
    let lsa_key = find_subkey(&control_key, "Lsa")?;

    // Collect class names from JD, Skew1, GBG, Data
    let mut hex_string = String::new();
    for name in &LSA_KEY_NAMES {
        let subkey = find_subkey(&lsa_key, name)
            .context(format!("LSA subkey '{}' not found", name))?;

        let class_name = subkey.class_name()
            .ok_or_else(|| anyhow::anyhow!("No class name on LSA subkey '{}'", name))?
            .map_err(|e| anyhow::anyhow!("Failed to read class name from '{}': {:?}", name, e))?;

        hex_string.push_str(&class_name.to_string_lossy());
    }

    log::debug!("LSA class names concatenated: {}", hex_string);

    // Decode hex -> raw bytes
    let raw_bytes = hex::decode(&hex_string)
        .context(format!("Invalid hex in LSA class names: '{}'", hex_string))?;

    if raw_bytes.len() != 16 {
        bail!("Expected 16 bytes from LSA class names, got {}", raw_bytes.len());
    }

    // Apply permutation
    let mut bootkey = [0u8; 16];
    for i in 0..16 {
        bootkey[i] = raw_bytes[BOOTKEY_PERMUTATION[i]];
    }

    log::info!("BootKey extracted: {}", hex::encode(bootkey));
    Ok(bootkey)
}

/// Read Select\Default DWORD value to determine the active ControlSet.
fn read_select_default(root: &nt_hive::KeyNode<'_, &[u8]>) -> Result<u32> {
    let select = find_subkey(root, "Select")?;
    let values = select.values()
        .ok_or_else(|| anyhow::anyhow!("Select key has no values"))?
        .map_err(|e| anyhow::anyhow!("Failed to read values: {:?}", e))?;

    for value_result in values {
        let value = value_result
            .map_err(|e| anyhow::anyhow!("Failed to read value: {:?}", e))?;
        let name = value.name()
            .map_err(|e| anyhow::anyhow!("Failed to read value name: {:?}", e))?;

        if name.to_string_lossy().eq_ignore_ascii_case("Default") {
            let dword = value.dword_data()
                .map_err(|e| anyhow::anyhow!("Failed to read Default DWORD: {:?}", e))?;
            return Ok(dword);
        }
    }
    bail!("Select\\Default value not found")
}

/// Find a subkey by name (case-insensitive).
fn find_subkey<'a>(
    parent: &nt_hive::KeyNode<'a, &'a [u8]>,
    name: &str,
) -> Result<nt_hive::KeyNode<'a, &'a [u8]>> {
    let subkeys = parent.subkeys()
        .ok_or_else(|| anyhow::anyhow!("Key has no subkeys"))?
        .map_err(|e| anyhow::anyhow!("Failed to read subkeys: {:?}", e))?;

    for subkey_result in subkeys {
        let subkey = subkey_result
            .map_err(|e| anyhow::anyhow!("Failed to read subkey: {:?}", e))?;
        let subkey_name = subkey.name()
            .map_err(|e| anyhow::anyhow!("Failed to read subkey name: {:?}", e))?;

        if subkey_name.to_string_lossy().eq_ignore_ascii_case(name) {
            return Ok(subkey);
        }
    }
    bail!("Subkey '{}' not found", name)
}
