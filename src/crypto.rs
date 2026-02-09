use anyhow::{Context, Result, bail};
use crate::ese::NtdsDatabase;
use crate::schema;

/// Decrypted hash result for a single user.
pub struct UserHash {
    pub sam_account_name: String,
    pub rid: u32,
    pub nt_hash: Option<[u8; 16]>,
    pub lm_hash: Option<[u8; 16]>,
}

// ==================== PEK Extraction ====================

/// Extract the encrypted PEK list from the datatable.
/// The PEK is stored as ATTk590689 (pekList) on the domain root object.
pub fn extract_pek_list(db: &NtdsDatabase) -> Result<Vec<u8>> {
    let table = db.datatable()
        .context("Failed to open datatable")?;

    let pek_col = schema::find_column_index(&table, "ATTk590689")
        .ok_or_else(|| anyhow::anyhow!("pekList column (ATTk590689) not found in datatable"))?;

    let record_count = table.count_records()
        .context("Failed to count records")?;

    for i in 0..record_count {
        let record = match table.record(i) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if let Some(data) = get_binary_value(&record, pek_col) {
            if data.len() > 24 {
                log::info!("Found pekList at record {} ({} bytes)", i, data.len());
                return Ok(data);
            }
        }
    }

    bail!("pekList (ATTk590689) not found in any datatable record")
}

/// Extract binary data from a record column.
fn get_binary_value(record: &libesedb::Record, col_idx: i32) -> Option<Vec<u8>> {
    match record.value(col_idx) {
        Ok(libesedb::Value::Binary(data)) if !data.is_empty() => Some(data),
        Ok(libesedb::Value::LargeBinary(data)) if !data.is_empty() => Some(data),
        _ => None,
    }
}

// ==================== PEK Decryption ====================

/// Decrypt the PEK (Password Encryption Key) using the BootKey.
///
/// PEK list format (per impacket secretsdump.py):
///   Bytes 0-3:   version (2=RC4, 3=AES)
///   Bytes 4-7:   flags
///   Bytes 8-23:  salt (16 bytes)
///   Bytes 24+:   encrypted PEK data
///
/// After decryption:
///   Bytes 0-35:  header (36 bytes)
///   Bytes 36-51: PEK key (16 bytes)
pub fn decrypt_pek(encrypted_pek: &[u8], bootkey: &[u8; 16]) -> Result<[u8; 16]> {
    if encrypted_pek.len() < 24 {
        bail!("PEK list too short ({} bytes, need at least 24)", encrypted_pek.len());
    }

    let version = u32::from_le_bytes(encrypted_pek[0..4].try_into()?);
    let salt = &encrypted_pek[8..24];
    let encrypted_data = &encrypted_pek[24..];

    log::info!("PEK version: {}, encrypted data: {} bytes", version, encrypted_data.len());

    let decrypted = match version {
        2 => {
            // Legacy RC4: key = MD5(bootkey + salt * 1000)
            log::info!("Decrypting PEK with RC4 (legacy)");
            let rc4_key = compute_rc4_key(bootkey, salt, 1000);
            rc4_crypt(&rc4_key, encrypted_data)
        }
        3 => {
            // Modern AES: AES-128-CBC(key=bootkey, iv=salt)
            log::info!("Decrypting PEK with AES (modern)");
            aes_128_cbc_decrypt(bootkey, salt, encrypted_data)?
        }
        _ => bail!("Unknown PEK version: {}", version),
    };

    // Extract actual PEK key from decrypted data
    // Decrypted format: 32-byte header + 4-byte PEK entry header + 16-byte key
    if decrypted.len() < 52 {
        bail!("Decrypted PEK data too short ({} bytes, need at least 52)", decrypted.len());
    }

    let mut pek = [0u8; 16];
    pek.copy_from_slice(&decrypted[36..52]);

    log::info!("PEK decrypted successfully");
    Ok(pek)
}

// ==================== Hash Decryption ====================

/// Decrypt an encrypted password hash (NT or LM) from the datatable.
///
/// Two encryption formats exist:
///
/// Legacy RC4 format:
///   Bytes 0-7:   header
///   Bytes 8-23:  salt (16 bytes)
///   Bytes 24-39: RC4-encrypted hash
///
/// Modern AES format (Win2016+):
///   Bytes 0-3:   version marker (0x001a113)
///   Bytes 4-7:   unknown
///   Bytes 8-11:  unknown
///   Bytes 12-27: salt/IV (16 bytes)
///   Bytes 28+:   AES-encrypted hash
///
/// After PEK decryption, the hash is still DES-encrypted with the user's RID.
pub fn decrypt_hash(encrypted: &[u8], pek: &[u8; 16], rid: u32) -> Option<[u8; 16]> {
    if encrypted.len() < 24 {
        return None;
    }

    let version_marker = u32::from_le_bytes(encrypted[0..4].try_into().ok()?);

    let pek_decrypted = if version_marker == 0x0013a1_01 {
        // AES (Win2016+): marker is 0x13A101 at bytes 0-3
        if encrypted.len() < 44 {
            return None;
        }
        let salt = &encrypted[12..28];
        let data = &encrypted[28..];
        let decrypted = aes_128_cbc_decrypt(pek, salt, data).ok()?;
        // AES decrypted data: first 16 bytes are the DES-encrypted hash
        if decrypted.len() < 16 {
            return None;
        }
        decrypted[..16].to_vec()
    } else {
        // RC4 (legacy)
        if encrypted.len() < 40 {
            return None;
        }
        let salt = &encrypted[8..24];
        let data = &encrypted[24..40];
        let rc4_key = compute_rc4_key(pek, salt, 1000);
        rc4_crypt(&rc4_key, data)
    };

    if pek_decrypted.len() < 16 {
        return None;
    }

    // Remove DES layer using RID-derived keys
    remove_des_layer(&pek_decrypted[..16], rid)
}

// ==================== DES Layer Removal ====================

/// Remove the DES encryption layer using RID-derived keys.
/// The 16-byte hash is split into two 8-byte halves, each decrypted
/// with a different DES key derived from the user's RID.
fn remove_des_layer(encrypted: &[u8], rid: u32) -> Option<[u8; 16]> {
    use des::Des;
    use cipher::{BlockDecrypt, KeyInit};

    if encrypted.len() < 16 {
        return None;
    }

    let (key1, key2) = rid_to_des_keys(rid);

    let cipher1 = Des::new_from_slice(&key1).ok()?;
    let cipher2 = Des::new_from_slice(&key2).ok()?;

    let mut block1 = cipher::generic_array::GenericArray::clone_from_slice(&encrypted[0..8]);
    let mut block2 = cipher::generic_array::GenericArray::clone_from_slice(&encrypted[8..16]);

    cipher1.decrypt_block(&mut block1);
    cipher2.decrypt_block(&mut block2);

    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&block1);
    hash[8..].copy_from_slice(&block2);

    Some(hash)
}

/// Derive two 8-byte DES keys from a RID.
fn rid_to_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let s = rid.to_le_bytes(); // 4 bytes

    let s1: [u8; 7] = [s[0], s[1], s[2], s[3], s[0], s[1], s[2]];
    let s2: [u8; 7] = [s[3], s[0], s[1], s[2], s[3], s[0], s[1]];

    (expand_des_key(&s1), expand_des_key(&s2))
}

/// Expand 7 bytes into an 8-byte DES key with parity bits.
fn expand_des_key(src: &[u8; 7]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = src[0] >> 1;
    key[1] = ((src[0] & 0x01) << 6) | (src[1] >> 2);
    key[2] = ((src[1] & 0x03) << 5) | (src[2] >> 3);
    key[3] = ((src[2] & 0x07) << 4) | (src[3] >> 4);
    key[4] = ((src[3] & 0x0F) << 3) | (src[4] >> 5);
    key[5] = ((src[4] & 0x1F) << 2) | (src[5] >> 6);
    key[6] = ((src[5] & 0x3F) << 1) | (src[6] >> 7);
    key[7] = src[6] & 0x7F;

    // Set odd parity bit (LSB)
    for b in key.iter_mut() {
        let v = *b;
        let parity = if v.count_ones() % 2 == 0 { 1u8 } else { 0u8 };
        *b = (v << 1) | parity;
    }

    key
}

// ==================== Crypto Primitives ====================

/// Compute RC4 key: MD5(key + salt repeated `iterations` times).
fn compute_rc4_key(key: &[u8], salt: &[u8], iterations: usize) -> [u8; 16] {
    use md5::{Md5, Digest};

    let mut hasher = Md5::new();
    hasher.update(key);
    for _ in 0..iterations {
        hasher.update(salt);
    }
    let result = hasher.finalize();

    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// RC4 stream cipher (encrypt = decrypt).
fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = [0; 256];
    for i in 0..256 {
        s[i] = i as u8;
    }

    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    let mut i: usize = 0;
    j = 0;
    let mut out = vec![0u8; data.len()];
    for (k, &byte) in data.iter().enumerate() {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        let t = (s[i] as usize + s[j] as usize) % 256;
        out[k] = byte ^ s[t];
    }

    out
}

/// AES-128-CBC decryption (no padding).
fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use aes::Aes128;
    use cbc::Decryptor;
    use cipher::{BlockDecryptMut, KeyIvInit};
    use cipher::block_padding::NoPadding;

    let mut buf = ciphertext.to_vec();
    let decryptor = Decryptor::<Aes128>::new_from_slices(key, iv)
        .map_err(|e| anyhow::anyhow!("AES init error: {}", e))?;

    let plaintext = decryptor.decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| anyhow::anyhow!("AES decrypt error: {}", e))?;

    Ok(plaintext.to_vec())
}
