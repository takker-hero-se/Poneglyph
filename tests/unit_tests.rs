//! Unit tests for Poneglyph pure functions.
//!
//! These tests verify cryptographic primitives, SID parsing, timestamp
//! conversion, and other logic that can be tested without an ESE database.

// ==================== Crypto Tests ====================

mod crypto_tests {
    /// Test DES key expansion from 7-byte seed to 8-byte key with parity.
    /// Reference: MS-SAMR Section 2.2.11.1.1
    #[test]
    fn test_expand_des_key() {
        // Known test vector: RID 500 (0x01F4) → first 7-byte seed
        // RID 500 in LE bytes: [0xF4, 0x01, 0x00, 0x00]
        // s1 = [0xF4, 0x01, 0x00, 0x00, 0xF4, 0x01, 0x00]
        let s1: [u8; 7] = [0xF4, 0x01, 0x00, 0x00, 0xF4, 0x01, 0x00];
        let key = poneglyph_lib::crypto::expand_des_key(&s1);

        // Verify: each byte should have odd parity (odd number of 1-bits)
        for (i, &b) in key.iter().enumerate() {
            assert!(
                b.count_ones() % 2 == 1,
                "DES key byte {} ({:#04x}) does not have odd parity",
                i, b
            );
        }

        // Key must be exactly 8 bytes
        assert_eq!(key.len(), 8);
    }

    /// Test RID to DES key pair derivation.
    #[test]
    fn test_rid_to_des_keys() {
        let (key1, key2) = poneglyph_lib::crypto::rid_to_des_keys(500);

        // Both keys must be 8 bytes
        assert_eq!(key1.len(), 8);
        assert_eq!(key2.len(), 8);

        // Keys must differ
        assert_ne!(key1, key2, "DES key1 and key2 for same RID should differ");

        // All bytes should have odd parity
        for &b in key1.iter().chain(key2.iter()) {
            assert!(b.count_ones() % 2 == 1, "DES key byte {:#04x} lacks odd parity", b);
        }
    }

    /// Test that different RIDs produce different DES keys.
    #[test]
    fn test_rid_to_des_keys_varies_by_rid() {
        let (k1a, k1b) = poneglyph_lib::crypto::rid_to_des_keys(500);
        let (k2a, k2b) = poneglyph_lib::crypto::rid_to_des_keys(1001);

        assert_ne!(k1a, k2a, "Different RIDs should produce different key1");
        assert_ne!(k1b, k2b, "Different RIDs should produce different key2");
    }

    /// Test RC4 round-trip (encrypt then decrypt should return original).
    #[test]
    fn test_rc4_roundtrip() {
        let key = b"test_key_12345";
        let plaintext = b"Hello, World! This is a test of RC4.";

        let ciphertext = poneglyph_lib::crypto::rc4_crypt(key, plaintext);
        let decrypted = poneglyph_lib::crypto::rc4_crypt(key, &ciphertext);

        assert_eq!(&decrypted, plaintext, "RC4 round-trip failed");
    }

    /// Test RC4 produces different output from input.
    #[test]
    fn test_rc4_encrypts() {
        let key = b"secret";
        let plaintext = b"data to encrypt";

        let ciphertext = poneglyph_lib::crypto::rc4_crypt(key, plaintext);
        assert_ne!(&ciphertext[..], &plaintext[..], "RC4 output should differ from input");
    }

    /// Test compute_rc4_key produces a 16-byte MD5 hash.
    #[test]
    fn test_compute_rc4_key() {
        let key = [0u8; 16];
        let salt = [1u8; 16];
        let result = poneglyph_lib::crypto::compute_rc4_key(&key, &salt, 1000);

        assert_eq!(result.len(), 16, "RC4 derived key should be 16 bytes");
        // Not all zeros (the hash should mix the inputs)
        assert_ne!(result, [0u8; 16], "Derived key should not be all zeros");
    }

    /// Test AES-128-CBC round-trip: encrypt with known key/IV, then decrypt.
    #[test]
    fn test_aes_128_cbc_roundtrip() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        // 16-byte plaintext (exactly one block, no padding needed)
        let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                         0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];

        // First encrypt: use our decrypt function to verify by round-tripping
        // We need a known ciphertext. NIST AES-128-CBC test vector:
        // Key:        2b7e151628aed2a6abf7158809cf4f3c
        // IV:         000102030405060708090a0b0c0d0e0f
        // Plaintext:  6bc1bee22e409f96e93d7e117393172a
        // Ciphertext: 7649abac8119b246cee98e9b12e9197d
        let expected_ciphertext: [u8; 16] = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
            0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        ];

        let decrypted = poneglyph_lib::crypto::aes_128_cbc_decrypt(&key, &iv, &expected_ciphertext).unwrap();
        assert_eq!(&decrypted[..16], &plaintext, "AES-128-CBC decrypt failed for NIST test vector");
    }

    /// Test decrypt_hash returns None for too-short input.
    #[test]
    fn test_decrypt_hash_short_input() {
        let pek = [0u8; 16];
        let result = poneglyph_lib::crypto::decrypt_hash(&[0u8; 10], &pek, 500);
        assert!(result.is_none(), "decrypt_hash should return None for short input");
    }

    /// Test decrypt_pek rejects too-short input.
    #[test]
    fn test_decrypt_pek_short_input() {
        let bootkey = [0u8; 16];
        let result = poneglyph_lib::crypto::decrypt_pek(&[0u8; 10], &bootkey);
        assert!(result.is_err(), "decrypt_pek should error on short input");
    }

    /// Test compute_rc4_key is deterministic.
    #[test]
    fn test_compute_rc4_key_deterministic() {
        let key = [0xAB; 16];
        let salt = [0xCD; 16];
        let r1 = poneglyph_lib::crypto::compute_rc4_key(&key, &salt, 500);
        let r2 = poneglyph_lib::crypto::compute_rc4_key(&key, &salt, 500);
        assert_eq!(r1, r2, "Same inputs should produce same output");
    }

    /// Test RC4 with empty data.
    #[test]
    fn test_rc4_empty_data() {
        let key = b"key";
        let result = poneglyph_lib::crypto::rc4_crypt(key, &[]);
        assert!(result.is_empty(), "RC4 of empty data should be empty");
    }

    /// Test RID 0 produces valid DES keys.
    #[test]
    fn test_rid_to_des_keys_zero() {
        let (key1, key2) = poneglyph_lib::crypto::rid_to_des_keys(0);
        assert_eq!(key1.len(), 8);
        assert_eq!(key2.len(), 8);
        for &b in key1.iter().chain(key2.iter()) {
            assert!(b.count_ones() % 2 == 1, "DES parity check failed for RID 0");
        }
    }
}

// ==================== SID Parsing Tests ====================

mod sid_tests {
    use poneglyph_lib::objects::parse_sid;
    use poneglyph_lib::objects::extract_rid;
    use poneglyph_lib::objects::domain_sid;

    /// Build a binary SID for testing.
    /// sub_authorities: all stored in their native format.
    /// Per NTDS.dit format: all sub-authorities except the last use little-endian,
    /// the last (RID) uses big-endian.
    fn build_test_sid(revision: u8, authority: u64, sub_authorities: &[u32]) -> Vec<u8> {
        let count = sub_authorities.len() as u8;
        let mut data = vec![revision, count];

        // Authority: 6 bytes big-endian
        for i in (0..6).rev() {
            data.push(((authority >> (i * 8)) & 0xFF) as u8);
        }

        // Sub-authorities: all LE except last (RID) in BE
        for (i, &sa) in sub_authorities.iter().enumerate() {
            if i == sub_authorities.len() - 1 {
                data.extend_from_slice(&sa.to_be_bytes()); // RID: big-endian
            } else {
                data.extend_from_slice(&sa.to_le_bytes()); // Others: little-endian
            }
        }

        data
    }

    /// Test parsing a well-known domain SID: S-1-5-21-x-y-z-500 (Administrator).
    #[test]
    fn test_parse_sid_administrator() {
        let sid_data = build_test_sid(1, 5, &[21, 1397410875, 1899557603, 474706272, 500]);
        let result = parse_sid(&sid_data).unwrap();
        assert_eq!(result, "S-1-5-21-1397410875-1899557603-474706272-500");
    }

    /// Test parsing the SYSTEM SID: S-1-5-18.
    #[test]
    fn test_parse_sid_system() {
        let sid_data = build_test_sid(1, 5, &[18]);
        let result = parse_sid(&sid_data).unwrap();
        assert_eq!(result, "S-1-5-18");
    }

    /// Test parsing a builtin SID: S-1-5-32-544 (Administrators).
    #[test]
    fn test_parse_sid_builtin_admins() {
        let sid_data = build_test_sid(1, 5, &[32, 544]);
        let result = parse_sid(&sid_data).unwrap();
        assert_eq!(result, "S-1-5-32-544");
    }

    /// Test parse_sid returns None for empty input.
    #[test]
    fn test_parse_sid_empty() {
        assert!(parse_sid(&[]).is_none());
    }

    /// Test parse_sid returns None for too-short input.
    #[test]
    fn test_parse_sid_too_short() {
        assert!(parse_sid(&[1, 5, 0, 0, 0, 0]).is_none());
    }

    /// Test extract_rid returns the correct RID.
    #[test]
    fn test_extract_rid() {
        let sid_data = build_test_sid(1, 5, &[21, 1000, 2000, 3000, 500]);
        let rid = extract_rid(&sid_data).unwrap();
        assert_eq!(rid, 500);
    }

    /// Test extract_rid with RID 1001.
    #[test]
    fn test_extract_rid_1001() {
        let sid_data = build_test_sid(1, 5, &[21, 1000, 2000, 3000, 1001]);
        let rid = extract_rid(&sid_data).unwrap();
        assert_eq!(rid, 1001);
    }

    /// Test extract_rid returns None for empty data.
    #[test]
    fn test_extract_rid_empty() {
        assert!(extract_rid(&[]).is_none());
    }

    /// Test extract_rid returns None for SID with no sub-authorities.
    #[test]
    fn test_extract_rid_no_sub_authorities() {
        // revision=1, count=0, authority=5
        let data = vec![1, 0, 0, 0, 0, 0, 0, 5];
        assert!(extract_rid(&data).is_none());
    }

    /// Test domain_sid extracts parent SID correctly.
    #[test]
    fn test_domain_sid() {
        let result = domain_sid("S-1-5-21-1000-2000-3000-500").unwrap();
        assert_eq!(result, "S-1-5-21-1000-2000-3000");
    }

    /// Test domain_sid with minimal SID.
    #[test]
    fn test_domain_sid_minimal() {
        let result = domain_sid("S-1-5-18").unwrap();
        assert_eq!(result, "S-1-5");
    }

    /// Test well-known RIDs (krbtgt=502, Guest=501).
    #[test]
    fn test_extract_rid_well_known() {
        let sid_data = build_test_sid(1, 5, &[21, 1000, 2000, 3000, 502]);
        assert_eq!(extract_rid(&sid_data).unwrap(), 502);
    }

    /// Test parse_sid with truncated sub-authority data.
    #[test]
    fn test_parse_sid_truncated_sub_auth() {
        // Claims 2 sub-authorities but only has room for 1
        let data = vec![1, 2, 0, 0, 0, 0, 0, 5, 0x15, 0x00, 0x00, 0x00];
        assert!(parse_sid(&data).is_none());
    }
}

// ==================== Timestamp Tests ====================

mod timestamp_tests {
    use poneglyph_lib::objects::filetime_to_string;
    use poneglyph_lib::objects::filetime_to_epoch;

    /// Test converting a known FILETIME to string.
    /// 2024-01-01 00:00:00 UTC = Unix 1704067200
    /// FILETIME = 1704067200 * 10_000_000 + 116_444_736_000_000_000 = 133_485_408_000_000_000
    #[test]
    fn test_filetime_to_string_2024() {
        let ft: i64 = 133_485_408_000_000_000;
        let result = filetime_to_string(ft).unwrap();
        assert_eq!(result, "2024-01-01 00:00:00 UTC");
    }

    /// Test FILETIME epoch conversion.
    #[test]
    fn test_filetime_to_epoch_2024() {
        let ft: i64 = 133_485_408_000_000_000;
        let epoch = filetime_to_epoch(ft).unwrap();
        // 2024-01-01 00:00:00 UTC = Unix timestamp 1704067200
        assert_eq!(epoch, 1_704_067_200);
    }

    /// Test FILETIME=0 returns None (never set).
    #[test]
    fn test_filetime_zero() {
        assert!(filetime_to_string(0).is_none());
        assert!(filetime_to_epoch(0).is_none());
    }

    /// Test FILETIME=0x7FFFFFFFFFFFFFFF returns None (never/max).
    #[test]
    fn test_filetime_max() {
        assert!(filetime_to_string(0x7FFFFFFFFFFFFFFF).is_none());
        assert!(filetime_to_epoch(0x7FFFFFFFFFFFFFFF).is_none());
    }

    /// Test negative FILETIME returns None.
    #[test]
    fn test_filetime_negative() {
        assert!(filetime_to_string(-1).is_none());
        assert!(filetime_to_epoch(-1).is_none());
    }

    /// Test very old FILETIME (before Unix epoch) returns None.
    #[test]
    fn test_filetime_before_unix_epoch() {
        // 1600-01-01 → before Unix epoch
        assert!(filetime_to_string(1).is_none());
    }

    /// Test FILETIME for Unix epoch itself (1970-01-01 00:00:00 UTC).
    /// FILETIME = 116444736000000000
    #[test]
    fn test_filetime_unix_epoch() {
        let ft: i64 = 116_444_736_000_000_000;
        let result = filetime_to_string(ft).unwrap();
        assert_eq!(result, "1970-01-01 00:00:00 UTC");
        assert_eq!(filetime_to_epoch(ft).unwrap(), 0);
    }
}

// ==================== UAC Flag Tests ====================

mod uac_tests {
    use poneglyph_lib::objects::describe_uac;

    /// Test normal user account.
    #[test]
    fn test_uac_normal_account() {
        let flags = describe_uac(0x200); // NORMAL_ACCOUNT
        assert!(flags.contains(&"NORMAL_ACCOUNT"));
        assert!(!flags.contains(&"DISABLED"));
    }

    /// Test disabled account.
    #[test]
    fn test_uac_disabled() {
        let flags = describe_uac(0x202); // NORMAL_ACCOUNT | ACCOUNTDISABLE
        assert!(flags.contains(&"NORMAL_ACCOUNT"));
        assert!(flags.contains(&"DISABLED"));
    }

    /// Test AS-REP roastable account.
    #[test]
    fn test_uac_dont_req_preauth() {
        let flags = describe_uac(0x400200); // NORMAL_ACCOUNT | DONT_REQ_PREAUTH
        assert!(flags.contains(&"DONT_REQ_PREAUTH"));
    }

    /// Test domain controller UAC.
    #[test]
    fn test_uac_server_trust() {
        let flags = describe_uac(0x2000); // SERVER_TRUST_ACCOUNT
        assert!(flags.contains(&"SERVER_TRUST (DC)"));
    }

    /// Test multiple flags combined.
    #[test]
    fn test_uac_multiple_flags() {
        // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD | TRUSTED_FOR_DELEGATION
        let flags = describe_uac(0x200 | 0x10000 | 0x80000);
        assert!(flags.contains(&"NORMAL_ACCOUNT"));
        assert!(flags.contains(&"DONT_EXPIRE_PASSWORD"));
        assert!(flags.contains(&"TRUSTED_FOR_DELEGATION"));
    }

    /// Test empty UAC (0).
    #[test]
    fn test_uac_zero() {
        let flags = describe_uac(0);
        assert!(flags.is_empty());
    }

    /// Test workstation trust account.
    #[test]
    fn test_uac_workstation_trust() {
        let flags = describe_uac(0x1000); // WORKSTATION_TRUST_ACCOUNT
        assert!(flags.contains(&"WORKSTATION_TRUST"));
    }

    /// Test smartcard required.
    #[test]
    fn test_uac_smartcard() {
        let flags = describe_uac(0x40000); // SMARTCARD_REQUIRED
        assert!(flags.contains(&"SMARTCARD_REQUIRED"));
    }
}

// ==================== Group Type Tests ====================

mod group_type_tests {
    use poneglyph_lib::objects::group::describe_group_type;

    /// Test security global group.
    #[test]
    fn test_security_global() {
        let gt = -2147483646_i32; // 0x80000002 = SECURITY | GLOBAL
        let flags = describe_group_type(gt);
        assert!(flags.contains(&"Security".to_string()));
        assert!(flags.contains(&"Global".to_string()));
    }

    /// Test distribution universal group.
    #[test]
    fn test_distribution_universal() {
        let gt = 0x00000008; // UNIVERSAL (no security bit)
        let flags = describe_group_type(gt);
        assert!(flags.contains(&"Distribution".to_string()));
        assert!(flags.contains(&"Universal".to_string()));
    }

    /// Test builtin local security group.
    #[test]
    fn test_builtin_local_security() {
        let gt = -2147483647_i32; // 0x80000001 = SECURITY | BUILTIN_LOCAL
        let flags = describe_group_type(gt);
        assert!(flags.contains(&"Security".to_string()));
        assert!(flags.contains(&"BuiltinLocal".to_string()));
    }

    /// Test domain local security group.
    #[test]
    fn test_domain_local_security() {
        let gt = -2147483644_i32; // 0x80000004 = SECURITY | DOMAIN_LOCAL
        let flags = describe_group_type(gt);
        assert!(flags.contains(&"Security".to_string()));
        assert!(flags.contains(&"DomainLocal".to_string()));
    }

    /// Test distribution global group.
    #[test]
    fn test_distribution_global() {
        let gt = 0x00000002_i32; // GLOBAL (no security bit)
        let flags = describe_group_type(gt);
        assert!(flags.contains(&"Distribution".to_string()));
        assert!(flags.contains(&"Global".to_string()));
    }
}

// ==================== Trust Helper Tests ====================

mod trust_tests {
    /// Test UTF-16LE decoding.
    #[test]
    fn test_decode_utf16le() {
        // "TEST" in UTF-16LE: T=0x0054, E=0x0045, S=0x0053, T=0x0054
        let data = vec![0x54, 0x00, 0x45, 0x00, 0x53, 0x00, 0x54, 0x00];
        let result = poneglyph_lib::objects::trust::decode_utf16le(&data);
        assert_eq!(result, "TEST");
    }

    /// Test UTF-16LE decoding with trailing null.
    #[test]
    fn test_decode_utf16le_with_null() {
        let data = vec![0x41, 0x00, 0x42, 0x00, 0x00, 0x00]; // "AB\0"
        let result = poneglyph_lib::objects::trust::decode_utf16le(&data);
        assert_eq!(result, "AB");
    }

    /// Test UTF-16LE with empty input.
    #[test]
    fn test_decode_utf16le_empty() {
        let result = poneglyph_lib::objects::trust::decode_utf16le(&[]);
        assert_eq!(result, "");
    }

    /// Test UTF-16LE with odd byte count (truncated).
    #[test]
    fn test_decode_utf16le_odd_bytes() {
        // Odd number of bytes - chunks_exact(2) should skip the last byte
        let data = vec![0x41, 0x00, 0x42]; // "A" + dangling byte
        let result = poneglyph_lib::objects::trust::decode_utf16le(&data);
        assert_eq!(result, "A");
    }

    /// Test trust direction string conversion.
    #[test]
    fn test_trust_direction_str() {
        assert_eq!(poneglyph_lib::objects::trust::trust_direction_str(0), "Disabled");
        assert_eq!(poneglyph_lib::objects::trust::trust_direction_str(1), "Inbound");
        assert_eq!(poneglyph_lib::objects::trust::trust_direction_str(2), "Outbound");
        assert_eq!(poneglyph_lib::objects::trust::trust_direction_str(3), "Bidirectional");
        assert!(poneglyph_lib::objects::trust::trust_direction_str(99).starts_with("Unknown"));
    }

    /// Test trust type string conversion.
    #[test]
    fn test_trust_type_str() {
        assert_eq!(poneglyph_lib::objects::trust::trust_type_str(1), "Downlevel (NT4)");
        assert_eq!(poneglyph_lib::objects::trust::trust_type_str(2), "Uplevel (AD)");
        assert_eq!(poneglyph_lib::objects::trust::trust_type_str(3), "MIT (Kerberos)");
        assert_eq!(poneglyph_lib::objects::trust::trust_type_str(4), "DCE");
        assert!(poneglyph_lib::objects::trust::trust_type_str(99).starts_with("Unknown"));
    }
}

// ==================== ACL Parsing Tests ====================

mod acl_tests {
    use poneglyph_lib::acl::parse_security_descriptor;

    /// Build a minimal valid security descriptor with a DACL.
    fn build_sd_with_dacl(dacl: &[u8]) -> Vec<u8> {
        let dacl_offset = 20u32; // Right after the SD header
        let mut sd = Vec::new();

        // SD header (20 bytes)
        sd.push(1);  // revision
        sd.push(0);  // sbz1
        sd.extend_from_slice(&0x8004u16.to_le_bytes()); // control: SE_DACL_PRESENT | SE_SELF_RELATIVE
        sd.extend_from_slice(&0u32.to_le_bytes()); // owner offset (0 = not present)
        sd.extend_from_slice(&0u32.to_le_bytes()); // group offset
        sd.extend_from_slice(&0u32.to_le_bytes()); // sacl offset
        sd.extend_from_slice(&dacl_offset.to_le_bytes()); // dacl offset

        sd.extend_from_slice(dacl);
        sd
    }

    /// Build a minimal ACL header.
    fn build_acl_header(ace_count: u16, aces: &[u8]) -> Vec<u8> {
        let acl_size = 8 + aces.len() as u16;
        let mut acl = Vec::new();
        acl.push(2); // revision
        acl.push(0); // sbz1
        acl.extend_from_slice(&acl_size.to_le_bytes());
        acl.extend_from_slice(&ace_count.to_le_bytes());
        acl.extend_from_slice(&0u16.to_le_bytes()); // sbz2
        acl.extend_from_slice(aces);
        acl
    }

    /// Test parsing SD with no DACL present.
    #[test]
    fn test_sd_no_dacl() {
        let mut sd = vec![0u8; 20];
        sd[0] = 1; // revision
        sd[2] = 0; sd[3] = 0; // control: no SE_DACL_PRESENT
        let result = parse_security_descriptor(&sd).unwrap();
        assert!(result.is_empty());
    }

    /// Test parsing SD that is too short.
    #[test]
    fn test_sd_too_short() {
        let result = parse_security_descriptor(&[1, 0, 0, 0, 0]);
        assert!(result.is_err());
    }

    /// Test parsing SD with empty DACL (0 ACEs).
    #[test]
    fn test_sd_empty_dacl() {
        let dacl = build_acl_header(0, &[]);
        let sd = build_sd_with_dacl(&dacl);
        let result = parse_security_descriptor(&sd).unwrap();
        assert!(result.is_empty());
    }

    /// Test parsing ACCESS_ALLOWED_ACE with GenericAll.
    #[test]
    fn test_allowed_ace_generic_all() {
        // Build a simple ACCESS_ALLOWED_ACE
        // SID: S-1-5-21-0-0-0-1001 (RID 1001 in BE)
        let sid_bytes = {
            let mut s = vec![1u8, 4]; // revision=1, sub_auth_count=4
            s.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // authority=5
            s.extend_from_slice(&21u32.to_le_bytes());   // sub-auth 1
            s.extend_from_slice(&0u32.to_le_bytes());    // sub-auth 2
            s.extend_from_slice(&0u32.to_le_bytes());    // sub-auth 3
            s.extend_from_slice(&1001u32.to_be_bytes()); // RID (BE per NTDS)
            s
        };

        let ace_size = (4 + 4 + sid_bytes.len()) as u16;
        let mut ace = Vec::new();
        ace.push(0x00); // type: ACCESS_ALLOWED_ACE
        ace.push(0x00); // flags: not inherited
        ace.extend_from_slice(&ace_size.to_le_bytes());
        ace.extend_from_slice(&0x10000000u32.to_le_bytes()); // mask: GENERIC_ALL
        ace.extend_from_slice(&sid_bytes);

        let dacl = build_acl_header(1, &ace);
        let sd = build_sd_with_dacl(&dacl);
        let result = parse_security_descriptor(&sd).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].right_name, "GenericAll");
        assert!(!result[0].is_inherited);
    }
}

// ==================== Forensics Anomaly Tests ====================

mod anomaly_tests {
    use std::collections::HashMap;
    use poneglyph_lib::objects::user::AdUser;
    use poneglyph_lib::objects::computer::AdComputer;
    use poneglyph_lib::acl::AceEntry;
    use poneglyph_lib::forensics::anomaly::run_all_rules;

    fn make_user(name: &str, uac: u32, enabled: bool) -> AdUser {
        AdUser {
            sam_account_name: name.to_string(),
            display_name: None,
            user_principal_name: None,
            sid: Some(format!("S-1-5-21-1000-2000-3000-{}", 1000 + name.len())),
            rid: Some(1000 + name.len() as u32),
            description: None,
            enabled,
            user_account_control: uac,
            uac_flags: vec![],
            admin_count: None,
            primary_group_id: None,
            when_created: None,
            when_changed: None,
            pwd_last_set: None,
            last_logon: None,
            last_logon_timestamp: None,
            logon_count: None,
            bad_pwd_count: None,
            spns: vec![],
            has_sid_history: false,
            has_key_credential_link: false,
            dnt: None,
            has_nt_hash: true,
            has_lm_hash: false,
        }
    }

    fn make_computer(name: &str, uac: u32, enabled: bool, is_dc: bool) -> AdComputer {
        AdComputer {
            sam_account_name: name.to_string(),
            dns_hostname: Some(format!("{}.test.local", name)),
            sid: Some(format!("S-1-5-21-1000-2000-3000-{}", 2000 + name.len())),
            rid: Some(2000 + name.len() as u32),
            description: None,
            enabled,
            user_account_control: uac,
            uac_flags: vec![],
            operating_system: Some("Windows Server 2022".to_string()),
            os_version: None,
            os_service_pack: None,
            when_created: None,
            when_changed: None,
            last_logon: None,
            last_logon_timestamp: None,
            primary_group_id: None,
            is_dc,
            dnt: None,
        }
    }

    /// Test ANOM-001: AS-REP Roastable detection.
    #[test]
    fn test_asrep_roastable_detection() {
        let users = vec![
            make_user("normal_user", 0x200, true),                // NORMAL_ACCOUNT
            make_user("asrep_user", 0x200 | 0x400000, true),      // DONT_REQ_PREAUTH
            make_user("disabled_asrep", 0x200 | 0x400000, false), // disabled, should not flag
        ];

        let findings = run_all_rules(&users, &[], &[], &HashMap::new()).unwrap();

        let anom001 = findings.iter().find(|f| f.rule_id == "ANOM-001");
        assert!(anom001.is_some(), "ANOM-001 should fire");
        let finding = anom001.unwrap();
        assert_eq!(finding.affected_objects.len(), 1, "Only enabled ASREP user should be flagged");
        assert_eq!(finding.affected_objects[0].name, "asrep_user");
    }

    /// Test ANOM-002: Password Not Required detection.
    #[test]
    fn test_passwd_not_required_detection() {
        let users = vec![
            make_user("normal", 0x200, true),
            make_user("no_passwd", 0x200 | 0x20, true), // PASSWD_NOTREQD
        ];

        let findings = run_all_rules(&users, &[], &[], &HashMap::new()).unwrap();

        let anom002 = findings.iter().find(|f| f.rule_id == "ANOM-002");
        assert!(anom002.is_some(), "ANOM-002 should fire");
        assert_eq!(anom002.unwrap().affected_objects.len(), 1);
        assert_eq!(anom002.unwrap().affected_objects[0].name, "no_passwd");
    }

    /// Test ANOM-003: Non-Expiring Password on privileged accounts.
    #[test]
    fn test_non_expiring_privileged() {
        let mut admin = make_user("admin", 0x200 | 0x10000, true); // DONT_EXPIRE_PASSWORD
        admin.admin_count = Some(1); // privileged

        let mut normal = make_user("normal", 0x200 | 0x10000, true);
        normal.admin_count = None; // not privileged

        let findings = run_all_rules(&[admin, normal], &[], &[], &HashMap::new()).unwrap();

        let anom003 = findings.iter().find(|f| f.rule_id == "ANOM-003");
        assert!(anom003.is_some(), "ANOM-003 should fire");
        assert_eq!(anom003.unwrap().affected_objects.len(), 1);
        assert_eq!(anom003.unwrap().affected_objects[0].name, "admin");
    }

    /// Test ANOM-006: Unconstrained Delegation on non-DC computer.
    #[test]
    fn test_unconstrained_delegation() {
        let computers = vec![
            make_computer("DC01$", 0x2000 | 0x80000, true, true),   // DC with delegation — should NOT flag
            make_computer("SRV01$", 0x1000 | 0x80000, true, false), // Non-DC with delegation — SHOULD flag
            make_computer("SRV02$", 0x1000, true, false),           // Normal workstation — no flag
        ];

        let findings = run_all_rules(&[], &computers, &[], &HashMap::new()).unwrap();

        let anom006 = findings.iter().find(|f| f.rule_id == "ANOM-006");
        assert!(anom006.is_some(), "ANOM-006 should fire for non-DC unconstrained delegation");
        assert_eq!(anom006.unwrap().affected_objects.len(), 1);
        assert_eq!(anom006.unwrap().affected_objects[0].name, "SRV01$");
    }

    /// Test ANOM-009: High bad password count.
    #[test]
    fn test_high_bad_password_count() {
        let mut user = make_user("bruteforce_target", 0x200, true);
        user.bad_pwd_count = Some(10);

        let mut clean = make_user("clean", 0x200, true);
        clean.bad_pwd_count = Some(0);

        let findings = run_all_rules(&[user, clean], &[], &[], &HashMap::new()).unwrap();

        let anom009 = findings.iter().find(|f| f.rule_id == "ANOM-009");
        assert!(anom009.is_some(), "ANOM-009 should fire for high bad password count");
        assert_eq!(anom009.unwrap().affected_objects.len(), 1);
        assert_eq!(anom009.unwrap().affected_objects[0].name, "bruteforce_target");
    }

    /// Test ANOM-011: DCSync-Capable accounts.
    #[test]
    fn test_dcsync_capable() {
        let mut aces_by_sid: HashMap<String, Vec<AceEntry>> = HashMap::new();

        // Non-admin SID with both GetChanges + GetChangesAll
        aces_by_sid.insert("S-1-5-21-1000-2000-3000-9999".to_string(), vec![
            AceEntry {
                principal_sid: "S-1-5-21-1000-2000-3000-9999".to_string(),
                principal_type: "User".to_string(),
                right_name: "GetChanges".to_string(),
                ace_type: "Allow".to_string(),
                is_inherited: false,
            },
            AceEntry {
                principal_sid: "S-1-5-21-1000-2000-3000-9999".to_string(),
                principal_type: "User".to_string(),
                right_name: "GetChangesAll".to_string(),
                ace_type: "Allow".to_string(),
                is_inherited: false,
            },
        ]);

        // Admin SID (RID 512 = Domain Admins) should be skipped
        aces_by_sid.insert("S-1-5-21-1000-2000-3000-512".to_string(), vec![
            AceEntry {
                principal_sid: "S-1-5-21-1000-2000-3000-512".to_string(),
                principal_type: "Group".to_string(),
                right_name: "GetChanges".to_string(),
                ace_type: "Allow".to_string(),
                is_inherited: false,
            },
            AceEntry {
                principal_sid: "S-1-5-21-1000-2000-3000-512".to_string(),
                principal_type: "Group".to_string(),
                right_name: "GetChangesAll".to_string(),
                ace_type: "Allow".to_string(),
                is_inherited: false,
            },
        ]);

        let findings = run_all_rules(&[], &[], &[], &aces_by_sid).unwrap();

        let anom011 = findings.iter().find(|f| f.rule_id == "ANOM-011");
        assert!(anom011.is_some(), "ANOM-011 should fire for non-admin DCSync principal");
        assert_eq!(anom011.unwrap().affected_objects.len(), 1);
    }

    /// Test ANOM-012: SID History Present.
    #[test]
    fn test_sid_history_present() {
        let mut user = make_user("migrated_user", 0x200, true);
        user.has_sid_history = true;

        let findings = run_all_rules(&[user], &[], &[], &HashMap::new()).unwrap();

        let anom012 = findings.iter().find(|f| f.rule_id == "ANOM-012");
        assert!(anom012.is_some(), "ANOM-012 should fire for user with SID history");
        assert_eq!(anom012.unwrap().affected_objects.len(), 1);
    }

    /// Test ANOM-013: Shadow Credentials.
    #[test]
    fn test_shadow_credentials() {
        let mut user = make_user("shadow_user", 0x200, true);
        user.has_key_credential_link = true;

        let findings = run_all_rules(&[user], &[], &[], &HashMap::new()).unwrap();

        let anom013 = findings.iter().find(|f| f.rule_id == "ANOM-013");
        assert!(anom013.is_some(), "ANOM-013 should fire for user with key credential link");
    }

    /// Test ANOM-014: Kerberoastable accounts.
    #[test]
    fn test_kerberoastable() {
        let mut user = make_user("svc_sql", 0x200, true);
        user.spns = vec!["MSSQLSvc/db01.test.local:1433".to_string()];

        let mut no_spn = make_user("normal", 0x200, true);
        no_spn.spns = vec![];

        let findings = run_all_rules(&[user, no_spn], &[], &[], &HashMap::new()).unwrap();

        let anom014 = findings.iter().find(|f| f.rule_id == "ANOM-014");
        assert!(anom014.is_some(), "ANOM-014 should fire for kerberoastable account");
        assert_eq!(anom014.unwrap().affected_objects.len(), 1);
        assert_eq!(anom014.unwrap().affected_objects[0].name, "svc_sql");
    }

    /// Test that no findings are generated for clean users.
    #[test]
    fn test_no_anomalies_for_clean_users() {
        let users = vec![make_user("clean_user", 0x200, true)]; // just NORMAL_ACCOUNT

        let findings = run_all_rules(&users, &[], &[], &HashMap::new()).unwrap();

        // ANOM-001, ANOM-002, ANOM-003 should NOT fire
        assert!(findings.iter().find(|f| f.rule_id == "ANOM-001").is_none());
        assert!(findings.iter().find(|f| f.rule_id == "ANOM-002").is_none());
        assert!(findings.iter().find(|f| f.rule_id == "ANOM-003").is_none());
    }

    /// Test ANOM-008: AdminCount=1 inventory.
    #[test]
    fn test_admin_count_set() {
        let mut admin = make_user("admin_user", 0x200, true);
        admin.admin_count = Some(1);

        let findings = run_all_rules(&[admin], &[], &[], &HashMap::new()).unwrap();

        let anom008 = findings.iter().find(|f| f.rule_id == "ANOM-008");
        assert!(anom008.is_some(), "ANOM-008 should fire for adminCount=1");
    }
}

// ==================== Hashcat Output Tests ====================

mod hashcat_tests {
    use poneglyph_lib::crypto::UserHash;
    use poneglyph_lib::output::hashcat::{format_entry, write_hashes};

    fn make_hash(name: &str, rid: u32, nt: Option<[u8; 16]>, lm: Option<[u8; 16]>) -> UserHash {
        UserHash {
            sam_account_name: name.to_string(),
            rid,
            nt_hash: nt,
            lm_hash: lm,
        }
    }

    /// Test format_entry with both NT and LM hashes.
    #[test]
    fn test_format_entry_both_hashes() {
        let nt = [0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17,
                   0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c];
        let lm = [0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
                   0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee];
        let entry = make_hash("Administrator", 500, Some(nt), Some(lm));
        let result = format_entry(&entry);
        assert_eq!(result, "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::");
    }

    /// Test format_entry with no hashes (empty hash placeholders).
    #[test]
    fn test_format_entry_no_hashes() {
        let entry = make_hash("Guest", 501, None, None);
        let result = format_entry(&entry);
        assert_eq!(result, "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::");
    }

    /// Test format_entry with only NT hash.
    #[test]
    fn test_format_entry_nt_only() {
        let nt = [0xAB; 16];
        let entry = make_hash("user1", 1001, Some(nt), None);
        let result = format_entry(&entry);
        assert!(result.starts_with("user1:1001:aad3b435b51404eeaad3b435b51404ee:abababababababababababababababab:::"));
    }

    /// Test write_hashes to a temp file.
    #[test]
    fn test_write_hashes_to_file() {
        let entries = vec![
            make_hash("zuser", 1002, None, None),
            make_hash("auser", 1001, None, None),
        ];
        let dir = std::env::temp_dir().join("poneglyph_test_hashcat");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("hashes.txt");
        write_hashes(&entries, Some(&path)).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        // Output should be sorted alphabetically
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("auser:"));
        assert!(lines[1].starts_with("zuser:"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test write_hashes with empty entries.
    #[test]
    fn test_write_hashes_empty() {
        let dir = std::env::temp_dir().join("poneglyph_test_hashcat_empty");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("hashes_empty.txt");
        write_hashes(&[], Some(&path)).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.trim(), "");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ==================== BloodHound Output Tests ====================

mod bloodhound_tests {
    use poneglyph_lib::objects::user::AdUser;
    use poneglyph_lib::objects::computer::AdComputer;
    use poneglyph_lib::objects::group::AdGroup;
    use poneglyph_lib::objects::trust::AdTrust;
    use poneglyph_lib::output::bloodhound::write_bloodhound;

    fn make_user(name: &str, sid: &str, enabled: bool) -> AdUser {
        AdUser {
            sam_account_name: name.to_string(),
            display_name: Some(format!("{} Display", name)),
            user_principal_name: None,
            sid: Some(sid.to_string()),
            rid: Some(500),
            description: None,
            enabled,
            user_account_control: 0x200,
            uac_flags: vec!["NORMAL_ACCOUNT".to_string()],
            admin_count: Some(1),
            primary_group_id: Some(513),
            when_created: Some("2024-01-01 00:00:00 UTC".to_string()),
            when_changed: None,
            pwd_last_set: Some("2024-06-01 12:00:00 UTC".to_string()),
            last_logon: None,
            last_logon_timestamp: None,
            logon_count: None,
            bad_pwd_count: None,
            spns: vec!["MSSQLSvc/db01:1433".to_string()],
            has_sid_history: false,
            has_key_credential_link: false,
            dnt: None,
            has_nt_hash: true,
            has_lm_hash: false,
        }
    }

    fn make_group(name: &str, sid: &str, members: Vec<String>) -> AdGroup {
        AdGroup {
            sam_account_name: name.to_string(),
            sid: Some(sid.to_string()),
            rid: Some(512),
            description: None,
            group_type: -2147483646,
            group_type_flags: vec!["Security".to_string(), "Global".to_string()],
            admin_count: Some(1),
            when_created: Some("2024-01-01 00:00:00 UTC".to_string()),
            when_changed: None,
            high_value: true,
            dnt: None,
            members,
        }
    }

    fn make_computer(name: &str, sid: &str, is_dc: bool) -> AdComputer {
        AdComputer {
            sam_account_name: name.to_string(),
            dns_hostname: Some(format!("{}.test.local", name.trim_end_matches('$'))),
            sid: Some(sid.to_string()),
            rid: Some(1000),
            description: None,
            enabled: true,
            user_account_control: if is_dc { 0x2000 } else { 0x1000 },
            uac_flags: vec![],
            operating_system: Some("Windows Server 2022".to_string()),
            os_version: None,
            os_service_pack: None,
            when_created: None,
            when_changed: None,
            last_logon: None,
            last_logon_timestamp: None,
            primary_group_id: Some(515),
            is_dc,
            dnt: None,
        }
    }

    fn make_trust(partner: &str, sid: &str) -> AdTrust {
        AdTrust {
            trust_partner: partner.to_string(),
            trust_direction: 3,
            trust_direction_str: "Bidirectional".to_string(),
            trust_type: 2,
            trust_type_str: "Uplevel (AD)".to_string(),
            trust_attributes: 0,
            sid: Some(sid.to_string()),
            when_created: None,
        }
    }

    /// Test BloodHound JSON output generates all 4 files.
    #[test]
    fn test_bloodhound_generates_files() {
        let dir = std::env::temp_dir().join("poneglyph_test_bloodhound");
        let _ = std::fs::remove_dir_all(&dir);

        let users = vec![make_user("Administrator", "S-1-5-21-1000-2000-3000-500", true)];
        let groups = vec![make_group("Domain Admins", "S-1-5-21-1000-2000-3000-512",
            vec!["S-1-5-21-1000-2000-3000-500".to_string()])];
        let computers = vec![make_computer("DC01$", "S-1-5-21-1000-2000-3000-1000", true)];
        let trusts = vec![make_trust("child.test.local", "S-1-5-21-4000-5000-6000")];

        write_bloodhound(&dir, "TEST.LOCAL", &users, &computers, &groups, &trusts).unwrap();

        assert!(dir.join("users.json").exists(), "users.json should exist");
        assert!(dir.join("groups.json").exists(), "groups.json should exist");
        assert!(dir.join("computers.json").exists(), "computers.json should exist");
        assert!(dir.join("domains.json").exists(), "domains.json should exist");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test BloodHound users.json structure.
    #[test]
    fn test_bloodhound_users_json_structure() {
        let dir = std::env::temp_dir().join("poneglyph_test_bh_users");
        let _ = std::fs::remove_dir_all(&dir);

        let users = vec![make_user("admin", "S-1-5-21-1000-2000-3000-500", true)];
        write_bloodhound(&dir, "TEST.LOCAL", &users, &[], &[], &[]).unwrap();

        let content = std::fs::read_to_string(dir.join("users.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Verify meta
        assert_eq!(json["meta"]["type"], "users");
        assert_eq!(json["meta"]["count"], 1);
        assert_eq!(json["meta"]["version"], 5);

        // Verify data
        let data = &json["data"][0];
        assert_eq!(data["ObjectIdentifier"], "S-1-5-21-1000-2000-3000-500");
        assert_eq!(data["Properties"]["name"], "ADMIN@TEST.LOCAL");
        assert_eq!(data["Properties"]["enabled"], true);
        assert_eq!(data["Properties"]["hasspn"], true);
        assert_eq!(data["PrimaryGroupSID"], "S-1-5-21-1000-2000-3000-513");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test BloodHound groups.json includes members.
    #[test]
    fn test_bloodhound_groups_json_members() {
        let dir = std::env::temp_dir().join("poneglyph_test_bh_groups");
        let _ = std::fs::remove_dir_all(&dir);

        let groups = vec![make_group("Domain Admins", "S-1-5-21-1000-2000-3000-512",
            vec!["S-1-5-21-1000-2000-3000-500".to_string()])];
        write_bloodhound(&dir, "TEST.LOCAL", &[], &[], &groups, &[]).unwrap();

        let content = std::fs::read_to_string(dir.join("groups.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        let members = &json["data"][0]["Members"];
        assert_eq!(members.as_array().unwrap().len(), 1);
        assert_eq!(members[0]["ObjectIdentifier"], "S-1-5-21-1000-2000-3000-500");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test BloodHound domains.json includes trust data.
    #[test]
    fn test_bloodhound_domains_json_trusts() {
        let dir = std::env::temp_dir().join("poneglyph_test_bh_domains");
        let _ = std::fs::remove_dir_all(&dir);

        let users = vec![make_user("admin", "S-1-5-21-1000-2000-3000-500", true)];
        let trusts = vec![make_trust("child.test.local", "S-1-5-21-4000-5000-6000")];
        write_bloodhound(&dir, "TEST.LOCAL", &users, &[], &[], &trusts).unwrap();

        let content = std::fs::read_to_string(dir.join("domains.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        let domain_trusts = &json["data"][0]["Trusts"];
        assert_eq!(domain_trusts.as_array().unwrap().len(), 1);
        assert_eq!(domain_trusts[0]["TargetDomainName"], "CHILD.TEST.LOCAL");
        assert_eq!(domain_trusts[0]["TrustDirection"], "Bidirectional");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ==================== CSV Timeline Output Tests ====================

mod csv_tests {
    use poneglyph_lib::objects::user::AdUser;
    use poneglyph_lib::objects::computer::AdComputer;
    use poneglyph_lib::objects::group::AdGroup;
    use poneglyph_lib::output::csv::write_timeline;

    fn make_user_for_timeline(name: &str, created: Option<&str>, pwd_set: Option<&str>) -> AdUser {
        AdUser {
            sam_account_name: name.to_string(),
            display_name: None,
            user_principal_name: None,
            sid: Some("S-1-5-21-1000-2000-3000-500".to_string()),
            rid: Some(500),
            description: None,
            enabled: true,
            user_account_control: 0x200,
            uac_flags: vec![],
            admin_count: None,
            primary_group_id: None,
            when_created: created.map(|s| s.to_string()),
            when_changed: None,
            pwd_last_set: pwd_set.map(|s| s.to_string()),
            last_logon: None,
            last_logon_timestamp: None,
            logon_count: None,
            bad_pwd_count: None,
            spns: vec![],
            has_sid_history: false,
            has_key_credential_link: false,
            dnt: None,
            has_nt_hash: false,
            has_lm_hash: false,
        }
    }

    fn make_computer_for_timeline(name: &str, created: Option<&str>) -> AdComputer {
        AdComputer {
            sam_account_name: name.to_string(),
            dns_hostname: Some(format!("{}.test.local", name.trim_end_matches('$'))),
            sid: Some("S-1-5-21-1000-2000-3000-1000".to_string()),
            rid: Some(1000),
            description: None,
            enabled: true,
            user_account_control: 0x1000,
            uac_flags: vec![],
            operating_system: Some("Windows Server 2022".to_string()),
            os_version: None,
            os_service_pack: None,
            when_created: created.map(|s| s.to_string()),
            when_changed: None,
            last_logon: None,
            last_logon_timestamp: None,
            primary_group_id: None,
            is_dc: false,
            dnt: None,
        }
    }

    fn make_group_for_timeline(name: &str, created: Option<&str>) -> AdGroup {
        AdGroup {
            sam_account_name: name.to_string(),
            sid: Some("S-1-5-21-1000-2000-3000-512".to_string()),
            rid: Some(512),
            description: None,
            group_type: -2147483646,
            group_type_flags: vec!["Security".to_string(), "Global".to_string()],
            admin_count: None,
            when_created: created.map(|s| s.to_string()),
            when_changed: None,
            high_value: false,
            dnt: None,
            members: vec![],
        }
    }

    /// Test timeline CSV has correct header.
    #[test]
    fn test_timeline_csv_header() {
        let dir = std::env::temp_dir().join("poneglyph_test_csv_header");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("timeline.csv");

        write_timeline(&path, &[], &[], &[]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let first_line = content.lines().next().unwrap();
        assert_eq!(first_line, "datetime,timestamp_desc,source,source_long,message,filename,inode,format,extra");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test timeline with user events.
    #[test]
    fn test_timeline_user_events() {
        let dir = std::env::temp_dir().join("poneglyph_test_csv_users");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("timeline.csv");

        let users = vec![make_user_for_timeline("admin",
            Some("2024-01-01 00:00:00 UTC"),
            Some("2024-06-15 12:00:00 UTC"))];

        write_timeline(&path, &users, &[], &[]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // header + creation + password change = 3 lines
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("Creation Time"));
        assert!(lines[1].contains("NTDS-User"));
        assert!(lines[2].contains("Password Change"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test timeline sorts by datetime.
    #[test]
    fn test_timeline_sorted_by_datetime() {
        let dir = std::env::temp_dir().join("poneglyph_test_csv_sort");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("timeline.csv");

        let users = vec![
            make_user_for_timeline("late_user", Some("2024-12-01 00:00:00 UTC"), None),
            make_user_for_timeline("early_user", Some("2024-01-01 00:00:00 UTC"), None),
        ];

        write_timeline(&path, &users, &[], &[]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().skip(1).collect(); // skip header
        assert!(lines[0].contains("early_user"), "Earlier event should come first");
        assert!(lines[1].contains("late_user"), "Later event should come second");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test timeline includes computer events.
    #[test]
    fn test_timeline_computer_events() {
        let dir = std::env::temp_dir().join("poneglyph_test_csv_comp");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("timeline.csv");

        let computers = vec![make_computer_for_timeline("DC01$", Some("2024-01-01 00:00:00 UTC"))];
        write_timeline(&path, &[], &computers, &[]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("NTDS-Computer"));
        assert!(content.contains("DC01.test.local"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test timeline includes group events.
    #[test]
    fn test_timeline_group_events() {
        let dir = std::env::temp_dir().join("poneglyph_test_csv_group");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("timeline.csv");

        let groups = vec![make_group_for_timeline("Domain Admins", Some("2024-01-01 00:00:00 UTC"))];
        write_timeline(&path, &[], &[], &groups).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("NTDS-Group"));
        assert!(content.contains("Domain Admins"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test timeline with no timestamps produces only the header.
    #[test]
    fn test_timeline_no_timestamps() {
        let dir = std::env::temp_dir().join("poneglyph_test_csv_notimestamp");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("timeline.csv");

        let users = vec![make_user_for_timeline("notime", None, None)];
        write_timeline(&path, &users, &[], &[]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "Only header should be present when no timestamps");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ==================== Graph Output Tests ====================

mod graph_tests {
    use poneglyph_lib::objects::user::AdUser;
    use poneglyph_lib::objects::computer::AdComputer;
    use poneglyph_lib::objects::group::AdGroup;
    use poneglyph_lib::objects::trust::AdTrust;
    use poneglyph_lib::output::graph::write_graph;

    fn make_user(name: &str, sid: &str) -> AdUser {
        AdUser {
            sam_account_name: name.to_string(),
            display_name: None,
            user_principal_name: None,
            sid: Some(sid.to_string()),
            rid: Some(500),
            description: None,
            enabled: true,
            user_account_control: 0x200,
            uac_flags: vec![],
            admin_count: Some(1),
            primary_group_id: None,
            when_created: None,
            when_changed: None,
            pwd_last_set: None,
            last_logon: None,
            last_logon_timestamp: None,
            logon_count: None,
            bad_pwd_count: None,
            spns: vec![],
            has_sid_history: false,
            has_key_credential_link: false,
            dnt: None,
            has_nt_hash: true,
            has_lm_hash: false,
        }
    }

    fn make_computer(name: &str, sid: &str, is_dc: bool) -> AdComputer {
        AdComputer {
            sam_account_name: name.to_string(),
            dns_hostname: Some(format!("{}.test.local", name.trim_end_matches('$'))),
            sid: Some(sid.to_string()),
            rid: Some(1000),
            description: None,
            enabled: true,
            user_account_control: if is_dc { 0x2000 } else { 0x1000 },
            uac_flags: vec![],
            operating_system: Some("Windows Server 2022".to_string()),
            os_version: None,
            os_service_pack: None,
            when_created: None,
            when_changed: None,
            last_logon: None,
            last_logon_timestamp: None,
            primary_group_id: None,
            is_dc,
            dnt: None,
        }
    }

    fn make_group(name: &str, sid: &str, members: Vec<String>) -> AdGroup {
        AdGroup {
            sam_account_name: name.to_string(),
            sid: Some(sid.to_string()),
            rid: Some(512),
            description: None,
            group_type: -2147483646,
            group_type_flags: vec!["Security".to_string(), "Global".to_string()],
            admin_count: None,
            when_created: None,
            when_changed: None,
            high_value: true,
            dnt: None,
            members,
        }
    }

    fn make_trust(partner: &str, sid: &str) -> AdTrust {
        AdTrust {
            trust_partner: partner.to_string(),
            trust_direction: 3,
            trust_direction_str: "Bidirectional".to_string(),
            trust_type: 2,
            trust_type_str: "Uplevel (AD)".to_string(),
            trust_attributes: 0,
            sid: Some(sid.to_string()),
            when_created: None,
        }
    }

    /// Test graph JSON contains correct nodes and links structure.
    #[test]
    fn test_graph_structure() {
        let dir = std::env::temp_dir().join("poneglyph_test_graph");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("graph.json");

        let users = vec![make_user("admin", "S-1-5-21-1000-2000-3000-500")];
        let computers = vec![make_computer("DC01$", "S-1-5-21-1000-2000-3000-1000", true)];
        let groups = vec![make_group("Domain Admins", "S-1-5-21-1000-2000-3000-512",
            vec!["S-1-5-21-1000-2000-3000-500".to_string()])];
        let trusts = vec![make_trust("child.test.local", "S-1-5-21-4000-5000-6000")];

        write_graph(&path, &users, &computers, &groups, &trusts).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        // nodes: 1 user + 1 computer + 1 group + 1 trust domain = 4
        let nodes = json["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 4);

        // links: 1 MemberOf + 1 Trust = 2
        let links = json["links"].as_array().unwrap();
        assert_eq!(links.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test graph node types are correct.
    #[test]
    fn test_graph_node_types() {
        let dir = std::env::temp_dir().join("poneglyph_test_graph_types");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("graph.json");

        let users = vec![make_user("admin", "S-1-5-21-1-2-3-500")];
        let computers = vec![
            make_computer("DC01$", "S-1-5-21-1-2-3-1000", true),
            make_computer("WS01$", "S-1-5-21-1-2-3-1001", false),
        ];

        write_graph(&path, &users, &computers, &[], &[]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        let nodes = json["nodes"].as_array().unwrap();
        let user_node = nodes.iter().find(|n| n["id"] == "S-1-5-21-1-2-3-500").unwrap();
        assert_eq!(user_node["type"], "user");

        let dc_node = nodes.iter().find(|n| n["id"] == "S-1-5-21-1-2-3-1000").unwrap();
        assert_eq!(dc_node["type"], "dc");

        let ws_node = nodes.iter().find(|n| n["id"] == "S-1-5-21-1-2-3-1001").unwrap();
        assert_eq!(ws_node["type"], "computer");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test graph MemberOf links are correct.
    #[test]
    fn test_graph_membership_links() {
        let dir = std::env::temp_dir().join("poneglyph_test_graph_links");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("graph.json");

        let groups = vec![make_group("Admins", "S-1-5-21-1-2-3-512",
            vec!["S-1-5-21-1-2-3-500".to_string(), "S-1-5-21-1-2-3-501".to_string()])];

        write_graph(&path, &[], &[], &groups, &[]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        let links = json["links"].as_array().unwrap();
        assert_eq!(links.len(), 2);
        assert!(links.iter().all(|l| l["type"] == "MemberOf"));
        assert!(links.iter().all(|l| l["target"] == "S-1-5-21-1-2-3-512"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test graph skips objects without SID.
    #[test]
    fn test_graph_skips_no_sid() {
        let dir = std::env::temp_dir().join("poneglyph_test_graph_nosid");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("graph.json");

        let mut user = make_user("no_sid_user", "");
        user.sid = None;

        write_graph(&path, &[user], &[], &[], &[]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        let nodes = json["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 0, "User without SID should be skipped");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Test graph with empty inputs.
    #[test]
    fn test_graph_empty() {
        let dir = std::env::temp_dir().join("poneglyph_test_graph_empty");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("graph.json");

        write_graph(&path, &[], &[], &[], &[]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(json["nodes"].as_array().unwrap().len(), 0);
        assert_eq!(json["links"].as_array().unwrap().len(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ==================== ACL Object ACE Tests ====================

mod acl_object_ace_tests {
    use poneglyph_lib::acl::parse_security_descriptor;

    /// Build a minimal valid security descriptor with a DACL.
    fn build_sd_with_dacl(dacl: &[u8]) -> Vec<u8> {
        let dacl_offset = 20u32;
        let mut sd = Vec::new();
        sd.push(1);  // revision
        sd.push(0);  // sbz1
        sd.extend_from_slice(&0x8004u16.to_le_bytes()); // control: SE_DACL_PRESENT | SE_SELF_RELATIVE
        sd.extend_from_slice(&0u32.to_le_bytes()); // owner offset
        sd.extend_from_slice(&0u32.to_le_bytes()); // group offset
        sd.extend_from_slice(&0u32.to_le_bytes()); // sacl offset
        sd.extend_from_slice(&dacl_offset.to_le_bytes()); // dacl offset
        sd.extend_from_slice(dacl);
        sd
    }

    fn build_acl_header(ace_count: u16, aces: &[u8]) -> Vec<u8> {
        let acl_size = 8 + aces.len() as u16;
        let mut acl = Vec::new();
        acl.push(2); // revision
        acl.push(0); // sbz1
        acl.extend_from_slice(&acl_size.to_le_bytes());
        acl.extend_from_slice(&ace_count.to_le_bytes());
        acl.extend_from_slice(&0u16.to_le_bytes()); // sbz2
        acl.extend_from_slice(aces);
        acl
    }

    fn build_simple_sid() -> Vec<u8> {
        let mut s = vec![1u8, 4]; // revision=1, sub_auth_count=4
        s.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // authority=5
        s.extend_from_slice(&21u32.to_le_bytes());
        s.extend_from_slice(&1000u32.to_le_bytes());
        s.extend_from_slice(&2000u32.to_le_bytes());
        s.extend_from_slice(&1001u32.to_be_bytes()); // RID in BE
        s
    }

    /// Test ACCESS_DENIED_ACE is skipped (only ALLOWED types are processed).
    #[test]
    fn test_access_denied_ace_skipped() {
        let sid_bytes = build_simple_sid();
        let ace_size = (4 + 4 + sid_bytes.len()) as u16;
        let mut ace = Vec::new();
        ace.push(0x01); // type: ACCESS_DENIED_ACE (not processed)
        ace.push(0x00); // flags
        ace.extend_from_slice(&ace_size.to_le_bytes());
        ace.extend_from_slice(&0x10000000u32.to_le_bytes()); // mask: GENERIC_ALL
        ace.extend_from_slice(&sid_bytes);

        let dacl = build_acl_header(1, &ace);
        let sd = build_sd_with_dacl(&dacl);
        let result = parse_security_descriptor(&sd).unwrap();

        // ACCESS_DENIED_ACE is not a BloodHound-relevant edge, so it should be skipped
        assert_eq!(result.len(), 0);
    }

    /// Test inherited ACE detection.
    #[test]
    fn test_inherited_ace_flag() {
        let sid_bytes = build_simple_sid();
        let ace_size = (4 + 4 + sid_bytes.len()) as u16;
        let mut ace = Vec::new();
        ace.push(0x00); // type: ACCESS_ALLOWED_ACE
        ace.push(0x10); // flags: INHERITED_ACE (0x10)
        ace.extend_from_slice(&ace_size.to_le_bytes());
        ace.extend_from_slice(&0x10000000u32.to_le_bytes()); // mask: GENERIC_ALL
        ace.extend_from_slice(&sid_bytes);

        let dacl = build_acl_header(1, &ace);
        let sd = build_sd_with_dacl(&dacl);
        let result = parse_security_descriptor(&sd).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].is_inherited, "ACE should be marked as inherited");
    }

    /// Test multiple ALLOW ACEs in a single DACL.
    #[test]
    fn test_multiple_aces() {
        let sid_bytes = build_simple_sid();
        let ace_size = (4 + 4 + sid_bytes.len()) as u16;

        let mut aces = Vec::new();

        // ACE 1: ALLOW GenericAll
        aces.push(0x00);
        aces.push(0x00);
        aces.extend_from_slice(&ace_size.to_le_bytes());
        aces.extend_from_slice(&0x10000000u32.to_le_bytes()); // GENERIC_ALL
        aces.extend_from_slice(&sid_bytes);

        // ACE 2: ALLOW WriteDacl
        aces.push(0x00);
        aces.push(0x00);
        aces.extend_from_slice(&ace_size.to_le_bytes());
        aces.extend_from_slice(&0x00040000u32.to_le_bytes()); // WRITE_DACL
        aces.extend_from_slice(&sid_bytes);

        let dacl = build_acl_header(2, &aces);
        let sd = build_sd_with_dacl(&dacl);
        let result = parse_security_descriptor(&sd).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].right_name, "GenericAll");
        assert_eq!(result[1].right_name, "WriteDacl");
    }

    /// Test WriteDacl right detection.
    #[test]
    fn test_write_dacl_right() {
        let sid_bytes = build_simple_sid();
        let ace_size = (4 + 4 + sid_bytes.len()) as u16;
        let mut ace = Vec::new();
        ace.push(0x00); // ACCESS_ALLOWED
        ace.push(0x00);
        ace.extend_from_slice(&ace_size.to_le_bytes());
        ace.extend_from_slice(&0x00040000u32.to_le_bytes()); // WRITE_DACL
        ace.extend_from_slice(&sid_bytes);

        let dacl = build_acl_header(1, &ace);
        let sd = build_sd_with_dacl(&dacl);
        let result = parse_security_descriptor(&sd).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].right_name, "WriteDacl");
    }
}
