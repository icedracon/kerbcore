//! RFC 4120 foundational data types — the shared vocabulary every Kerberos
//! message is built from. Each type owns its DER `encode()` and a total
//! `decode()` (no panics on hostile bytes; see [`crate::der`]).
//!
//! These replace the `picky_krb::data_types` structs that `adhammer-kerberos`
//! consumes (`PrincipalName`, `KerberosTime`, `PaData`, `EncryptedData`, …).

use crate::der::{
    context_tag, encode_general_string, encode_generalized_time, encode_integer,
    encode_octet_string, encode_sequence, explicit, Der, DerError, TAG_GENERALIZED_TIME,
    TAG_GENERAL_STRING, TAG_OCTET_STRING, TAG_SEQUENCE,
};

/// Parse the whole buffer as a single tagged element, require `tag`, and ensure
/// nothing trails. Used where a field's content is itself one complete element.
fn one(der: &[u8], tag: u8) -> Result<&[u8], DerError> {
    let mut r = Der::new(der);
    let content = r.expect(tag)?;
    r.finish()?;
    Ok(content)
}

/// Read an `INTEGER` element (full TLV) as `i32`.
fn read_i32(der: &[u8]) -> Result<i32, DerError> {
    let mut r = Der::new(der);
    let v = r.read_integer()?;
    r.finish()?;
    i32::try_from(v).map_err(|_| DerError::IntTooLarge)
}

/// Read a `GeneralString` element (full TLV) as a `String`.
fn read_kerberos_string(der: &[u8]) -> Result<String, DerError> {
    let c = one(der, TAG_GENERAL_STRING)?;
    Ok(String::from_utf8_lossy(c).into_owned())
}

// ── KerberosTime ────────────────────────────────────────────────────────────

/// `KerberosTime ::= GeneralizedTime` — e.g. `"20240102030405Z"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KerberosTime(pub String);

impl KerberosTime {
    /// Bare DER (a `GeneralizedTime` element).
    pub fn encode(&self) -> Vec<u8> {
        encode_generalized_time(&self.0)
    }
    /// Parse a `GeneralizedTime` element.
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let c = one(der, TAG_GENERALIZED_TIME)?;
        Ok(KerberosTime(String::from_utf8_lossy(c).into_owned()))
    }
}

// ── PrincipalName ───────────────────────────────────────────────────────────

/// `PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalName {
    /// `NT-PRINCIPAL` (1), `NT-SRV-INST` (2), `NT-SRV-HST` (3), …
    pub name_type: i32,
    /// e.g. `["HTTP", "web.example.com"]` for a service name.
    pub name_string: Vec<String>,
}

impl PrincipalName {
    /// Bare DER (a `SEQUENCE`).
    pub fn encode(&self) -> Vec<u8> {
        let nt = explicit(0, &encode_integer(self.name_type as i64));
        let strs: Vec<u8> = self
            .name_string
            .iter()
            .flat_map(|s| encode_general_string(s))
            .collect();
        let ns = explicit(1, &encode_sequence(&strs));
        encode_sequence(&[nt, ns].concat())
    }

    /// Parse a `PrincipalName` `SEQUENCE`.
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let body = one(der, TAG_SEQUENCE)?;
        let mut r = Der::new(body);
        let name_type = read_i32(r.expect(context_tag(0))?)?;
        let ns_seq = one(r.expect(context_tag(1))?, TAG_SEQUENCE)?;
        r.finish()?;
        let mut sr = Der::new(ns_seq);
        let mut name_string = Vec::new();
        while !sr.is_empty() {
            let s = sr.expect(TAG_GENERAL_STRING)?;
            name_string.push(String::from_utf8_lossy(s).into_owned());
        }
        Ok(PrincipalName {
            name_type,
            name_string,
        })
    }
}

// ── EncryptionKey ───────────────────────────────────────────────────────────

/// `EncryptionKey ::= SEQUENCE { keytype [0] Int32, keyvalue [1] OCTET STRING }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptionKey {
    /// The enctype (18 = aes256-cts-hmac-sha1-96, …).
    pub keytype: i32,
    /// The raw key bytes.
    pub keyvalue: Vec<u8>,
}

impl EncryptionKey {
    /// Bare DER.
    pub fn encode(&self) -> Vec<u8> {
        let kt = explicit(0, &encode_integer(self.keytype as i64));
        let kv = explicit(1, &encode_octet_string(&self.keyvalue));
        encode_sequence(&[kt, kv].concat())
    }
    /// Parse.
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let body = one(der, TAG_SEQUENCE)?;
        let mut r = Der::new(body);
        let keytype = read_i32(r.expect(context_tag(0))?)?;
        let keyvalue = one(r.expect(context_tag(1))?, TAG_OCTET_STRING)?.to_vec();
        r.finish()?;
        Ok(EncryptionKey { keytype, keyvalue })
    }
}

// ── EncryptedData ───────────────────────────────────────────────────────────

/// `EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedData {
    /// The enctype the `cipher` was produced under.
    pub etype: i32,
    /// Key version number, if the KDC supplied one.
    pub kvno: Option<u32>,
    /// The ciphertext (RFC 3961/8009 encrypt-then-MAC output).
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    /// Bare DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = explicit(0, &encode_integer(self.etype as i64));
        if let Some(kvno) = self.kvno {
            body.extend_from_slice(&explicit(1, &encode_integer(kvno as i64)));
        }
        body.extend_from_slice(&explicit(2, &encode_octet_string(&self.cipher)));
        encode_sequence(&body)
    }
    /// Parse.
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let body = one(der, TAG_SEQUENCE)?;
        let mut r = Der::new(body);
        let etype = read_i32(r.expect(context_tag(0))?)?;
        let kvno = if r.peek_tag() == Some(context_tag(1)) {
            Some(crate::der::read_u32(r.expect(context_tag(1))?)?)
        } else {
            None
        };
        let cipher = one(r.expect(context_tag(2))?, TAG_OCTET_STRING)?.to_vec();
        r.finish()?;
        Ok(EncryptedData {
            etype,
            kvno,
            cipher,
        })
    }
}

// ── PaData ──────────────────────────────────────────────────────────────────

/// `PA-DATA ::= SEQUENCE { padata-type [1] Int32, padata-value [2] OCTET STRING }`.
/// Note the field tags are `[1]`/`[2]`, not `[0]`/`[1]` — an RFC 4120 quirk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaData {
    /// e.g. `2` = PA-ENC-TIMESTAMP, `128` = PA-PAC-REQUEST.
    pub padata_type: i32,
    /// The type-specific value (already-encoded DER, usually).
    pub padata_value: Vec<u8>,
}

impl PaData {
    /// Bare DER.
    pub fn encode(&self) -> Vec<u8> {
        let t = explicit(1, &encode_integer(self.padata_type as i64));
        let v = explicit(2, &encode_octet_string(&self.padata_value));
        encode_sequence(&[t, v].concat())
    }
    /// Parse.
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let body = one(der, TAG_SEQUENCE)?;
        let mut r = Der::new(body);
        let padata_type = read_i32(r.expect(context_tag(1))?)?;
        let padata_value = one(r.expect(context_tag(2))?, TAG_OCTET_STRING)?.to_vec();
        r.finish()?;
        Ok(PaData {
            padata_type,
            padata_value,
        })
    }
}

// ── Checksum ────────────────────────────────────────────────────────────────

/// `Checksum ::= SEQUENCE { cksumtype [0] Int32, checksum [1] OCTET STRING }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checksum {
    /// Checksum type (e.g. `-138` = HMAC-MD5, `16` = HMAC-SHA1-96-AES256).
    pub cksumtype: i32,
    /// The checksum bytes.
    pub checksum: Vec<u8>,
}

impl Checksum {
    /// Bare DER.
    pub fn encode(&self) -> Vec<u8> {
        let t = explicit(0, &encode_integer(self.cksumtype as i64));
        let c = explicit(1, &encode_octet_string(&self.checksum));
        encode_sequence(&[t, c].concat())
    }
    /// Parse.
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let body = one(der, TAG_SEQUENCE)?;
        let mut r = Der::new(body);
        let cksumtype = read_i32(r.expect(context_tag(0))?)?;
        let checksum = one(r.expect(context_tag(1))?, TAG_OCTET_STRING)?.to_vec();
        r.finish()?;
        Ok(Checksum {
            cksumtype,
            checksum,
        })
    }
}

/// Encode a `Realm` (a bare `KerberosString`).
pub fn encode_realm(realm: &str) -> Vec<u8> {
    encode_general_string(realm)
}
/// Decode a `Realm`.
pub fn decode_realm(der: &[u8]) -> Result<String, DerError> {
    read_kerberos_string(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn principal_name_roundtrip_and_tags() {
        let pn = PrincipalName {
            name_type: 2, // NT-SRV-INST
            name_string: vec!["host".into(), "dc.example.com".into()],
        };
        let der = pn.encode();
        // Outer SEQUENCE, then [0] then [1].
        assert_eq!(der[0], TAG_SEQUENCE);
        assert!(hexs(&der).contains("a003020102")); // [0] { INTEGER 2 }
        assert_eq!(PrincipalName::decode(&der).unwrap(), pn);
    }

    #[test]
    fn encrypted_data_optional_kvno() {
        let with = EncryptedData {
            etype: 18,
            kvno: Some(2),
            cipher: vec![1, 2, 3, 4],
        };
        let der = with.encode();
        assert_eq!(EncryptedData::decode(&der).unwrap(), with);
        // [0] INTEGER 18, [1] INTEGER 2 present.
        assert!(hexs(&der).contains("a003020112")); // [0]{INTEGER 0x12=18}
        assert!(hexs(&der).contains("a103020102")); // [1]{INTEGER 2} (kvno)

        let without = EncryptedData {
            etype: 23,
            kvno: None,
            cipher: vec![0xaa],
        };
        let der2 = without.encode();
        assert_eq!(EncryptedData::decode(&der2).unwrap(), without);
        assert!(!hexs(&der2).contains("a1")); // no [1] kvno field
    }

    #[test]
    fn padata_uses_tags_1_and_2() {
        let p = PaData {
            padata_type: 128,
            padata_value: vec![0x30, 0x00],
        };
        let der = p.encode();
        assert_eq!(PaData::decode(&der).unwrap(), p);
        // First field is [1] (0xA1), NOT [0].
        let body = one(&der, TAG_SEQUENCE).unwrap();
        assert_eq!(body[0], context_tag(1));
    }

    #[test]
    fn key_time_checksum_realm_roundtrip() {
        let k = EncryptionKey {
            keytype: 18,
            keyvalue: vec![0; 32],
        };
        assert_eq!(EncryptionKey::decode(&k.encode()).unwrap(), k);
        let t = KerberosTime("20240102030405Z".into());
        assert_eq!(KerberosTime::decode(&t.encode()).unwrap(), t);
        let c = Checksum {
            cksumtype: 16,
            checksum: vec![9; 12],
        };
        assert_eq!(Checksum::decode(&c.encode()).unwrap(), c);
        assert_eq!(
            decode_realm(&encode_realm("EXAMPLE.COM")).unwrap(),
            "EXAMPLE.COM"
        );
    }

    #[test]
    fn decode_rejects_garbage_without_panic() {
        for bad in [&[][..], &[0x30, 0x03, 0x02, 0x01][..], &[0xff, 0xff][..]] {
            assert!(PrincipalName::decode(bad).is_err());
            assert!(EncryptedData::decode(bad).is_err());
        }
    }
}
