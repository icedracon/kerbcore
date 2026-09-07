#![no_main]
//! Fuzz every kerbcore decoder entry point against arbitrary bytes.
//!
//! kerbcore's decoders are documented as **total** — a hostile KDC / attacker
//! byte string must return `Err`, never panic. libFuzzer treats any panic (or
//! out-of-bounds index, arithmetic overflow, etc.) as a crash, so a clean run is
//! a machine-checked proof of the no-panic guarantee across the whole codec.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Low-level DER cursor: read a TLV and an integer.
    {
        let mut d = kerbcore::der::Der::new(data);
        let _ = d.read_tlv();
        let mut d2 = kerbcore::der::Der::new(data);
        let _ = d2.read_integer();
    }

    // Foundational types.
    let _ = kerbcore::types::PrincipalName::decode(data);
    let _ = kerbcore::types::EncryptedData::decode(data);
    let _ = kerbcore::types::EncryptionKey::decode(data);
    let _ = kerbcore::types::PaData::decode(data);
    let _ = kerbcore::types::Checksum::decode(data);
    let _ = kerbcore::types::KerberosTime::decode(data);

    // Messages — the top-level PDUs a KDC sends back.
    let _ = kerbcore::messages::Ticket::decode(data);
    let _ = kerbcore::messages::KdcReq::decode(data);
    let _ = kerbcore::messages::KdcRep::decode(data);
    let _ = kerbcore::messages::KrbError::decode(data);
    let _ = kerbcore::messages::KdcReqBody::decode(data);

    // Client-side parsers that consume raw KDC bytes.
    let _ = kerbcore::client::parse_etype_info2(data);
    let _ = kerbcore::client::enc_kdc_rep_part_session_key(data);
});
