//! `gss_wrap_unwrap.rs` — GSS RFC 4121 message protection round-trip.
//!
//! Once a Kerberos handshake finishes, both peers share a session key. From that
//! moment, application data is protected with GSS per-message tokens:
//! `GetMIC` / `VerifyMIC` for integrity, `Wrap` / `Unwrap` for confidentiality.
//! kerbcore exposes all four directly on top of any [`KerberosKey`] — you don't
//! need a running KDC for this, just a shared key.
//!
//! Run with:
//! ```text
//! cargo run --example gss_wrap_unwrap
//! ```
//!
//! Compare with `libgssapi-sys`, where `gss_wrap` / `gss_unwrap` / `gss_get_mic`
//! all require a live `gss_ctx_id_t` allocated by the underlying MIT/Heimdal
//! library. Here the "context" is just the session key + a sequence number
//! you own.

use kerbcore::gss::{get_mic, unwrap, verify_mic, wrap};
use kerbcore::keys::{Enctype, KerberosKey};

fn main() {
    // A shared AES-256 session key — in a real deployment this is the
    // `enc.key` returned by the AS-REP decrypt in `examples/get_tgt.rs`, or
    // handed over on the acceptor side after `AP-REQ` decrypt.
    let session_key_bytes = vec![0x42u8; 32];
    let key = KerberosKey::new(Enctype::Aes256CtsHmacSha1_96, session_key_bytes)
        .expect("32-byte AES-256 key");

    // Peer-controlled 64-bit sequence numbers (RFC 4121 §4.2). Initiator and
    // acceptor each keep their own; kerbcore does NOT track them for you (this
    // is intentional — the crate is pure, no per-context state).
    let seq_initiator: u64 = 1;

    let payload = b"hello, kerberos";

    // `is_acceptor=false` → this side is the initiator (client). Set to true
    // on the acceptor (server); kerbcore picks the RFC 4121 sender-role usage
    // key from that flag. `acceptor_subkey=false` → no post-handshake subkey.
    let is_acceptor = false;
    let acceptor_subkey = false;

    // ── GetMIC / VerifyMIC — integrity only, payload travels in the clear.
    let mic = get_mic(&key, seq_initiator, payload, is_acceptor, acceptor_subkey);
    println!("[+] GetMIC produced {} bytes", mic.len());
    verify_mic(&key, &mic, payload).expect("MIC verifies");
    println!("[+] VerifyMIC OK (integrity + sender authentication)");

    // Bit-flip a payload byte → verify must reject.
    let mut tampered = payload.to_vec();
    tampered[0] ^= 0x01;
    assert!(
        verify_mic(&key, &mic, &tampered).is_err(),
        "MIC MUST reject a tampered payload"
    );
    println!("[+] tampered payload correctly rejected");

    // ── Wrap / Unwrap — sealed (integrity + confidentiality).
    let sealed = wrap(&key, seq_initiator, payload, is_acceptor, acceptor_subkey);
    println!(
        "[+] Wrap produced {} bytes ({} payload)",
        sealed.len(),
        payload.len()
    );
    let recovered = unwrap(&key, &sealed).expect("unwrap");
    assert_eq!(recovered, payload);
    println!("[+] Unwrap recovered {} bytes matching input", recovered.len());

    // Sequence-number & key checks are enforced by the caller: kerbcore doesn't
    // maintain per-peer state. On the wire, decrypted sequence numbers must be
    // strictly greater than the previous ones from the same sender (replay
    // rejection).
    println!("\n(a real acceptor would now check the sequence number against its watermark)");
}
