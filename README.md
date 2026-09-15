# kerbcore

Pure-Rust Kerberos building blocks — **no FFI, no dependency on a host krb5**,
`#![forbid(unsafe_code)]`.

`kerbcore` implements the modern Kerberos encryption-type matrix, a from-scratch
DER / RFC 4120 message codec, and a plain **AS / TGS client** — the protocol core a
defender, DFIR engineer, or interoperability author needs without linking a system
krb5. The crate is pure: bytes in, bytes out. Network I/O stays with the caller.

## Install

```toml
[dependencies]
kerbcore = "0.2"
```

Requires Rust 1.88+.

## Status

Pre-1.0 — 0.2.x is the current line (typed-key enctype dispatch, AP-REP mutual auth,
GSS RFC 4121, SPNEGO, FAST, KKDCP, kpasswd, cross-realm referrals). A 0.3.0
API-freeze candidate is planned before 1.0. The AS/TGS crypto, codec, and client are
complete and **live-validated end-to-end against Windows Server 2019, 2022, and
2025 KDCs**: each obtains a real TGT and service ticket, handling the three different
salt schemes the servers return (the salt is parsed from the KDC's `ETYPE-INFO2`,
never guessed).

## When to reach for kerbcore (honest table)

Kerbcore covers a specific niche in the Rust Kerberos ecosystem. It is not the right
choice for everyone; the alternatives are legitimately better for other use cases.

| You want... | Reach for | Why |
|---|---|---|
| Kerberos client that just works everywhere your OS runs | [`libgssapi-sys`] | Battle-tested MIT/Heimdal FFI; largest user base; the boring safe default |
| Windows-native SSPI parity from Rust | [`sspi-rs`] | Real SSPI reimplementation; substantial user base; handles Windows quirks |
| Just KRB message codec, no client | [`picky-krb`] | Smallest surface; long history; used by sspi-rs internally |
| Static binary, no libclang at build, no libkrb5 at runtime | **kerbcore** | Zero FFI, zero system deps |
| Cross-compile to musl / minimal Alpine / embedded | **kerbcore** | Pure-Rust, `#![forbid(unsafe_code)]`, tiny external tree (8 deps) |
| Wire-level control (roast, forge, inspect PA-data, walk KDC-REP by hand) | **kerbcore** | Types are yours; the codec is total (no panic on hostile input) |
| Environments where the MIT/Heimdal C audit surface is unacceptable | **kerbcore** | Pure-Rust, no `unsafe` |
| A production-mature Kerberos crate with a large ecosystem | **not kerbcore yet** | Pre-1.0, small user base — pick libgssapi or sspi-rs |

The pure-Rust-Kerberos-with-no-FFI category is a small niche. Kerbcore's goal is to be
the honest top of that niche, not to displace libgssapi.

[`libgssapi-sys`]: https://crates.io/crates/libgssapi-sys
[`sspi-rs`]: https://crates.io/crates/sspi
[`picky-krb`]: https://crates.io/crates/picky-krb

## Examples

Three runnable examples under `examples/`:

- **`get_tgt`** — obtain a real TGT from a live KDC (env-configured), from
  scratch in ~90 LOC. AS-REQ → KRB-ERROR (salt) → PA-ENC-TIMESTAMP → AS-REP →
  decrypt session key.
- **`asrep_roast`** — no-preauth account → hashcat `-m 18200` line. The
  offline-cracking primitive behind AS-REP roasting, in ~90 LOC and no runtime.
- **`gss_wrap_unwrap`** — RFC 4121 message protection round-trip (offline,
  no KDC needed). Shows the post-handshake `Wrap` / `Unwrap` / `GetMIC` /
  `VerifyMIC` primitives you'd otherwise reach for through libgssapi.

```sh
cargo run --example gss_wrap_unwrap
```

## Encryption-type coverage

The modern Active Directory encryption-type matrix — not a single profile:

| etype | profile | status |
|------:|---------|--------|
| **17** | aes128-cts-hmac-sha1-96 (RFC 3962) | ✅ |
| **18** | aes256-cts-hmac-sha1-96 (RFC 3962) | ✅ |
| **19** | aes128-cts-hmac-sha256-128 (RFC 8009) | ✅ — RFC 8009 §7 KAT |
| **20** | aes256-cts-hmac-sha384-192 (RFC 8009) | ✅ — RFC 8009 §7 KAT |
| **23** | rc4-hmac (RFC 4757) | ✅ — differential-tested |
| 1 / 3 | des-cbc-* | out of scope — no weak/legacy crypto shipped |

RFC 8009 (etypes 19/20) is implemented from scratch — few Rust libraries do. On
Windows these are added in Server 2025 / Windows 11 24H2 (disabled by default); MIT
krb5, Heimdal, and Samba negotiate them today.

## ASN.1 / RFC 4120 message codec

A hand-rolled DER (X.690) codec — **no external ASN.1 crate** — with a **total,
no-panic decoder**: every malformed byte returns a `DerError`, never a crash.

- `der` — canonical DER encoder + total decoder (KAT'd integer/length encodings).
- `types` — `PrincipalName`, `KerberosTime`, `EncryptionKey`, `EncryptedData`,
  `PaData`, `Checksum`, `Realm`.
- `messages` — `Ticket` `[APP 1]`, `KDC-REQ` (AS-REQ / TGS-REQ), `KDC-REP`
  (AS-REP / TGS-REP), `KRB-ERROR` `[APP 30]`.

Every message round-trips, application/context tags are verified, and `Ticket`,
`AS-REP`, and `KRB-ERROR` encode **byte-identically to `picky-krb`** (kerbcore DER →
strict decode → re-encode → same bytes). `picky-krb` is used only as a dev-dependency
differential oracle.

## Crypto primitives

The RFC 3961 / 3962 primitive set, key-length-generic across the AES-SHA1 profiles:

- `nfold` — RFC 3961 §5.2 n-fold
- `aes_cts_encrypt` / `aes_cts_decrypt` — RFC 3962 §5 AES CBC-CTS (CS3), AES-128 and AES-256
- `dr` / `dk` — RFC 3961 §5.1 DR/DK derivation
- `hmac_sha1_96` — RFC 2104 HMAC-SHA1 truncated to 96 bits
- `derive_kc` / `derive_ke` / `derive_ki` — RFC 3961 §5.3 subkey derivation
- `encrypt_message` / `decrypt_message` — the generic encrypt-then-integrity primitive
- `string_to_key` — RFC 3962 §4 (PBKDF2) and RFC 8009 §4 string-to-key

The RFC 8009 (SHA-2) and RC4-HMAC families live in the `rfc8009` and `rc4` modules.

## Conformance

Known-answer tested, not just round-tripped:

- `nfold("012345", 64) == 0xbe072631276b1955` (RFC 3961 §5.2)
- PBKDF2-HMAC-SHA1 vs RFC 6070; HMAC-SHA1/MD5 vs RFC 2202; NT-hash + RC4 vs canonical vectors
- AES-SHA1 string-to-key vs RFC 3962; DR/DK determinism + AES `random_to_key = identity`
- AES-128/256 CTS round-trips across the CTS edge lengths (16 / 17 / 31 / 32 / 47 / 48 / 64 B)
- **RFC 8009 §7 vectors** — Kc/Ke/Ki derivation + all four sample encryptions, both etypes
- **RC4-HMAC** — byte-exact differential vs an independent reference, across key-usages × lengths
- encrypt-then-integrity round-trip + tamper / wrong-usage / truncation rejection
- the DER/message decoders fuzz-clean (coverage-guided, billions of iterations, zero panics)

> Bringing up the RFC 8009 §7 known-answer vectors surfaced and fixed a latent CBC-CS3
> edge case (the last-two-block swap for exact-multiple inputs) that round-trip tests
> alone did not catch.

`cargo test` → 65 passing (crypto + DER/message codec + client), plus one env-gated
live-KDC integration test that no-ops without credentials (so `cargo test` and CI stay
offline; no credentials or host identifiers live in the source).

## Dependencies

`aes`, `hmac`, `sha1`, `sha2`, `md4`, `md-5` (RustCrypto) and `getrandom`; RC4 is
hand-rolled. No FFI, no system krb5, `#![forbid(unsafe_code)]`. The differential
oracles (`picky-krb`, `picky-asn1-der`, `ms-pac-forge`) are **dev-dependencies only**.

## Scope

`kerbcore` is the protocol core — encryption-type crypto, the wire codec, and a plain
AS/TGS client. It performs no network I/O (the caller owns the socket) and ships no
ticket-forging or attack tooling; those belong in higher-level tools built on top.

## License

MIT.
