# kerbcore

Pure-Rust Kerberos building blocks — **no FFI, no dependency on a host krb5**.

> **Status (1.5.1).** Local, unpublished (`publish = false`). Two layers are done:
> the full modern **etype crypto matrix** (+ string-to-key) and a from-scratch
> **DER + RFC 4120 message codec**, the latter verified byte-identical to
> `picky-krb`. An AS/TGS **client** lands next (1.6), at which point `kerbcore`
> replaces `picky-krb` inside ADhammer's Kerberos stack. Ship-target: `0.1.0-beta.1`.

## ASN.1 / RFC 4120 message codec

A hand-rolled DER (X.690) codec — **no external ASN.1 crate** — with a **total,
no-panic decoder** (every malformed KDC/attacker byte returns `DerError`, never
crashes). Types and messages:

- `der` — canonical DER encoder + total decoder (KAT'd integer/length encodings).
- `types` — `PrincipalName`, `KerberosTime`, `EncryptionKey`, `EncryptedData`,
  `PaData`, `Checksum`, `Realm`.
- `messages` — `Ticket` `[APP 1]`, `KDC-REQ` (AS-REQ / TGS-REQ), `KDC-REP`
  (AS-REP / TGS-REP), `KRB-ERROR` `[APP 30]`.

**Wire conformance:** every message round-trips, its application/context tags are
hand-verified, and — the real proof — `Ticket`, `AS-REP`, and `KRB-ERROR` encode
**byte-identically to `picky-krb`** (kerbcore DER → picky-krb strict decode →
re-encode → same bytes). `picky-krb` is a dev-dependency only.

## What it does today (crypto)

The RFC 3961 / RFC 3962 primitive set, key-length-generic across the AES-SHA1 profiles:

- `nfold` — RFC 3961 §5.2 n-fold
- `aes_cts_encrypt` / `aes_cts_decrypt` — RFC 3962 §5 AES CBC-CTS (CS3), AES-128 **and** AES-256
- `dr` / `dk` — RFC 3961 §5.1 DR/DK derivation (output = base key length)
- `hmac_sha1_96` — RFC 2104 HMAC-SHA1 truncated to 96 bits
- `derive_kc` / `derive_ke` / `derive_ki` — RFC 3961 §5.3 subkey derivation
- `encrypt_message` / `decrypt_message` — the generic encrypt-then-MAC primitive
  that KILE `EncryptedData` and GSS-API wrap-tokens compose out of

## Encryption-type coverage

A complete AD Kerberos crypto crate owns the whole etype matrix — not one profile:

| etype | profile | status |
|------:|---------|--------|
| **17** | aes128-cts-hmac-sha1-96 | ✅ implemented |
| **18** | aes256-cts-hmac-sha1-96 | ✅ implemented |
| **19** | aes128-cts-hmac-sha256-128 (RFC 8009) | ✅ implemented — RFC 8009 §7 KAT |
| **20** | aes256-cts-hmac-sha384-192 (RFC 8009) | ✅ implemented — RFC 8009 §7 KAT |
| **23** | rc4-hmac (RFC 4757) | ✅ implemented — differential vs reference |
| 1 / 3 | des-cbc-* | ✂ out of scope — dead in AD, no weak crypto shipped |

The full modern AD etype matrix — including RFC 8009 (etypes 19/20), which almost no
Rust library implements from scratch and which Windows Server 2022+ negotiates.

## Conformance

Known-answer tested, not just round-tripped:

- `nfold("012345", 64) == 0xbe072631276b1955` (RFC 3961 §5.2 worked example)
- HMAC-SHA1 vs RFC 2202; HMAC-MD5 vs RFC 2202; NT-hash + RC4 vs canonical vectors
- DR/DK determinism + AES `random_to_key = identity`
- AES-128/256 CTS round-trips across the edge lengths (16 / 17 / 31 / 32 / 47 / 48 / 64 B)
- **RFC 8009 §7 vectors** — Kc/Ke/Ki derivation + all four sample encryptions, both etypes
- **RC4-HMAC** — byte-exact differential vs the live-DC-validated `ms-pac-forge` reference
  (dev-dependency only), across 8 key-usages × 7 lengths
- encrypt-then-MAC / checksum-verify round-trip + tamper / wrong-usage / truncation rejection
- unsupported AES key length (e.g. AES-192) panics loudly rather than mis-deriving

> Note: implementing the RFC 8009 §7 KAT surfaced and fixed a latent CBC-CS3 bug in the
> lifted AES-CTS (the last-two-block swap was skipped for exact-multiple inputs) — a case
> the never-closed sealer's round-trip tests could not catch.

`cargo test` → 55 passing (crypto + DER/message codec).

## Dependencies

`aes`, `hmac`, `sha1`, `sha2`, `md4`, `md-5` (RustCrypto); RC4 is hand-rolled. No FFI, no
system krb5, `#![forbid(unsafe_code)]`. (`ms-pac-forge` is a **dev**-dependency only, used
as the RC4-HMAC differential oracle — never a runtime dep.)

## Scope

The offensive compositions (golden/silver/diamond tickets, S4U abuse, unPAC,
PKINIT-relay) intentionally do **not** live here — they stay in the ADhammer CLI.
`kerbcore` is the dual-use core: the wire crypto and (soon) the ASN.1 codec + a
plain AS/TGS client that a defender, DFIR engineer, or interop author would want.

## Provenance

The crypto here is lifted verbatim from ADhammer's KAT-verified sealer
(`crates/kerberos/src/rpc_seal.rs` at git tag `v1.4.7`, cut from `main` in 1.4.8).
Rationale: `docs/PLAN_KRB_CRATE.md` in the ADhammer repo.

## License

MIT.
