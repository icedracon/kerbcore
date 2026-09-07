# kerbcore

Pure-Rust Kerberos building blocks — **no FFI, no dependency on a host krb5**.

> **Spike status (1.5.1).** Local, unpublished (`publish = false`). This first cut
> ships only the RFC 3961 / RFC 3962 crypto for the `aes256-cts-hmac-sha1-96`
> profile (etype 18). The ASN.1 message codec and an AS/TGS client land next (1.6),
> at which point `kerbcore` replaces `picky-krb` inside ADhammer's Kerberos stack.
> Ship-target version when frozen: `0.1.0-beta.1`.

## What it does today

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
| **19** | aes128-cts-hmac-sha256-128 (RFC 8009) | ⏳ next — SP800-108 KDF + SHA-256 |
| **20** | aes256-cts-hmac-sha384-192 (RFC 8009) | ⏳ next — SP800-108 KDF + SHA-384 |
| **23** | rc4-hmac (RFC 4757) | ⏳ next — RC4 + HMAC-MD5 + MD4(NT-hash) |
| 1 / 3 | des-cbc-* | ✂ out of scope — dead in AD, no weak crypto shipped |

etypes 19/20 (AES-SHA2) are the point of the crate: almost no Rust library implements
RFC 8009 from scratch, and Windows Server 2022+ negotiates them.

## Conformance

Known-answer tested, not just round-tripped:

- `nfold("012345", 64) == 0xbe072631276b1955` (RFC 3961 §5.2 worked example)
- HMAC-SHA1 against RFC 2202 test case 1
- DR/DK determinism + AES `random_to_key = identity`
- AES-128 and AES-256 CTS round-trips across the edge lengths (16 / 17 / 31 / 32 / 47 / 48 / 64 B)
- encrypt-then-MAC round-trip + tamper / wrong-usage / truncation rejection (both key sizes)
- unsupported key length (e.g. AES-192) panics loudly rather than mis-deriving

Per-etype known-answer vectors come from RFC 3962 App B (17/18), RFC 8009 App A
(19/20), and RFC 4757 / MS-KILE (23) as each profile lands.

`cargo test` → 22 passing.

## Dependencies

`aes`, `hmac`, `sha1` (RustCrypto). No FFI, no system krb5, `#![forbid(unsafe_code)]`.

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
