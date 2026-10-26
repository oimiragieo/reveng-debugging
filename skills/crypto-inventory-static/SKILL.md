---
name: crypto-inventory-static
description: Use when inventorying cryptographic libraries and APIs in an authorized binary. DO NOT USE to crack, forge, or weaken cryptography.
---

# crypto-inventory-static

Original identify-only pass over a `reveng-debug` inventory. Name libraries, APIs, and algorithm tokens that are actually in the JSON. Do not paste courseware. Do not implement cryptanalysis, key recovery, signature or certificate forgery, hash cracking, protocol downgrades, or any change that makes cryptography weaker.

Vocabulary is for **labels**. A missing algorithm name is **unknown**, never “not used” and never “easy to break.”

## Hard rules

| Do | Never |
|---|---|
| Work on the session copy (`workspace_path`) | Mutate the original target |
| Read `findings.imports`, `imported_libraries`, `exported_symbols`, `dynamic_symbols`, `exports`, `strings`, JS `package` / `files` | Invent imports, versions, or cipher names |
| Mark every row **seen**, **inferred**, or **unknown** | Treat a generic API as a named algorithm |
| Treat “not in the 200-string / 200-name cap” as **unknown** | Treat a cap miss as absent |
| Slice extra needles on text (JS/Electron extract) | Dump whole minified files |
| Stop at identification | Crack, forge, unwrap, or “test” crypto by attacking it |
| Leave strength, CVE, and runtime use **unknown** unless a version or call is seen | Reproduce Heartbleed, POODLE, padding oracles, rainbow tables, or RSA/AES math |

Static inventory is not observed execution. An import or string is not a call.

## First move

```powershell
reveng-debug doctor
reveng-debug identify .\target
reveng-debug inventory .\target
```

Use `workspace_path` from the inventory JSON. If `doctor` lists dumpbin, optional `/IMPORTS` on the **copy** is still identify-only. Missing dumpbin stays **unknown** — do not fake it. Do not run `ghidra` unless the operator opts in; even then, only collect crypto-ish names, never patches.

## Where the inventory keeps crypto

Match tokens against these fields only. Caps are real: PE import names 200 per DLL, exports 200, ASCII strings 200, ELF/Mach-O libraries/symbols/strings similarly bounded.

| Kind | Fields |
|---|---|
| PE | `findings.imports[].dll`, `findings.imports[].names`, `findings.exports`, `findings.strings` |
| ELF / Mach-O | `findings.imported_libraries`, `findings.exported_symbols`, `findings.dynamic_symbols`, `findings.strings` |
| JS / Electron | `findings.package` (deps), `findings.files`; then `reveng-debug slice PATH NEEDLE` on the extract |

If `target_kind` is `unknown` or `status` is not `present`, the whole crypto inventory is **unknown**.

Needles that missed the string cap are still **unknown** unless a later `slice` on a **text** file hits. Do not write a custom unbounded strings dumper. `slice` on a native binary is the wrong tool (it reads text); stay on inventory JSON for PE/ELF/Mach-O.

## Label families (identify only)

Use these buckets to tag a **seen** token. Do not infer a security goal (confidentiality, integrity, authentication, non-repudiation) unless the token itself names that goal.

| Family | What a hit means | Typical tokens (examples, not exhaustive) |
|---|---|---|
| Windows CryptoAPI / CNG | A Microsoft crypto DLL or `Crypt*` / `BCrypt*` / `NCrypt*` export name is listed | `advapi32` `CryptEncrypt` `CryptCreateHash` `CryptGenKey`; `bcrypt.dll` `BCryptEncrypt` `BCryptHash`; `ncrypt.dll`; `crypt32` `CertOpenStore` `CryptProtectData`; `rsaenh` `dssenh` `cryptsp` `dpapi` |
| Schannel / SSPI | Transport crypto API name listed | `secur32` `schannel` `EncryptMessage` `InitializeSecurityContext` |
| OpenSSL-family library | Needed lib or `EVP_` / `SSL_` / `TLS_` symbol or banner | `libcrypto` `libssl` `libeay32` `ssleay32` `EVP_EncryptInit` `SSL_read` `OpenSSL` |
| Other shipped libraries | A named third-party crypto lib is imported or string-matched | `mbedtls` `wolfssl` `libsodium` `nss3` `softokn3` `boringssl` `Keyczar` |
| Named primitive | The algorithm or mode **string itself** appears | `AES` `AES-256-GCM` `DES` `3DES` `RC4` `Blowfish` `Twofish` `IDEA` `RSA` `DSA` `ECC` `ECDH` `ECDSA` `DH` `DHE` `ECDHE` `MD5` `SHA-1` `SHA-256` `SHA-3` `HMAC` `RIPEMD` `ChaCha20` `Poly1305` `PBKDF2` `scrypt` `bcrypt` `Argon2` `NTLM` `NTLMv2` |
| PKI / certificates | Cert or key-container vocabulary | `X509` `PEM` `DER` `PKCS` `PFX` `P12` `CRL` `OCSP` `certificate` `CN=` |
| Transport suite names | TLS/SSL/IPsec/WPA cipher-suite or protocol labels | `TLS` `SSL` `TLS_ECDHE_` `IPsec` `WPA2` `CCMP` `TKIP` `WEP` |
| Email / disk products | Product names, not proof they ran | `PGP` `GPG` `OpenPGP` `S/MIME` `BitLocker` `LUKS` `FileVault` `VeraCrypt` |
| JS / Node surfaces | Module or WebCrypto API in package.json or slice | `crypto` `node:crypto` `crypto.subtle` `createHash` `createHmac` `createCipheriv` `pbkdf2` `crypto-js` `node-forge` `tweetnacl` `sodium-native` |

**Inferred (narrow):** `CryptEncrypt` **seen** → family Windows CryptoAPI **inferred**; the block cipher behind it stays **unknown**. `BCryptOpenAlgorithmProvider` **seen** → CNG **inferred**; algorithm id **unknown** unless a sibling string names `AES` / `SHA256` / etc.

**Unknown on purpose:** generic `encrypt` / `decrypt` / `hash` / `sign` without a library or primitive name; any algorithm not literally present; whether an import is reached at runtime; whether a library version is vulnerable; key escrow / recovery-agent / “government access” strings as political or product copy — tag `key-management-vocab` if seen, do not explain how keys would be seized.

Steganography tokens (`steg`, `LSB`) are name hits only. Do not extract hidden payloads.

## Workflow

1. Confirm authorization and stay on the session copy.
2. Run identify + inventory. Record `engine`, `coverage`, `limitations`.
3. Scan the tables above. Copy the matching token **verbatim** into the report.
4. For JS/Electron, slice a short needle list (`createCipheriv`, `crypto.subtle`, `node-forge`, `AES-GCM`, `pbkdf2`). Stop after a handful of needles; do not boil the bundle.
5. Optional: if the operator opted into Ghidra, collect function names that contain `Crypt`, `AES`, `RSA`, `SHA`, `EVP_`, `BCrypt`, `NCrypt`. Still identify-only.
6. Emit the table. Every unnamed algorithm cell is `unknown`.

## Output contract

```markdown
## Crypto inventory (static)

- target_kind: …
- engine / coverage: …
- workspace_path: …

| token | field | family | role | confidence | limitation |
|---|---|---|---|---|---|
| BCryptEncrypt | imports bcrypt.dll | CNG | cipher API | seen | import ≠ call; algorithm unknown |
| AES-256-GCM | strings | named primitive | cipher+mode | seen | string only |
| RSA | — | — | — | unknown | not in capped strings/imports |

Notes:
- Runtime use: unknown
- Key material: do not extract, print, or reconstruct
- Strength / breakage: out of scope
```

Zero hits → say **unknown**, not “this binary has no cryptography.”

## Hard stops (CEH Module 18 attack material stays out)

Do not list, implement, or walk through ciphertext-only / chosen-text attacks, DSA/RSA key generation, AES round internals, SSL 3.0 downgrade, heartbeat memory disclosure, online “hash decrypt” sites, or cryptanalysis toolkits. Naming `OpenSSL` plus a version **string that is actually present** is allowed; turning that version into an exploit is not. Do not ship weak configs, disabled verification, or “just use MD5/ECB” advice.

## Siblings

- `reveng-debug` — CLI router (`doctor`, `identify`, `inventory`, `slice`)
- `authorized-scope-ethics` — permission before analysis
- `secplus-observe-vs-assume` — claims need evidence
- `pe-iat-capability-map` — imports as capability buckets, not calls
