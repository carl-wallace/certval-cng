# certval-cng

A Windows CNG crypto provider for [certval](https://github.com/carl-wallace/rust-pki). It supplies
implementations of the hashing and signature verification callbacks that a `PkiEnvironment`
dispatches through, so certification path validation on Windows can be performed with Cryptography
API: Next Generation rather than the in-process software implementation.

The provider is defined only on Windows, so a workspace that builds for several platforms can depend
on the crate unconditionally and register the provider only where it exists.

```rust
use certval::PkiEnvironment;
use certval_cng::CngCrypto;

let mut pe = PkiEnvironment::default();

// Registering before populate_5280_pki_environment puts CNG ahead of the software
// implementations, so it is consulted first and software answers only what it declined.
pe.add_calculate_hash_callback(CngCrypto::new());
pe.add_verify_signature_message_callback(CngCrypto::new());
pe.add_verify_signature_digest_callback(CngCrypto::new());

pe.populate_5280_pki_environment();
```

The provider holds no state. It uses CNG's algorithm pseudo-handles (Windows 10 and later), so there
is no provider to open or close, and each verification imports the issuer's key with
`BCryptImportKeyPair`, verifies with `BCryptVerifySignature`, and destroys the key.

## Registration is additive

`PkiEnvironment` consults registered implementations in order and stops at the first verdict. The
provider reports a rejection only when CNG judged the signature invalid (`STATUS_INVALID_SIGNATURE`);
anything else it declines, and a declined verification falls through to the next implementation.
That lets CNG answer for the algorithms it offers while software covers the rest.

It also means registering the provider does not by itself guarantee that every verification reaches
CNG. A caller who requires that must make the registration exclusive:

```rust
pe.populate_5280_pki_environment();
pe.clear_verify_signature_message_callbacks();
pe.clear_verify_signature_digest_callbacks();
pe.add_verify_signature_message_callback(CngCrypto::new());
pe.add_verify_signature_digest_callback(CngCrypto::new());
```

## FIPS mode

Whether CNG runs in its FIPS-approved mode is set system-wide by the "System cryptography: Use FIPS
compliant algorithms" policy; a library cannot switch it on. `CngCrypto::fips_mode_enabled()` reports
the setting (through `BCryptGetFipsAlgorithmMode`) for a caller whose deployment depends on it.
Whether CNG's validation covers a given Windows build is a question for NIST's CMVP list, not for
this crate.

## Algorithm coverage

| Signature algorithm | Padding | Notes |
|---|---|---|
| RSA PKCS #1 v1.5, SHA-256/384/512 | `BCRYPT_PAD_PKCS1` | |
| RSASSA-PSS, SHA-256/384/512 | `BCRYPT_PAD_PSS` | salt length taken from the parameters |
| ECDSA on P-256/384/521, SHA-256/384/512 | none | signature reshaped to fixed-width `r‖s` |
| ML-DSA-44/65/87, pure, empty context | `BCRYPT_PAD_PQDSA` | message interface only; where this Windows' CNG has ML-DSA |

| Hash | |
|---|---|
| SHA-1, SHA-256, SHA-384, SHA-512 | `BCryptHash` |

CNG verifies RSA and ECDSA over digests only, so the message interface hashes with `BCryptHash` and
then verifies as the digest interface does; both the hash and the verification happen inside CNG.
ML-DSA signs the message itself (RFC 9881), which CNG takes as it is, so it has the message
interface only. Recent Windows 11 builds have ML-DSA in CNG; `CngCrypto::ml_dsa_available()`
reports whether this Windows does, and without it ML-DSA is declined. The SDK's ML-DSA definitions, which windows-sys does not yet bind, are restated in the
crate. Anything else is declined, and software answers it. The deliberate declines:

- **SHA-224 throughout.** CNG has no SHA-224 provider.
- **RSASSA-PSS with a mask other than MGF1 over the message hash**, or relying on RFC 4055's SHA-1
  defaults for the hash or the mask. CNG always masks with MGF1 over the padding's hash. An omitted
  salt length takes the RFC 4055 default of 20, as certval's software verifier reads it.
- **An elliptic curve key on any curve but P-256, P-384 or P-521.**
- **A PKCS #1 v1.5 signature under a key identified as `id-RSASSA-PSS`.** RFC 4055 restricts such a
  key to PSS, and certval's software verifier rejects the combination, so it gives that verdict.
- **ML-DSA with parameters in its algorithm identifier**, which RFC 9881 requires to be absent, or
  under a key of another parameter set.

Four encoding differences between X.509 and CNG are bridged internally:

- an RSA key travels as a DER `RSAPublicKey`, while `BCRYPT_RSAPUBLIC_BLOB` is a header followed by
  the big-endian exponent and modulus, without DER's leading sign byte;
- an elliptic curve key travels as an uncompressed point with the curve named separately, while
  `BCRYPT_ECCPUBLIC_BLOB` names the curve in its header's magic number;
- an ECDSA signature travels as `SEQUENCE { r, s }`, while CNG uses fixed-width `r‖s`;
- an ML-DSA key travels as the bare public key with the parameter set named by its OID, while
  `BCRYPT_PQDSA_PUBLIC_BLOB` is a `BCRYPT_PQDSA_KEY_BLOB` header, the parameter set's name in
  UTF-16, then the key.

## CMS

With the `cms` feature, `CngCrypto` also implements
[certval-cms](https://github.com/carl-wallace/certval-cms)'s content encryption and decryption and
key transport, and NCrypt keys serve as credentials: `CngRecipientKey` decrypts, `CngSigningKey`
signs, and `CertStoreIdentities` finds both in the current user's personal certificate store, where
CAPI and virtual smart card keys are: a decryption key by the recipient identifier a message
contains, and signing keys by signer identifier, email address or subject, each key opened silently
so that no dialog interrupts a lookup, and `certificates()` lists them without opening any key.
`import_pkcs8` makes both for a key imported into the Microsoft Software Key Storage Provider; an
ML-KEM key, whose PKCS #8 form the provider does not import, goes in as CNG's own seed or
decapsulation-key blob, in whichever of RFC 9935's forms the PKCS #8 holds it.

A key with no certificate yet, e.g. one signing its own certificate request or a self-signed
certificate, is certval-cms's `SigningKey`: `CngKey`, which `import_pkcs8_key` makes from a PKCS #8
RSA, EC or ML-DSA key imported into the same provider. It signs as `CngSigningKey` does, and its
public key is the one CNG exports for it, so an EC key need not carry its public key.

| Operation | Coverage |
|---|---|
| Content encryption and decryption | AES-128/192/256 in CBC and GCM, by BCrypt |
| Key transport | RSAES-PKCS1-v1_5, RSAES-OAEP with SHA-1/256/384/512, by `BCryptEncrypt` and `NCryptDecrypt` |
| Key agreement | ECDH on P-256, P-384 and P-521, by `BCryptSecretAgreement` to encrypt and `NCryptSecretAgreement` to decrypt; the X9.63 KDF and AES key wrap by certval-cms |
| Signing | RSA PKCS #1 v1.5 and RSASSA-PSS, and ECDSA, by `NCryptSignHash`, over a digest the environment computes; pure ML-DSA-44/65/87 with an empty context, by `NCryptSignHash` over the message, where this Windows' CNG has ML-DSA |
| KEM | ML-KEM-512/768/1024, where this Windows' CNG has ML-KEM: encryption all by CNG, `BCryptEncapsulate`, CNG's HKDF and AES key wrap; decryption by `NCryptDecapsulate`, then HKDF and AES key unwrap by certval-cms |

CNG has no X9.63 KDF, so for key agreement CNG returns the shared secret (`BCRYPT_KDF_RAW_SECRET`),
and certval-cms's `wrap_with_ecdh_secret` wraps the content-encryption key or `cek_from_ecdh_secret`
recovers it; the private key stays in its store.

To encrypt to an ML-KEM recipient, as AWS-LC and OpenSSL do, CNG performs every step:
`BCryptEncapsulate` to the recipient's key (`BCRYPT_MLKEM_PUBLIC_BLOB`), CNG's HKDF
(`BCRYPT_HKDF_ALG_HANDLE`, the salt absent) over certval-cms's `CMSORIforKEMOtherInfo` (RFC 9629),
and CNG's AES key wrap, the content-encryption key exported under the key-encryption key as
`BCRYPT_AES_WRAP_KEY_BLOB` (which CNG performs only under a key in AES's default CBC mode). To
decrypt, `NCryptDecapsulate` returns the shared secret, from which certval-cms's
`cek_from_kem_secret` derives the key-encryption key and unwraps the content-encryption key, as a
PKCS #11 token's decapsulation does with certval-pkcs11; the private key stays in its store, and
the shared secret leaves CNG. bcrypt.dll and ncrypt.dll export `BCryptEncapsulate` and
`NCryptDecapsulate` only where CNG has ML-KEM, so they are looked up at run time rather than
linked, and `CngCrypto::ml_kem_available()` reports whether both were found.

## Testing

`cargo test` runs on any platform; off Windows it runs only the portable unit tests (the algorithm
table and the key blob encoding). On Windows it adds the signature tests: ECDSA signatures made by
RustCrypto with fixed keys, and RSA and RSASSA-PSS signatures from keys CNG generates in memory,
each checked against certval's software verifier, and each also checked with a changed message and a
changed signature, which must be **rejections**, not refusals. With `cms` and `pqc`, and where this
Windows' CNG has ML-DSA, ML-DSA-44, -65 and -87 keys made in software are imported into CNG, sign
SignedData and their own certificate requests, which software verifies, and CNG alone verifies
SignedData software signs. Where CNG has ML-KEM, ML-KEM-512, -768 and -1024 keys made in software
are imported into CNG, with each KDF and key wrap, with and without user keying material, in
AES-CBC and AES-GCM: CNG alone decrypts what software encrypts to them, and software and CNG each
decrypt what CNG alone encrypts.

The collection tests verify certificates through the provider and compare against software. No
certificates are carried in this repository; the collections are named by environment variables, and
a test whose collection is not set reports that and passes.

| Variable | Meaning |
|---|---|
| `CERTVAL_CNG_RSA_CERTS` | directory of RSA-signed certificates |
| `CERTVAL_CNG_ECDSA_CERTS` | directory of ECDSA-signed certificates |
| `CERTVAL_CNG_PSS_CERTS` | directory of RSASSA-PSS-signed certificates |
| `CERTVAL_CNG_MLDSA_CERTS` | directory of ML-DSA-signed certificates, which the provider must answer where this Windows' CNG has ML-DSA, and decline where it does not |

```powershell
$EX = "..\rust-pki\certval\tests\examples"
$env:CERTVAL_CNG_RSA_CERTS = "$EX\PKITS_data_2048\certs"
$env:CERTVAL_CNG_ECDSA_CERTS = "$EX\PKITS_data_p256\certs"
$env:CERTVAL_CNG_PSS_CERTS = "$EX\rsapss"
$env:CERTVAL_CNG_MLDSA_CERTS = "$EX\pkits_ml_dsa_44\certs"

cargo test --features pqc,cms -- --nocapture
```

The assertion in each case is **agreement**, not success, and `--nocapture` prints how many
verifications CNG answered itself, and whether FIPS-approved mode is on.

## Status

Run in CI on GitHub's hosted Windows runner against rust-pki's PKITS collections: CNG answered all
389 RSA and 388 ECDSA verifications that software accepted, and both RSASSA-PSS ones, with no
disagreements in either interface, and declined every ML-DSA one. Changed messages and changed
signatures were rejections, not refusals. The runner was not in FIPS-approved mode.

ML-DSA has been run on Windows 11 build 26300, whose CNG has it, against rust-pki's ML-DSA-44, -65
and -87 PKITS collections: CNG answered all 390 verifications software accepted in each, with no
disagreements. Whether GitHub's hosted runner has ML-DSA in CNG decides whether CI exercises it or
the fall-through to software.

The `cms` feature's tests run in Windows CI.

certval-cms is not on crates.io yet, so `Cargo.toml`'s `[patch.crates-io]` takes it from a
neighboring checkout (`../certval-cms`), and CI checks it out there. Both go when it publishes, and
this crate cannot publish before it does.

certval is consumed from crates.io. A commented `[patch.crates-io]` line in `Cargo.toml` redirects
the dependency to a local checkout for developing both crates together.

## License

Apache-2.0 OR MIT.
