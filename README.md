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

| Hash | |
|---|---|
| SHA-1, SHA-256, SHA-384, SHA-512 | `BCryptHash` |

CNG verifies digests only, so the message interface hashes with `BCryptHash` and then verifies as the
digest interface does; both the hash and the verification happen inside CNG. Anything else is
declined, and software answers it. The deliberate declines:

- **SHA-224 throughout.** CNG has no SHA-224 provider.
- **RSASSA-PSS with a mask other than MGF1 over the message hash**, or relying on RFC 4055's SHA-1
  defaults for the hash or the mask. CNG always masks with MGF1 over the padding's hash. An omitted
  salt length takes the RFC 4055 default of 20, as certval's software verifier reads it.
- **An elliptic curve key on any curve but P-256, P-384 or P-521.**
- **A PKCS #1 v1.5 signature under a key identified as `id-RSASSA-PSS`.** RFC 4055 restricts such a
  key to PSS, and certval's software verifier rejects the combination, so it gives that verdict.
- **ML-DSA.**

Three encoding differences between X.509 and CNG are bridged internally:

- an RSA key travels as a DER `RSAPublicKey`, while `BCRYPT_RSAPUBLIC_BLOB` is a header followed by
  the big-endian exponent and modulus, without DER's leading sign byte;
- an elliptic curve key travels as an uncompressed point with the curve named separately, while
  `BCRYPT_ECCPUBLIC_BLOB` names the curve in its header's magic number;
- an ECDSA signature travels as `SEQUENCE { r, s }`, while CNG uses fixed-width `r‖s`.

## Testing

`cargo test` runs on any platform; off Windows it runs only the portable unit tests (the algorithm
table and the key blob encoding). On Windows it adds the signature tests: ECDSA signatures made by
RustCrypto with fixed keys, and RSA and RSASSA-PSS signatures from keys CNG generates in memory,
each checked against certval's software verifier, and each also checked with a changed message and a
changed signature, which must be **rejections**, not refusals.

The collection tests verify certificates through the provider and compare against software. No
certificates are carried in this repository; the collections are named by environment variables, and
a test whose collection is not set reports that and passes.

| Variable | Meaning |
|---|---|
| `CERTVAL_CNG_RSA_CERTS` | directory of RSA-signed certificates |
| `CERTVAL_CNG_ECDSA_CERTS` | directory of ECDSA-signed certificates |
| `CERTVAL_CNG_PSS_CERTS` | directory of RSASSA-PSS-signed certificates |
| `CERTVAL_CNG_MLDSA_CERTS` | directory of ML-DSA-signed certificates, which the provider must decline |

```powershell
$EX = "..\rust-pki\certval\tests\examples"
$env:CERTVAL_CNG_RSA_CERTS = "$EX\PKITS_data_2048\certs"
$env:CERTVAL_CNG_ECDSA_CERTS = "$EX\PKITS_data_p256\certs"
$env:CERTVAL_CNG_PSS_CERTS = "$EX\rsapss"
$env:CERTVAL_CNG_MLDSA_CERTS = "$EX\pkits_ml_dsa_44\certs"

cargo test --features pqc -- --nocapture
```

The assertion in each case is **agreement**, not success, and `--nocapture` prints how many
verifications CNG answered itself, and whether FIPS-approved mode is on.

## Status

**Not yet run on Windows.** The portable unit tests pass on macOS, and the Windows code paths
(including the tests) type-check against `x86_64-pc-windows-msvc`, but nothing that calls bcrypt.dll
has executed. The first Windows CI run is the first real test. Not yet published to crates.io.

certval is consumed from crates.io. A commented `[patch.crates-io]` line in `Cargo.toml` redirects
the dependency to a local checkout for developing both crates together.

## License

Apache-2.0 OR MIT.
