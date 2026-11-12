# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## [0.1.0-rc.1] - 2026-11-12

Signing keys without a certificate (certval-cms's `SigningKey`), e.g. to sign a certificate request:
`CngKey`, which `import_pkcs8_key` makes from a PKCS #8 RSA or EC key, its public key exported by
CNG.

ML-DSA-44, -65 and -87, pure with an empty context string, where this Windows' CNG has ML-DSA
(recent Windows 11 builds), which `CngCrypto::ml_dsa_available()` reports:
certificate and message signature verification through the message interface, and with `cms`,
signing by `CngSigningKey` and `CngKey`, an ML-DSA PKCS #8 key importing into CNG as other keys
do. Without CNG's ML-DSA the provider declines it, as before. The `pqc` feature now also enables
certval-cms's software ML-DSA signing, for the tests.

ML-KEM-512, -768 and -1024, where this Windows' CNG has ML-KEM. `CngCrypto` implements
certval-cms's `EncryptKem` entirely in CNG: `BCryptEncapsulate`, CNG's HKDF and CNG's AES key wrap.
`CngRecipientKey` decrypts, decapsulating with `NCryptDecapsulate`, and certval-cms's
`cek_from_kem_secret` derives the key-encryption key and unwraps. Both entry points are looked up
at run time, since older Windows' bcrypt.dll and ncrypt.dll lack them;
`CngCrypto::ml_kem_available()` reports whether CNG has them. `import_pkcs8` takes an ML-KEM key in
any of RFC 9935's three forms into the Software Key Storage Provider as CNG's seed or
decapsulation-key blob, since the provider's PKCS #8 import does not take one.

## [0.1.0-rc.1]

Initial release. Calculates SHA-1/256/384/512 digests and verifies RSA PKCS #1 v1.5, RSASSA-PSS and
ECDSA (P-256/384/521) certificate signatures through Windows CNG, through all three of certval's
hashing and verification interfaces. `CngCrypto::fips_mode_enabled` reports the system's FIPS policy.

A `cms` feature implements certval-cms's AES-CBC and AES-GCM content encryption and decryption and
RSA key transport by BCrypt, with `CngRecipientKey` and `CngSigningKey` decrypting and signing with
NCrypt keys, `CertStoreIdentities` finding them in the current user's certificate store and
listing them with `certificates()`, and `import_pkcs8` importing a key into the Microsoft Software
Key Storage Provider. Key agreement uses CNG's ECDH and certval-cms's X9.63 KDF and key wrap, CNG
having no X9.63 KDF.

MSRV 1.89.
