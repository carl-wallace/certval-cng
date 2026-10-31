# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## [0.1.0-rc.1] - 2026-10-31

Initial release. Calculates SHA-1/256/384/512 digests and verifies RSA PKCS #1 v1.5, RSASSA-PSS and
ECDSA (P-256/384/521) certificate signatures through Windows CNG, through all three of certval's
hashing and verification interfaces. `CngCrypto::fips_mode_enabled` reports the system's FIPS policy.
MSRV 1.88.
