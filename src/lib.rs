//! Windows CNG crypto provider for [`certval`].
//!
//! [`certval`] performs hashing and signature verification through callbacks registered on a
//! [`PkiEnvironment`](certval::PkiEnvironment). This crate supplies implementations of those
//! callbacks that route the work to Cryptography API: Next Generation (`BCryptHash`,
//! `BCryptImportKeyPair` and `BCryptVerifySignature`), so certification path validation on Windows
//! can be performed with the operating system's cryptographic module rather than the in-process
//! software implementation.
//!
//! The provider is defined only on Windows, so a workspace that builds for several platforms can
//! depend on the crate unconditionally and register the provider only where it exists.
//!
//! ```no_run
//! # #[cfg(windows)]
//! # {
//! use certval::PkiEnvironment;
//! use certval_cng::CngCrypto;
//!
//! let mut pe = PkiEnvironment::default();
//!
//! // Registering before populate_5280_pki_environment puts CNG ahead of the software
//! // implementations, so it is consulted first and software answers only what it declined.
//! pe.add_calculate_hash_callback(CngCrypto::new());
//! pe.add_verify_signature_message_callback(CngCrypto::new());
//! pe.add_verify_signature_digest_callback(CngCrypto::new());
//!
//! pe.populate_5280_pki_environment();
//! # }
//! ```
//!
//! # Registration is additive
//!
//! [`PkiEnvironment`](certval::PkiEnvironment) consults registered implementations in order and
//! stops at the first verdict. The provider reports a rejection only when CNG judged the signature
//! invalid; anything else it declines, and a declined verification falls through to the next
//! implementation. A caller who requires that every verification reach CNG must make the
//! registration exclusive by clearing the software callbacks first:
//!
//! ```no_run
//! # #[cfg(windows)]
//! # {
//! # use certval::PkiEnvironment;
//! # use certval_cng::CngCrypto;
//! # let mut pe = PkiEnvironment::default();
//! pe.populate_5280_pki_environment();
//! pe.clear_verify_signature_message_callbacks();
//! pe.clear_verify_signature_digest_callbacks();
//! pe.add_verify_signature_message_callback(CngCrypto::new());
//! pe.add_verify_signature_digest_callback(CngCrypto::new());
//! # }
//! ```
//!
//! # FIPS mode
//!
//! Whether CNG is operating in its FIPS-approved mode is a property of the system, set by the
//! "System cryptography: Use FIPS compliant algorithms" policy, not something a library can switch
//! on. [`CngCrypto::fips_mode_enabled`] reports the setting so a caller that depends on it can
//! check it.

#![deny(unsafe_code)]
#![warn(missing_docs)]

// The algorithm table and the key blob encoding are plain data transformations, so they compile
// and are unit tested on every platform. Only the calls into bcrypt.dll are Windows-specific.
#[cfg_attr(not(windows), allow(dead_code))]
mod algorithm;
#[cfg_attr(not(windows), allow(dead_code))]
mod blob;
#[cfg(windows)]
#[allow(unsafe_code)]
mod cng;
#[cfg(windows)]
mod provider;

#[cfg(windows)]
pub use provider::CngCrypto;
