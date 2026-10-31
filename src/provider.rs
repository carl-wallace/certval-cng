//! The provider that implements certval's hashing and verification interfaces against CNG.

use crate::algorithm::{signature_scheme, Hash, Padding, Scheme};
use crate::blob::{ecc_public_blob, ecdsa_signature_raw, rsa_public_blob};
use crate::cng::{self, Verdict};
use certval::{
    CalculateHash, PathValidationStatus, PkiEnvironment, VerifySignatureDigest,
    VerifySignatureMessage,
};
use der::asn1::BitString;
use log::debug;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// A [`certval`] crypto provider backed by Windows CNG.
///
/// The value holds no state: each verification imports the issuer's key, verifies, and destroys
/// the key. Importing a public key is an in-process call with no session behind it, so there is
/// no round trip for a cache to save. The same value can be registered in every role:
///
/// ```no_run
/// # use certval::PkiEnvironment;
/// # use certval_cng::CngCrypto;
/// # let mut pe = PkiEnvironment::default();
/// pe.add_calculate_hash_callback(CngCrypto::new());
/// pe.add_verify_signature_message_callback(CngCrypto::new());
/// pe.add_verify_signature_digest_callback(CngCrypto::new());
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct CngCrypto {
    _private: (),
}

impl CngCrypto {
    /// Returns a provider.
    pub fn new() -> Self {
        CngCrypto { _private: () }
    }

    /// Reports whether CNG is operating in FIPS-approved mode, as set by the "System
    /// cryptography: Use FIPS compliant algorithms" policy. `None` means the query itself failed.
    ///
    /// The provider behaves the same either way; this is for a caller whose deployment requires
    /// the mode and wants to confirm it before relying on the provider.
    pub fn fips_mode_enabled() -> Option<bool> {
        cng::fips_mode_enabled()
    }

    /// Verifies `signature` over `digest`, reporting the outcome in the terms certval's interfaces
    /// are defined in.
    fn verify_digest(
        &self,
        spki: &SubjectPublicKeyInfoOwned,
        scheme: Scheme,
        digest: &[u8],
        signature: &[u8],
    ) -> certval::Result<()> {
        if digest.len() != scheme.hash.len() {
            return Err(certval::Error::Unrecognized);
        }

        let (key, signature) = match scheme.padding {
            Padding::Pkcs1 | Padding::Pss { .. } => {
                let Some(blob) = rsa_public_blob(spki, scheme.padding) else {
                    return Err(certval::Error::Unrecognized);
                };
                (cng::import_rsa(&blob), signature.to_vec())
            }
            Padding::Ecdsa => {
                let Some((curve, blob)) = ecc_public_blob(spki) else {
                    return Err(certval::Error::Unrecognized);
                };
                let Some(raw) = ecdsa_signature_raw(signature, curve.field_len()) else {
                    return Err(certval::Error::Unrecognized);
                };
                (cng::import_ecdsa(curve, &blob), raw)
            }
        };
        let Some(key) = key else {
            return Err(certval::Error::Unrecognized);
        };

        match cng::verify(&key, scheme.padding, scheme.hash, digest, &signature) {
            // CNG verified the signature.
            Verdict::Valid => Ok(()),

            // CNG reached a verdict and it was negative. The environment treats this as final and
            // consults no other implementation.
            Verdict::Invalid => Err(certval::Error::PathValidation(
                PathValidationStatus::SignatureVerificationFailure,
            )),

            // Any other status is CNG declining the request rather than judging the signature,
            // so another implementation answers.
            Verdict::Declined(status) => {
                debug!("CNG could not verify a signature: {status:#010x}");
                Err(certval::Error::Unrecognized)
            }
        }
    }
}

impl CalculateHash for CngCrypto {
    fn calculate_hash(
        &self,
        _pe: &PkiEnvironment,
        hash_alg: &AlgorithmIdentifierOwned,
        buffer_to_hash: &[u8],
    ) -> certval::Result<Vec<u8>> {
        let Some(hash) = Hash::from_oid(&hash_alg.oid) else {
            return Err(certval::Error::Unrecognized);
        };
        cng::hash(hash, buffer_to_hash).ok_or(certval::Error::Unrecognized)
    }
}

impl VerifySignatureMessage for CngCrypto {
    fn verify_signature_message(
        &self,
        _pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &BitString,
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        let Some(scheme) = signature_scheme(signature_alg) else {
            return Err(certval::Error::Unrecognized);
        };
        let signature = signature.as_bytes().ok_or(certval::Error::ParseError)?;
        // CNG verifies digests only, so the message is hashed here, also with CNG.
        let Some(digest) = cng::hash(scheme.hash, message_to_verify) else {
            return Err(certval::Error::Unrecognized);
        };
        self.verify_digest(spki, scheme, &digest, signature)
    }
}

impl VerifySignatureDigest for CngCrypto {
    fn verify_signature_digest(
        &self,
        _pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &BitString,
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        let Some(scheme) = signature_scheme(signature_alg) else {
            return Err(certval::Error::Unrecognized);
        };
        let signature = signature.as_bytes().ok_or(certval::Error::ParseError)?;
        self.verify_digest(spki, scheme, hash_to_verify, signature)
    }
}
