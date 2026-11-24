//! Key management for cms's own recipient builders, through CNG's BCrypt: [`CngKeyEncryptor`] for
//! `KeyTransRecipientInfoBuilder`, and [`CngKeyAgreement`] and [`CngKeyWrap`] for
//! `KeyAgreeRecipientInfoBuilder`. These implement cms's traits directly, so a caller using cms's
//! builders without a certval-cms `CmsEnvironment` can have Windows perform the operation.
//!
//! The random number generator cms's builders pass is not used: BCrypt draws the RSA padding and
//! the ephemeral key from the system's generator.

use certval_cms::{
    Error as CmsError, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
};
use cms::builder::{self, DhSinglePassStdDhKdf, KeyAgreement, KeyAgreementOutput};
use cms::enveloped_data::OriginatorPublicKey;
use const_oid::{DynAssociatedOid, ObjectIdentifier};
use der::asn1::BitString;
use kdf::Kdf;
use log::debug;
use rsa::traits::RandomizedEncryptor;
use spki::{AlgorithmIdentifierOwned, DynAssociatedAlgorithmIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use crate::cms::{cng_aes_key_wrap, ecdh, rsa_encrypt};

/// A certval-cms error as a cms builder error, which holds only a message.
fn builder_error(e: CmsError) -> builder::Error {
    match e {
        CmsError::Asn1(e) => builder::Error::Asn1(e),
        e => builder::Error::Builder(e.to_string()),
    }
}

/// RSA key transport to one recipient's key, by BCrypt, for cms's `KeyTransRecipientInfoBuilder`:
/// RSAES-PKCS1-v1_5 or RSAES-OAEP, as the [`KeyTransportAlgorithm`] given says.
#[derive(Clone, Debug)]
pub struct CngKeyEncryptor {
    spki: SubjectPublicKeyInfoOwned,
    alg: KeyTransportAlgorithm,
}

impl CngKeyEncryptor {
    /// Key transport with `alg` to the RSA key in `spki`.
    pub fn new(spki: SubjectPublicKeyInfoOwned, alg: KeyTransportAlgorithm) -> Self {
        Self { spki, alg }
    }

    /// Key transport with `alg` to the RSA key in `cert`.
    pub fn from_certificate(cert: &Certificate, alg: KeyTransportAlgorithm) -> Self {
        Self::new(
            cert.tbs_certificate().subject_public_key_info().clone(),
            alg,
        )
    }
}

impl RandomizedEncryptor for CngKeyEncryptor {
    fn encrypt_with_rng<R: rsa::rand_core::TryCryptoRng + ?Sized>(
        &self,
        _rng: &mut R,
        msg: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        rsa_encrypt(self.alg, &self.spki, msg).map_err(|e| {
            debug!("CNG key transport with {:?} failed: {e}", self.alg);
            rsa::Error::Internal
        })
    }
}

impl DynAssociatedAlgorithmIdentifier for CngKeyEncryptor {
    fn algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        // Only encoding the OAEP parameters can fail.
        self.alg.algorithm_identifier().map_err(|e| match e {
            CmsError::Asn1(e) => spki::Error::Asn1(e),
            _ => spki::Error::Asn1(der::ErrorKind::Failed.into()),
        })
    }
}

/// Ephemeral-static ECDH with one recipient's key on P-256, P-384 or P-521, by BCrypt, for cms's
/// `KeyAgreeRecipientInfoBuilder`. CNG has no X9.63 KDF, so the key-encryption key is derived
/// from the shared secret with cms's [`DhSinglePassStdDhKdf`], in process. The
/// [`KeyAgreementAlgorithm`] given identifies the scheme and the KDF's hash.
#[derive(Clone, Debug)]
pub struct CngKeyAgreement {
    spki: SubjectPublicKeyInfoOwned,
    alg: KeyAgreementAlgorithm,
}

impl CngKeyAgreement {
    /// Key agreement with `alg` with the EC key in `spki`.
    pub fn new(spki: SubjectPublicKeyInfoOwned, alg: KeyAgreementAlgorithm) -> Self {
        Self { spki, alg }
    }

    /// Key agreement with `alg` with the EC key in `cert`.
    pub fn from_certificate(cert: &Certificate, alg: KeyAgreementAlgorithm) -> Self {
        Self::new(
            cert.tbs_certificate().subject_public_key_info().clone(),
            alg,
        )
    }
}

impl DynAssociatedOid for CngKeyAgreement {
    fn oid(&self) -> ObjectIdentifier {
        self.alg.oid()
    }
}

impl<R: ?Sized> KeyAgreement<R> for CngKeyAgreement {
    fn agree(
        &self,
        shared_info: &[u8],
        kek_size: usize,
        _rng: &mut R,
    ) -> builder::Result<KeyAgreementOutput> {
        let (ephemeral_public_key, z) = ecdh(&self.spki).map_err(builder_error)?;
        let mut key_encryption_key = Zeroizing::new(vec![0u8; kek_size]);
        // A cofactor scheme derives as its standard counterpart does, since the supported curves
        // have cofactor 1.
        match self.alg {
            KeyAgreementAlgorithm::EcdhSha256 | KeyAgreementAlgorithm::EcdhCofactorSha256 => {
                DhSinglePassStdDhKdf::<sha2::Sha256>::new().derive_key(
                    &z,
                    shared_info,
                    &mut key_encryption_key,
                )
            }
            KeyAgreementAlgorithm::EcdhSha384 | KeyAgreementAlgorithm::EcdhCofactorSha384 => {
                DhSinglePassStdDhKdf::<sha2::Sha384>::new().derive_key(
                    &z,
                    shared_info,
                    &mut key_encryption_key,
                )
            }
            KeyAgreementAlgorithm::EcdhSha512 | KeyAgreementAlgorithm::EcdhCofactorSha512 => {
                DhSinglePassStdDhKdf::<sha2::Sha512>::new().derive_key(
                    &z,
                    shared_info,
                    &mut key_encryption_key,
                )
            }
            _ => return Err(builder_error(CmsError::Unrecognized)),
        }
        .map_err(|_| {
            builder::Error::Builder(String::from("could not derive the key-encryption key"))
        })?;
        Ok(KeyAgreementOutput {
            // RFC 5753, section 3.1.1: the ephemeral key is on the recipient's curve, which the
            // algorithm identifier names.
            originator_key: OriginatorPublicKey {
                algorithm: self.spki.algorithm.clone(),
                public_key: BitString::from_bytes(&ephemeral_public_key)?,
            },
            key_encryption_key,
        })
    }
}

/// AES key wrap (RFC 3394) by BCrypt, for cms's `KeyAgreeRecipientInfoBuilder`.
#[derive(Clone, Copy, Debug)]
pub struct CngKeyWrap {
    wrap: KeyWrapAlgorithm,
}

impl CngKeyWrap {
    /// Key wrap with `wrap`.
    pub fn new(wrap: KeyWrapAlgorithm) -> Self {
        Self { wrap }
    }
}

impl builder::KeyWrapAlgorithm for CngKeyWrap {
    fn algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
        self.wrap.algorithm_identifier()
    }

    fn kek_size(&self) -> usize {
        self.wrap.kek_len()
    }

    fn try_wrap(&self, kek: &[u8], key: &[u8]) -> builder::Result<Vec<u8>> {
        // BCrypt takes the key size from the key-encryption key, so one of another size would
        // wrap under another algorithm than the one identified.
        if kek.len() != self.wrap.kek_len() {
            return Err(builder::Error::Builder(format!(
                "a {}-octet key-encryption key for {:?}",
                kek.len(),
                self.wrap
            )));
        }
        cng_aes_key_wrap(kek, key).map_err(builder_error)
    }
}
