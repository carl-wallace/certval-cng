//! Translation from the algorithm identifiers certval presents to the hash and padding CNG needs.
//!
//! CNG verifies RSA and ECDSA signatures over digests only (`BCryptVerifySignature` takes a hash),
//! so the message interface hashes with `BCryptHash` first and then verifies exactly as the digest
//! interface does. Both interfaces therefore share one table. ML-DSA is pure, signing the message
//! itself, so it has a table of its own and only the message interface.

use certval::{
    PKIXALG_ECDSA_WITH_SHA256, PKIXALG_ECDSA_WITH_SHA384, PKIXALG_ECDSA_WITH_SHA512, PKIXALG_MGF1,
    PKIXALG_RSASSA_PSS, PKIXALG_SHA1, PKIXALG_SHA256, PKIXALG_SHA256_WITH_RSA_ENCRYPTION,
    PKIXALG_SHA384, PKIXALG_SHA384_WITH_RSA_ENCRYPTION, PKIXALG_SHA512,
    PKIXALG_SHA512_WITH_RSA_ENCRYPTION,
};
use const_oid::db::fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768};
use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;

/// An ML-DSA parameter set (FIPS 204), signing purely: over the message, with an empty context
/// string, as RFC 9881 has certificates and CRLs and RFC 9882 has CMS.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum MlDsa {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsa {
    /// The parameter set an ML-DSA OID names, for a key or a signature algorithm.
    pub(crate) fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match *oid {
            ID_ML_DSA_44 => Some(MlDsa::MlDsa44),
            ID_ML_DSA_65 => Some(MlDsa::MlDsa65),
            ID_ML_DSA_87 => Some(MlDsa::MlDsa87),
            _ => None,
        }
    }

    /// The parameter set of an ML-DSA signature algorithm identifier, whose parameters RFC 9881
    /// requires to be absent. An identifier with parameters is declined, and software judges it.
    pub(crate) fn from_algorithm(alg: &AlgorithmIdentifierOwned) -> Option<Self> {
        if alg.parameters.is_some() {
            return None;
        }
        Self::from_oid(&alg.oid)
    }

    pub(crate) fn oid(self) -> ObjectIdentifier {
        match self {
            MlDsa::MlDsa44 => ID_ML_DSA_44,
            MlDsa::MlDsa65 => ID_ML_DSA_65,
            MlDsa::MlDsa87 => ID_ML_DSA_87,
        }
    }

    /// The name CNG gives the parameter set (`BCRYPT_MLDSA_PARAMETER_SET_*`).
    pub(crate) fn parameter_set(self) -> &'static str {
        match self {
            MlDsa::MlDsa44 => "44",
            MlDsa::MlDsa65 => "65",
            MlDsa::MlDsa87 => "87",
        }
    }

    /// The size in octets of a public key (FIPS 204, table 2).
    pub(crate) fn public_key_len(self) -> usize {
        match self {
            MlDsa::MlDsa44 => 1312,
            MlDsa::MlDsa65 => 1952,
            MlDsa::MlDsa87 => 2592,
        }
    }

    /// The size in octets of a signature (FIPS 204, table 2).
    pub(crate) fn signature_len(self) -> usize {
        match self {
            MlDsa::MlDsa44 => 2420,
            MlDsa::MlDsa65 => 3309,
            MlDsa::MlDsa87 => 4627,
        }
    }

    pub(crate) const ALL: [MlDsa; 3] = [MlDsa::MlDsa44, MlDsa::MlDsa65, MlDsa::MlDsa87];
}

/// An ML-KEM parameter set (FIPS 203), for a KEMRecipientInfo (RFC 9629, RFC 9936).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) enum MlKem {
    MlKem512,
    MlKem768,
    MlKem1024,
}

#[cfg_attr(not(feature = "cms"), allow(dead_code))]
impl MlKem {
    /// The parameter set an ML-KEM key's OID names.
    pub(crate) fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match *oid {
            ID_ALG_ML_KEM_512 => Some(MlKem::MlKem512),
            ID_ALG_ML_KEM_768 => Some(MlKem::MlKem768),
            ID_ALG_ML_KEM_1024 => Some(MlKem::MlKem1024),
            _ => None,
        }
    }

    /// The name CNG gives the parameter set (`BCRYPT_MLKEM_PARAMETER_SET_*`).
    pub(crate) fn parameter_set(self) -> &'static str {
        match self {
            MlKem::MlKem512 => "512",
            MlKem::MlKem768 => "768",
            MlKem::MlKem1024 => "1024",
        }
    }

    /// The size in octets of a public (encapsulation) key (FIPS 203, table 3).
    pub(crate) fn public_key_len(self) -> usize {
        match self {
            MlKem::MlKem512 => 800,
            MlKem::MlKem768 => 1184,
            MlKem::MlKem1024 => 1568,
        }
    }

    /// The size in octets of a ciphertext (FIPS 203, table 3).
    pub(crate) fn ciphertext_len(self) -> usize {
        match self {
            MlKem::MlKem512 => 768,
            MlKem::MlKem768 => 1088,
            MlKem::MlKem1024 => 1568,
        }
    }

    /// The size in octets of a decapsulation key (FIPS 203, table 3).
    pub(crate) fn private_key_len(self) -> usize {
        match self {
            MlKem::MlKem512 => 1632,
            MlKem::MlKem768 => 2400,
            MlKem::MlKem1024 => 3168,
        }
    }

    /// The size in octets of the shared secret, the same for every parameter set (FIPS 203).
    pub(crate) const SHARED_SECRET_LEN: usize = 32;

    /// The size in octets of the seed `d ‖ z` a key pair is generated from, the same for every
    /// parameter set (FIPS 203).
    pub(crate) const SEED_LEN: usize = 64;
}

/// A hash CNG provides. SHA-224 is absent because CNG has no SHA-224 provider, so SHA-224
/// signatures and digests are left to software.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub(crate) fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match *oid {
            PKIXALG_SHA1 => Some(Hash::Sha1),
            PKIXALG_SHA256 => Some(Hash::Sha256),
            PKIXALG_SHA384 => Some(Hash::Sha384),
            PKIXALG_SHA512 => Some(Hash::Sha512),
            _ => None,
        }
    }

    pub(crate) fn len(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }
}

/// How the signature is laid out over the digest.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Padding {
    /// RSA PKCS #1 v1.5. Needs a key identified as `rsaEncryption`.
    Pkcs1,
    /// RSASSA-PSS with MGF1 over the signature hash and the given salt length. Accepts a key
    /// identified as either `rsaEncryption` or `id-RSASSA-PSS`.
    Pss { salt_len: u32 },
    /// ECDSA.
    Ecdsa,
}

/// The hash and padding a signature algorithm identifier calls for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Scheme {
    pub(crate) hash: Hash,
    pub(crate) padding: Padding,
}

/// Returns the scheme for a signature algorithm identifier, or `None` when CNG cannot verify it.
pub(crate) fn signature_scheme(alg: &AlgorithmIdentifierOwned) -> Option<Scheme> {
    let scheme = |hash, padding| Some(Scheme { hash, padding });
    match alg.oid {
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION => scheme(Hash::Sha256, Padding::Pkcs1),
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION => scheme(Hash::Sha384, Padding::Pkcs1),
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION => scheme(Hash::Sha512, Padding::Pkcs1),

        PKIXALG_ECDSA_WITH_SHA256 => scheme(Hash::Sha256, Padding::Ecdsa),
        PKIXALG_ECDSA_WITH_SHA384 => scheme(Hash::Sha384, Padding::Ecdsa),
        PKIXALG_ECDSA_WITH_SHA512 => scheme(Hash::Sha512, Padding::Ecdsa),

        PKIXALG_RSASSA_PSS => pss_scheme(alg),

        _ => None,
    }
}

/// Reads RSASSA-PSS parameters into a scheme CNG can honor.
///
/// `BCRYPT_PSS_PADDING_INFO` names the hash and the salt length, and CNG always masks with MGF1
/// over that same hash. A parameter block naming a different mask is declined, as is a SHA-1 hash:
/// RFC 4055 defaults the hash and the mask to SHA-1, so a block omitting either is declined too.
/// An omitted salt length takes the RFC 4055 default of 20, which is how certval's software
/// verifier reads it.
fn pss_scheme(alg: &AlgorithmIdentifierOwned) -> Option<Scheme> {
    let encoded = alg.parameters.as_ref()?.to_der().ok()?;
    let pss = RsaPssParams::from_der(&encoded).ok()?;

    let hash = Hash::from_oid(&pss.hash?.oid)?;
    if hash == Hash::Sha1 {
        return None;
    }

    let mask_gen = pss.mask_gen?;
    if mask_gen.oid != PKIXALG_MGF1 {
        return None;
    }
    let mgf_hash = mask_gen
        .parameters
        .as_ref()?
        .decode_as::<AlgorithmIdentifierOwned>()
        .ok()?;
    if Hash::from_oid(&mgf_hash.oid)? != hash {
        return None;
    }

    if pss.trailer_field.unwrap_or(1) != 1 {
        return None;
    }

    Some(Scheme {
        hash,
        padding: Padding::Pss {
            salt_len: pss.salt_len.unwrap_or(20),
        },
    })
}

/// The parameter block carried by an RSASSA-PSS algorithm identifier.
#[derive(der::Sequence)]
pub(crate) struct RsaPssParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) salt_len: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) trailer_field: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use certval::{PKIXALG_ECDSA_WITH_SHA224, PKIXALG_SHA224, PKIXALG_SHA224_WITH_RSA_ENCRYPTION};
    use der::asn1::Any;

    fn hash_alg(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: Some(Any::null()),
        }
    }

    fn pss(
        hash: Option<ObjectIdentifier>,
        mgf_hash: Option<ObjectIdentifier>,
        salt_len: Option<u32>,
    ) -> AlgorithmIdentifierOwned {
        let params = RsaPssParams {
            hash: hash.map(hash_alg),
            mask_gen: mgf_hash.map(|h| AlgorithmIdentifierOwned {
                oid: PKIXALG_MGF1,
                parameters: Some(Any::encode_from(&hash_alg(h)).unwrap()),
            }),
            salt_len,
            trailer_field: None,
        };
        AlgorithmIdentifierOwned {
            oid: PKIXALG_RSASSA_PSS,
            parameters: Some(Any::encode_from(&params).unwrap()),
        }
    }

    fn plain(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    #[test]
    fn pkcs1_and_ecdsa_map_to_their_hash() {
        let s = signature_scheme(&plain(PKIXALG_SHA384_WITH_RSA_ENCRYPTION)).unwrap();
        assert_eq!(s.hash, Hash::Sha384);
        assert_eq!(s.padding, Padding::Pkcs1);
        let s = signature_scheme(&plain(PKIXALG_ECDSA_WITH_SHA512)).unwrap();
        assert_eq!(s.hash, Hash::Sha512);
        assert_eq!(s.padding, Padding::Ecdsa);
    }

    #[test]
    fn sha224_signatures_are_declined() {
        assert!(signature_scheme(&plain(PKIXALG_SHA224_WITH_RSA_ENCRYPTION)).is_none());
        assert!(signature_scheme(&plain(PKIXALG_ECDSA_WITH_SHA224)).is_none());
        assert!(
            signature_scheme(&pss(Some(PKIXALG_SHA224), Some(PKIXALG_SHA224), Some(28))).is_none()
        );
        assert!(Hash::from_oid(&PKIXALG_SHA224).is_none());
    }

    #[test]
    fn ml_dsa_is_not_a_digest_scheme() {
        // ML-DSA signs the message, so it has no place in the digest table.
        for set in MlDsa::ALL {
            assert!(signature_scheme(&plain(set.oid())).is_none());
        }
    }

    #[test]
    fn ml_dsa_parameter_sets() {
        for (oid, set, name) in [
            (ID_ML_DSA_44, MlDsa::MlDsa44, "44"),
            (ID_ML_DSA_65, MlDsa::MlDsa65, "65"),
            (ID_ML_DSA_87, MlDsa::MlDsa87, "87"),
        ] {
            assert_eq!(MlDsa::from_algorithm(&plain(oid)), Some(set));
            assert_eq!(set.oid(), oid);
            assert_eq!(set.parameter_set(), name);
        }
        assert!(MlDsa::from_oid(&PKIXALG_SHA256_WITH_RSA_ENCRYPTION).is_none());
    }

    #[test]
    fn ml_kem_parameter_sets() {
        for (oid, set, name, public_key_len, private_key_len, ciphertext_len) in [
            (ID_ALG_ML_KEM_512, MlKem::MlKem512, "512", 800, 1632, 768),
            (ID_ALG_ML_KEM_768, MlKem::MlKem768, "768", 1184, 2400, 1088),
            (
                ID_ALG_ML_KEM_1024,
                MlKem::MlKem1024,
                "1024",
                1568,
                3168,
                1568,
            ),
        ] {
            assert_eq!(MlKem::from_oid(&oid), Some(set));
            assert_eq!(set.parameter_set(), name);
            assert_eq!(set.public_key_len(), public_key_len);
            assert_eq!(set.private_key_len(), private_key_len);
            assert_eq!(set.ciphertext_len(), ciphertext_len);
        }
        assert!(MlKem::from_oid(&ID_ML_DSA_65).is_none());
    }

    #[test]
    fn ml_dsa_with_parameters_is_declined() {
        // RFC 9881: the parameters are absent, not NULL.
        assert!(MlDsa::from_algorithm(&hash_alg(ID_ML_DSA_65)).is_none());
    }

    #[test]
    fn pss_salt_length_is_carried_through() {
        let s =
            signature_scheme(&pss(Some(PKIXALG_SHA256), Some(PKIXALG_SHA256), Some(20))).unwrap();
        assert_eq!(s.padding, Padding::Pss { salt_len: 20 });
        let s =
            signature_scheme(&pss(Some(PKIXALG_SHA512), Some(PKIXALG_SHA512), Some(64))).unwrap();
        assert_eq!(s.padding, Padding::Pss { salt_len: 64 });
    }

    #[test]
    fn pss_omitted_salt_takes_the_rfc_4055_default() {
        let s = signature_scheme(&pss(Some(PKIXALG_SHA256), Some(PKIXALG_SHA256), None)).unwrap();
        assert_eq!(s.padding, Padding::Pss { salt_len: 20 });
    }

    #[test]
    fn pss_mgf_hash_other_than_the_message_hash_is_declined() {
        assert!(
            signature_scheme(&pss(Some(PKIXALG_SHA256), Some(PKIXALG_SHA384), Some(32))).is_none()
        );
    }

    #[test]
    fn pss_with_defaulted_hash_or_mask_is_declined() {
        assert!(signature_scheme(&pss(None, Some(PKIXALG_SHA256), Some(32))).is_none());
        assert!(signature_scheme(&pss(Some(PKIXALG_SHA256), None, Some(32))).is_none());
        assert!(signature_scheme(&pss(Some(PKIXALG_SHA1), Some(PKIXALG_SHA1), Some(20))).is_none());
        assert!(signature_scheme(&plain(PKIXALG_RSASSA_PSS)).is_none());
    }
}
