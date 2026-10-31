//! Translation from the algorithm identifiers certval presents to the hash and padding CNG needs.
//!
//! CNG verifies signatures over digests only (`BCryptVerifySignature` takes a hash), so the
//! message interface hashes with `BCryptHash` first and then verifies exactly as the digest
//! interface does. Both interfaces therefore share one table.

use certval::{
    PKIXALG_ECDSA_WITH_SHA256, PKIXALG_ECDSA_WITH_SHA384, PKIXALG_ECDSA_WITH_SHA512, PKIXALG_MGF1,
    PKIXALG_RSASSA_PSS, PKIXALG_SHA1, PKIXALG_SHA256, PKIXALG_SHA256_WITH_RSA_ENCRYPTION,
    PKIXALG_SHA384, PKIXALG_SHA384_WITH_RSA_ENCRYPTION, PKIXALG_SHA512,
    PKIXALG_SHA512_WITH_RSA_ENCRYPTION,
};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;

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
    fn unknown_algorithm_is_declined() {
        let ml_dsa_44 = const_oid::db::fips204::ID_ML_DSA_44;
        assert!(signature_scheme(&plain(ml_dsa_44)).is_none());
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
