//! Turning a `SubjectPublicKeyInfo` into the key blobs `BCryptImportKeyPair` takes, and reshaping
//! ECDSA signatures into the form `BCryptVerifySignature` expects.
//!
//! Three encoding differences between X.509 and CNG are bridged here:
//!
//! - an RSA key travels as a DER `RSAPublicKey`, while `BCRYPT_RSAPUBLIC_BLOB` is a
//!   `BCRYPT_RSAKEY_BLOB` header followed by the big-endian exponent and modulus;
//! - an elliptic curve key travels as an uncompressed point with the curve named separately, while
//!   `BCRYPT_ECCPUBLIC_BLOB` is a `BCRYPT_ECCKEY_BLOB` header, whose magic number names the curve,
//!   followed by the two coordinates;
//! - an ECDSA signature travels as `SEQUENCE { r INTEGER, s INTEGER }`, while CNG uses the
//!   fixed-width concatenation of `r` and `s`.
//!
//! The headers are written field by field rather than by casting the `windows-sys` structs, which
//! keeps this module free of `unsafe` and buildable, and testable, on any platform.

use crate::algorithm::Padding;
use certval::{
    PKIXALG_EC_PUBLIC_KEY, PKIXALG_RSASSA_PSS, PKIXALG_RSA_ENCRYPTION, PKIXALG_SECP256R1,
    PKIXALG_SECP384R1, PKIXALG_SECP521R1,
};
use const_oid::ObjectIdentifier;
use der::asn1::UintRef;
use der::{Decode, Sequence};
use spki::SubjectPublicKeyInfoOwned;

/// `BCRYPT_RSAPUBLIC_MAGIC`, "RSA1".
pub(crate) const RSAPUBLIC_MAGIC: u32 = 0x3141_5352;
/// `BCRYPT_ECDSA_PUBLIC_P256_MAGIC`, "ECS1".
pub(crate) const ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;
/// `BCRYPT_ECDSA_PUBLIC_P384_MAGIC`, "ECS3".
pub(crate) const ECDSA_PUBLIC_P384_MAGIC: u32 = 0x3353_4345;
/// `BCRYPT_ECDSA_PUBLIC_P521_MAGIC`, "ECS5".
pub(crate) const ECDSA_PUBLIC_P521_MAGIC: u32 = 0x3553_4345;

/// A curve CNG provides ECDSA over.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match *oid {
            PKIXALG_SECP256R1 => Some(Curve::P256),
            PKIXALG_SECP384R1 => Some(Curve::P384),
            PKIXALG_SECP521R1 => Some(Curve::P521),
            _ => None,
        }
    }

    /// The size in bytes of one coordinate, which is also the width each of `r` and `s` is padded
    /// to in a CNG signature.
    pub(crate) fn field_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }

    fn magic(self) -> u32 {
        match self {
            Curve::P256 => ECDSA_PUBLIC_P256_MAGIC,
            Curve::P384 => ECDSA_PUBLIC_P384_MAGIC,
            Curve::P521 => ECDSA_PUBLIC_P521_MAGIC,
        }
    }
}

/// Builds a `BCRYPT_RSAPUBLIC_BLOB` for `spki`, for use with `padding`.
///
/// A PKCS #1 v1.5 signature needs a key identified as `rsaEncryption`: RFC 4055 restricts a key
/// identified as `id-RSASSA-PSS` to PSS, and certval's software verifier rejects the combination,
/// so it is declined here and software gives that verdict.
pub(crate) fn rsa_public_blob(
    spki: &SubjectPublicKeyInfoOwned,
    padding: Padding,
) -> Option<Vec<u8>> {
    let identified_as = spki.algorithm.oid;
    let acceptable = match padding {
        Padding::Pkcs1 => identified_as == PKIXALG_RSA_ENCRYPTION,
        Padding::Pss { .. } => {
            identified_as == PKIXALG_RSA_ENCRYPTION || identified_as == PKIXALG_RSASSA_PSS
        }
        Padding::Ecdsa => false,
    };
    if !acceptable {
        return None;
    }

    let key = RsaPublicKey::from_der(spki.subject_public_key.as_bytes()?).ok()?;
    let modulus = key.modulus.as_bytes();
    let exponent = key.public_exponent.as_bytes();
    let top = *modulus.first()?;
    let bit_length = u32::try_from(modulus.len() * 8).ok()? - top.leading_zeros();

    let mut blob = Vec::with_capacity(24 + exponent.len() + modulus.len());
    for field in [
        RSAPUBLIC_MAGIC,
        bit_length,
        u32::try_from(exponent.len()).ok()?,
        u32::try_from(modulus.len()).ok()?,
        0, // cbPrime1, absent from a public blob
        0, // cbPrime2, absent from a public blob
    ] {
        blob.extend_from_slice(&field.to_le_bytes());
    }
    blob.extend_from_slice(exponent);
    blob.extend_from_slice(modulus);
    Some(blob)
}

/// Builds a `BCRYPT_ECCPUBLIC_BLOB` for `spki`, together with the curve it is on.
///
/// The curve must be named, must be one CNG provides, and must match the length of the point.
pub(crate) fn ecc_public_blob(spki: &SubjectPublicKeyInfoOwned) -> Option<(Curve, Vec<u8>)> {
    if spki.algorithm.oid != PKIXALG_EC_PUBLIC_KEY {
        return None;
    }
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()?
        .decode_as::<ObjectIdentifier>()
        .ok()?;
    let curve = Curve::from_oid(&curve_oid)?;

    let point = spki.subject_public_key.as_bytes()?;
    let field_len = curve.field_len();
    if point.len() != 1 + 2 * field_len || point[0] != 0x04 {
        return None;
    }

    let mut blob = Vec::with_capacity(8 + 2 * field_len);
    blob.extend_from_slice(&curve.magic().to_le_bytes());
    blob.extend_from_slice(&u32::try_from(field_len).ok()?.to_le_bytes());
    blob.extend_from_slice(&point[1..]);
    Some((curve, blob))
}

/// Reshapes a DER ECDSA signature into fixed-width `r‖s`.
///
/// `field_len` comes from the curve rather than from the signature, since either integer can be
/// short by more than one byte.
pub(crate) fn ecdsa_signature_raw(signature: &[u8], field_len: usize) -> Option<Vec<u8>> {
    let parsed = EcdsaSignature::from_der(signature).ok()?;
    let r = parsed.r.as_bytes();
    let s = parsed.s.as_bytes();
    if r.len() > field_len || s.len() > field_len {
        return None;
    }
    let mut out = vec![0u8; field_len * 2];
    out[field_len - r.len()..field_len].copy_from_slice(r);
    out[field_len * 2 - s.len()..].copy_from_slice(s);
    Some(out)
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

/// `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
#[derive(Sequence)]
struct EcdsaSignature<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::{Any, BitString};
    use der::Encode;
    use spki::AlgorithmIdentifierOwned;

    fn rsa_spki(
        oid: ObjectIdentifier,
        modulus: &[u8],
        exponent: &[u8],
    ) -> SubjectPublicKeyInfoOwned {
        let key = RsaPublicKey {
            modulus: UintRef::new(modulus).unwrap(),
            public_exponent: UintRef::new(exponent).unwrap(),
        };
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&key.to_der().unwrap()).unwrap(),
        }
    }

    fn ec_spki(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: PKIXALG_EC_PUBLIC_KEY,
                parameters: Some(Any::encode_from(&curve).unwrap()),
            },
            subject_public_key: BitString::from_bytes(point).unwrap(),
        }
    }

    fn le(blob: &[u8], field: usize) -> u32 {
        u32::from_le_bytes(blob[field * 4..field * 4 + 4].try_into().unwrap())
    }

    #[test]
    fn rsa_blob_layout() {
        // A 2047-bit modulus: the top byte is 0x7f, so one bit short of 2048.
        let mut modulus = vec![0xabu8; 256];
        modulus[0] = 0x7f;
        let spki = rsa_spki(PKIXALG_RSA_ENCRYPTION, &modulus, &[0x01, 0x00, 0x01]);
        let blob = rsa_public_blob(&spki, Padding::Pkcs1).unwrap();

        assert_eq!(le(&blob, 0), RSAPUBLIC_MAGIC);
        assert_eq!(le(&blob, 1), 2047);
        assert_eq!(le(&blob, 2), 3);
        assert_eq!(le(&blob, 3), 256);
        assert_eq!(le(&blob, 4), 0);
        assert_eq!(le(&blob, 5), 0);
        assert_eq!(&blob[24..27], &[0x01, 0x00, 0x01]);
        assert_eq!(&blob[27..], modulus.as_slice());
    }

    #[test]
    fn rsa_blob_drops_the_der_sign_byte() {
        // A modulus with its top bit set is encoded in DER with a leading zero, which is not part
        // of the value and must not reach the blob.
        let modulus = vec![0xffu8; 256];
        let spki = rsa_spki(PKIXALG_RSA_ENCRYPTION, &modulus, &[0x03]);
        let blob = rsa_public_blob(&spki, Padding::Pkcs1).unwrap();
        assert_eq!(le(&blob, 1), 2048);
        assert_eq!(le(&blob, 3), 256);
        assert_eq!(blob.len(), 24 + 1 + 256);
    }

    #[test]
    fn a_pss_key_verifies_only_pss() {
        let spki = rsa_spki(PKIXALG_RSASSA_PSS, &[0xc5; 256], &[0x01, 0x00, 0x01]);
        assert!(rsa_public_blob(&spki, Padding::Pkcs1).is_none());
        assert!(rsa_public_blob(&spki, Padding::Pss { salt_len: 32 }).is_some());
    }

    #[test]
    fn ecc_blob_layout() {
        for (oid, curve, field_len, magic) in [
            (PKIXALG_SECP256R1, Curve::P256, 32, ECDSA_PUBLIC_P256_MAGIC),
            (PKIXALG_SECP384R1, Curve::P384, 48, ECDSA_PUBLIC_P384_MAGIC),
            (PKIXALG_SECP521R1, Curve::P521, 66, ECDSA_PUBLIC_P521_MAGIC),
        ] {
            let mut point = vec![0x04u8];
            point.extend(std::iter::repeat_n(0x0a, field_len));
            point.extend(std::iter::repeat_n(0x0b, field_len));
            let (found, blob) = ecc_public_blob(&ec_spki(oid, &point)).unwrap();
            assert_eq!(found, curve);
            assert_eq!(le(&blob, 0), magic);
            assert_eq!(le(&blob, 1) as usize, field_len);
            assert_eq!(&blob[8..], &point[1..]);
        }
    }

    #[test]
    fn ecc_point_must_fit_its_curve() {
        let mut point = vec![0x04u8; 65];
        assert!(ecc_public_blob(&ec_spki(PKIXALG_SECP384R1, &point)).is_none());
        point[0] = 0x02;
        assert!(ecc_public_blob(&ec_spki(PKIXALG_SECP256R1, &point)).is_none());
        let brainpool = ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7");
        assert!(ecc_public_blob(&ec_spki(brainpool, &[0x04; 65])).is_none());
    }

    #[test]
    fn ecdsa_signature_is_padded_to_the_field() {
        let sig = EcdsaSignature {
            r: UintRef::new(&[0x01, 0x02]).unwrap(),
            s: UintRef::new(&[0xff; 32]).unwrap(),
        }
        .to_der()
        .unwrap();
        let raw = ecdsa_signature_raw(&sig, 32).unwrap();
        assert_eq!(raw.len(), 64);
        assert_eq!(&raw[..30], &[0u8; 30]);
        assert_eq!(&raw[30..32], &[0x01, 0x02]);
        assert_eq!(&raw[32..], &[0xff; 32]);
    }

    #[test]
    fn ecdsa_signature_wider_than_the_field_is_refused() {
        let sig = EcdsaSignature {
            r: UintRef::new(&[0x01; 33]).unwrap(),
            s: UintRef::new(&[0x01]).unwrap(),
        }
        .to_der()
        .unwrap();
        assert!(ecdsa_signature_raw(&sig, 32).is_none());
    }

    /// The magic numbers are restated here so the module builds without `windows-sys`; this checks
    /// the restatement against the bindings wherever they exist.
    #[cfg(windows)]
    #[test]
    fn magic_numbers_match_the_bindings() {
        use windows_sys::Win32::Security::Cryptography as c;
        assert_eq!(RSAPUBLIC_MAGIC, c::BCRYPT_RSAPUBLIC_MAGIC);
        assert_eq!(ECDSA_PUBLIC_P256_MAGIC, c::BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
        assert_eq!(ECDSA_PUBLIC_P384_MAGIC, c::BCRYPT_ECDSA_PUBLIC_P384_MAGIC);
        assert_eq!(ECDSA_PUBLIC_P521_MAGIC, c::BCRYPT_ECDSA_PUBLIC_P521_MAGIC);
    }
}
