//! Turning a `SubjectPublicKeyInfo` into the key blobs `BCryptImportKeyPair` takes, and back from
//! the public key blobs `NCryptExportKey` gives, and reshaping ECDSA signatures into the form
//! `BCryptVerifySignature` expects.
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

use crate::algorithm::{MlDsa, MlKem, Padding};
use certval::{
    PKIXALG_EC_PUBLIC_KEY, PKIXALG_RSASSA_PSS, PKIXALG_RSA_ENCRYPTION, PKIXALG_SECP256R1,
    PKIXALG_SECP384R1, PKIXALG_SECP521R1,
};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, BitString, UintRef};
use der::{Decode, Encode, Sequence};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// `BCRYPT_RSAPUBLIC_MAGIC`, "RSA1".
pub(crate) const RSAPUBLIC_MAGIC: u32 = 0x3141_5352;
/// `BCRYPT_ECDSA_PUBLIC_P256_MAGIC`, "ECS1".
pub(crate) const ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;
/// `BCRYPT_ECDSA_PUBLIC_P384_MAGIC`, "ECS3".
pub(crate) const ECDSA_PUBLIC_P384_MAGIC: u32 = 0x3353_4345;
/// `BCRYPT_ECDSA_PUBLIC_P521_MAGIC`, "ECS5".
pub(crate) const ECDSA_PUBLIC_P521_MAGIC: u32 = 0x3553_4345;
/// `BCRYPT_ECDH_PUBLIC_P256_MAGIC`, "ECK1".
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) const ECDH_PUBLIC_P256_MAGIC: u32 = 0x314B_4345;
/// `BCRYPT_ECDH_PUBLIC_P384_MAGIC`, "ECK3".
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) const ECDH_PUBLIC_P384_MAGIC: u32 = 0x334B_4345;
/// `BCRYPT_ECDH_PUBLIC_P521_MAGIC`, "ECK5".
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) const ECDH_PUBLIC_P521_MAGIC: u32 = 0x354B_4345;
/// `BCRYPT_MLDSA_PUBLIC_MAGIC`, "DSPK".
pub(crate) const MLDSA_PUBLIC_MAGIC: u32 = 0x4B50_5344;
/// `BCRYPT_MLKEM_PUBLIC_MAGIC`, "MLKP".
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) const MLKEM_PUBLIC_MAGIC: u32 = 0x504B_4C4D;
/// `BCRYPT_MLKEM_PRIVATE_MAGIC`, "MLKR": an expanded decapsulation key.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) const MLKEM_PRIVATE_MAGIC: u32 = 0x524B_4C4D;
/// `BCRYPT_MLKEM_PRIVATE_SEED_MAGIC`, "MLKS": the seed `d ‖ z` a key pair is generated from.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) const MLKEM_PRIVATE_SEED_MAGIC: u32 = 0x534B_4C4D;
/// `BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC`, "ECDP": a key of the generic ECDSA algorithm, whose blob
/// does not name its curve.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) const ECDSA_PUBLIC_GENERIC_MAGIC: u32 = 0x5044_4345;
/// `BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC`, "ECKP": as for ECDSA.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) const ECDH_PUBLIC_GENERIC_MAGIC: u32 = 0x504B_4345;

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

    #[cfg_attr(not(feature = "cms"), allow(dead_code))]
    fn oid(self) -> ObjectIdentifier {
        match self {
            Curve::P256 => PKIXALG_SECP256R1,
            Curve::P384 => PKIXALG_SECP384R1,
            Curve::P521 => PKIXALG_SECP521R1,
        }
    }

    /// The curve a public key blob's magic number names: an ECDSA or an ECDH one, since a key
    /// imported from PKCS #8 may be either.
    #[cfg_attr(not(feature = "cms"), allow(dead_code))]
    fn from_magic(magic: u32) -> Option<Self> {
        match magic {
            ECDSA_PUBLIC_P256_MAGIC | ECDH_PUBLIC_P256_MAGIC => Some(Curve::P256),
            ECDSA_PUBLIC_P384_MAGIC | ECDH_PUBLIC_P384_MAGIC => Some(Curve::P384),
            ECDSA_PUBLIC_P521_MAGIC | ECDH_PUBLIC_P521_MAGIC => Some(Curve::P521),
            _ => None,
        }
    }

    /// The curve whose coordinates are `field_len` octets.
    #[cfg_attr(not(feature = "cms"), allow(dead_code))]
    fn from_field_len(field_len: usize) -> Option<Self> {
        match field_len {
            32 => Some(Curve::P256),
            48 => Some(Curve::P384),
            66 => Some(Curve::P521),
            _ => None,
        }
    }
}

/// The little-endian `u32` at field `index` of a blob header.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
fn header_field(blob: &[u8], index: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        blob.get(index * 4..index * 4 + 4)?.try_into().ok()?,
    ))
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

/// The `SubjectPublicKeyInfo` for a `BCRYPT_RSAPUBLIC_BLOB`, as `NCryptExportKey` gives one: the
/// reverse of [`rsa_public_blob`], the key identified as `rsaEncryption` with NULL parameters, as
/// RFC 3279 has it.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) fn rsa_spki_from_blob(blob: &[u8]) -> Option<SubjectPublicKeyInfoOwned> {
    if header_field(blob, 0)? != RSAPUBLIC_MAGIC {
        return None;
    }
    let exponent_len = usize::try_from(header_field(blob, 2)?).ok()?;
    let modulus_len = usize::try_from(header_field(blob, 3)?).ok()?;
    let exponent = blob.get(24..24 + exponent_len)?;
    let modulus = blob.get(24 + exponent_len..24 + exponent_len + modulus_len)?;
    // UintRef takes the big-endian magnitude, and DER adds the sign byte a value with its top bit
    // set needs.
    let key = RsaPublicKey {
        modulus: UintRef::new(modulus).ok()?,
        public_exponent: UintRef::new(exponent).ok()?,
    };
    Some(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: PKIXALG_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        },
        subject_public_key: BitString::from_bytes(&key.to_der().ok()?).ok()?,
    })
}

/// The `SubjectPublicKeyInfo` for a `BCRYPT_ECCPUBLIC_BLOB` on P-256, P-384 or P-521, as
/// `NCryptExportKey` gives one: the reverse of [`ecc_public_blob`], an uncompressed point with the
/// curve named. The blob's magic may be an ECDSA or an ECDH one, and a curve's must agree with the
/// blob's length; a generic one, which names no curve, leaves the curve to the length.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) fn ecc_spki_from_blob(blob: &[u8]) -> Option<SubjectPublicKeyInfoOwned> {
    let magic = header_field(blob, 0)?;
    let field_len = usize::try_from(header_field(blob, 1)?).ok()?;
    let curve = match Curve::from_magic(magic) {
        Some(curve) => curve,
        None if magic == ECDSA_PUBLIC_GENERIC_MAGIC || magic == ECDH_PUBLIC_GENERIC_MAGIC => {
            Curve::from_field_len(field_len)?
        }
        None => return None,
    };
    if curve.field_len() != field_len {
        return None;
    }
    let coordinates = blob.get(8..8 + 2 * field_len)?;
    let mut point = Vec::with_capacity(1 + 2 * field_len);
    point.push(0x04);
    point.extend_from_slice(coordinates);
    Some(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: PKIXALG_EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&curve.oid()).ok()?),
        },
        subject_public_key: BitString::from_bytes(&point).ok()?,
    })
}

/// A parameter set's name as a `BCRYPT_PQDSA_KEY_BLOB` or `BCRYPT_MLKEM_KEY_BLOB` carries it:
/// UTF-16LE, ending in a null.
fn parameter_set_utf16(name: &str) -> Vec<u8> {
    name.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// A post-quantum key blob: a `BCRYPT_PQDSA_KEY_BLOB` or `BCRYPT_MLKEM_KEY_BLOB` header (`magic`,
/// the name's length, the key's length), the parameter set's name, then the key.
fn pq_key_blob(magic: u32, parameter_set: &str, key: &[u8]) -> Option<Vec<u8>> {
    let name = parameter_set_utf16(parameter_set);
    let mut blob = Vec::with_capacity(12 + name.len() + key.len());
    for field in [
        magic,
        u32::try_from(name.len()).ok()?,
        u32::try_from(key.len()).ok()?,
    ] {
        blob.extend_from_slice(&field.to_le_bytes());
    }
    blob.extend_from_slice(&name);
    blob.extend_from_slice(key);
    Some(blob)
}

/// Builds a `BCRYPT_MLKEM_PUBLIC_BLOB` (the encapsulation blob) for an ML-KEM `spki`, together with
/// its parameter set. The `SubjectPublicKeyInfo` carries the encapsulation key as it is (RFC 9935),
/// with no parameters, and its length must be the parameter set's.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) fn ml_kem_public_blob(spki: &SubjectPublicKeyInfoOwned) -> Option<(MlKem, Vec<u8>)> {
    if spki.algorithm.parameters.is_some() {
        return None;
    }
    let set = MlKem::from_oid(&spki.algorithm.oid)?;
    let key = spki.subject_public_key.as_bytes()?;
    if key.len() != set.public_key_len() {
        return None;
    }
    Some((
        set,
        pq_key_blob(MLKEM_PUBLIC_MAGIC, set.parameter_set(), key)?,
    ))
}

/// The blob an ML-KEM private key imports as: `BCRYPT_MLKEM_PRIVATE_SEED_BLOB` or
/// `BCRYPT_MLKEM_PRIVATE_BLOB`.
#[cfg(feature = "cms")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum MlKemPrivateBlob {
    /// A `BCRYPT_MLKEM_KEY_BLOB` with the seed, from which CNG expands the key.
    Seed,
    /// A `BCRYPT_MLKEM_KEY_BLOB` with the expanded decapsulation key.
    Expanded,
}

/// Builds the `BCRYPT_MLKEM_KEY_BLOB` for an ML-KEM private key of the parameter set `set`, in one
/// of RFC 9935's three forms: the seed where the key has one, which CNG expands, otherwise the
/// expanded decapsulation key. The seed or key must be its parameter set's length. CNG's PKCS #8
/// import does not take an ML-KEM key, so this is how one reaches the Software Key Storage
/// Provider.
#[cfg(feature = "cms")]
pub(crate) fn ml_kem_private_blob(
    set: MlKem,
    key: &certval_cms::SeedOrExpandedKey,
) -> Option<(MlKemPrivateBlob, zeroize::Zeroizing<Vec<u8>>)> {
    use certval_cms::SeedOrExpandedKey;
    let (kind, magic, bytes, len) = match key {
        SeedOrExpandedKey::Seed(seed) => (
            MlKemPrivateBlob::Seed,
            MLKEM_PRIVATE_SEED_MAGIC,
            seed.as_bytes(),
            MlKem::SEED_LEN,
        ),
        SeedOrExpandedKey::Both(both) => (
            MlKemPrivateBlob::Seed,
            MLKEM_PRIVATE_SEED_MAGIC,
            both.seed.as_bytes(),
            MlKem::SEED_LEN,
        ),
        SeedOrExpandedKey::ExpandedKey(expanded) => (
            MlKemPrivateBlob::Expanded,
            MLKEM_PRIVATE_MAGIC,
            expanded.as_bytes(),
            set.private_key_len(),
        ),
    };
    if bytes.len() != len {
        return None;
    }
    let blob = pq_key_blob(magic, set.parameter_set(), bytes)?;
    Some((kind, zeroize::Zeroizing::new(blob)))
}

/// Builds a `BCRYPT_PQDSA_PUBLIC_BLOB` for an ML-DSA `spki`, together with its parameter set: a
/// `BCRYPT_PQDSA_KEY_BLOB` header, the parameter set's name, then the public key, which the
/// `SubjectPublicKeyInfo` carries as it is (RFC 9881). The key's parameters must be absent and its
/// length the parameter set's.
pub(crate) fn ml_dsa_public_blob(spki: &SubjectPublicKeyInfoOwned) -> Option<(MlDsa, Vec<u8>)> {
    let set = MlDsa::from_algorithm(&spki.algorithm)?;
    let key = spki.subject_public_key.as_bytes()?;
    if key.len() != set.public_key_len() {
        return None;
    }
    Some((
        set,
        pq_key_blob(MLDSA_PUBLIC_MAGIC, set.parameter_set(), key)?,
    ))
}

/// The `SubjectPublicKeyInfo` for a `BCRYPT_PQDSA_PUBLIC_BLOB` of an ML-DSA key, as
/// `NCryptExportKey` gives one: the reverse of [`ml_dsa_public_blob`].
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) fn ml_dsa_spki_from_blob(blob: &[u8]) -> Option<SubjectPublicKeyInfoOwned> {
    if header_field(blob, 0)? != MLDSA_PUBLIC_MAGIC {
        return None;
    }
    let name_len = usize::try_from(header_field(blob, 1)?).ok()?;
    let key_len = usize::try_from(header_field(blob, 2)?).ok()?;
    let name = blob.get(12..12 + name_len)?;
    let key = blob.get(12 + name_len..12 + name_len + key_len)?;
    let set = MlDsa::ALL
        .into_iter()
        .find(|set| parameter_set_utf16(set.parameter_set()) == name)?;
    if key.len() != set.public_key_len() {
        return None;
    }
    Some(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: set.oid(),
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(key).ok()?,
    })
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
    fn rsa_spki_round_trips_through_the_blob() {
        // A modulus with its top bit set, which DER encodes with a sign byte the blob does not
        // carry, and one without.
        for top in [0xc5u8, 0x7f] {
            let mut modulus = vec![0xabu8; 256];
            modulus[0] = top;
            let spki = rsa_spki(PKIXALG_RSA_ENCRYPTION, &modulus, &[0x01, 0x00, 0x01]);
            let blob = rsa_public_blob(&spki, Padding::Pkcs1).unwrap();
            let back = rsa_spki_from_blob(&blob).unwrap();
            assert_eq!(back.algorithm.oid, PKIXALG_RSA_ENCRYPTION);
            assert_eq!(back.algorithm.parameters, Some(Any::null()));
            assert_eq!(back.subject_public_key, spki.subject_public_key);
        }
    }

    #[test]
    fn rsa_blob_too_short_for_its_header_is_refused() {
        let spki = rsa_spki(PKIXALG_RSA_ENCRYPTION, &[0xc5; 256], &[0x01, 0x00, 0x01]);
        let blob = rsa_public_blob(&spki, Padding::Pkcs1).unwrap();
        assert!(rsa_spki_from_blob(&blob[..blob.len() - 1]).is_none());
        let mut wrong_magic = blob.clone();
        wrong_magic[0] ^= 1;
        assert!(rsa_spki_from_blob(&wrong_magic).is_none());
    }

    #[test]
    fn ecc_spki_round_trips_through_the_blob() {
        for (oid, field_len, ecdh_magic) in [
            (PKIXALG_SECP256R1, 32, ECDH_PUBLIC_P256_MAGIC),
            (PKIXALG_SECP384R1, 48, ECDH_PUBLIC_P384_MAGIC),
            (PKIXALG_SECP521R1, 66, ECDH_PUBLIC_P521_MAGIC),
        ] {
            let mut point = vec![0x04u8];
            point.extend(std::iter::repeat_n(0x0a, field_len));
            point.extend(std::iter::repeat_n(0x0b, field_len));
            let spki = ec_spki(oid, &point);
            let (_, mut blob) = ecc_public_blob(&spki).unwrap();
            assert_eq!(ecc_spki_from_blob(&blob).unwrap(), spki);
            // A key NCrypt imported from PKCS #8 may export as an ECDH key, or as one of a
            // generic algorithm, whose magic names no curve.
            for magic in [
                ecdh_magic,
                ECDSA_PUBLIC_GENERIC_MAGIC,
                ECDH_PUBLIC_GENERIC_MAGIC,
            ] {
                blob[..4].copy_from_slice(&magic.to_le_bytes());
                assert_eq!(ecc_spki_from_blob(&blob).unwrap(), spki);
            }
        }
    }

    #[test]
    fn ecc_blob_must_agree_with_its_magic() {
        let mut point = vec![0x04u8];
        point.extend(std::iter::repeat_n(0x0a, 64));
        let (_, mut blob) = ecc_public_blob(&ec_spki(PKIXALG_SECP256R1, &point)).unwrap();
        blob[4..8].copy_from_slice(&48u32.to_le_bytes());
        assert!(ecc_spki_from_blob(&blob).is_none());
        let (_, blob) = ecc_public_blob(&ec_spki(PKIXALG_SECP256R1, &point)).unwrap();
        assert!(ecc_spki_from_blob(&blob[..blob.len() - 1]).is_none());
        assert!(ecc_spki_from_blob(&RSAPUBLIC_MAGIC.to_le_bytes()).is_none());
    }

    fn ml_dsa_spki(set: MlDsa, key: &[u8]) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: set.oid(),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(key).unwrap(),
        }
    }

    #[test]
    fn ml_dsa_blob_layout() {
        for set in MlDsa::ALL {
            let key: Vec<u8> = (0..set.public_key_len()).map(|i| i as u8).collect();
            let (found, blob) = ml_dsa_public_blob(&ml_dsa_spki(set, &key)).unwrap();
            assert_eq!(found, set);
            assert_eq!(le(&blob, 0), MLDSA_PUBLIC_MAGIC);
            // Two digits and a null, each a UTF-16 code unit.
            assert_eq!(le(&blob, 1), 6);
            assert_eq!(le(&blob, 2) as usize, key.len());
            let name: Vec<u8> = set
                .parameter_set()
                .bytes()
                .flat_map(|b| [b, 0])
                .chain([0, 0])
                .collect();
            assert_eq!(&blob[12..18], name.as_slice());
            assert_eq!(&blob[18..], key.as_slice());
        }
    }

    #[test]
    fn ml_dsa_spki_round_trips_through_the_blob() {
        for set in MlDsa::ALL {
            let spki = ml_dsa_spki(set, &vec![0x5a; set.public_key_len()]);
            let (_, blob) = ml_dsa_public_blob(&spki).unwrap();
            assert_eq!(ml_dsa_spki_from_blob(&blob).unwrap(), spki);
        }
    }

    #[test]
    fn ml_dsa_key_must_fit_its_parameter_set() {
        // ML-DSA-65's length under ML-DSA-44's OID.
        let spki = ml_dsa_spki(MlDsa::MlDsa44, &[0; 1952]);
        assert!(ml_dsa_public_blob(&spki).is_none());
        let mut with_parameters = ml_dsa_spki(MlDsa::MlDsa44, &[0; 1312]);
        with_parameters.algorithm.parameters = Some(Any::null());
        assert!(ml_dsa_public_blob(&with_parameters).is_none());
        let (_, blob) = ml_dsa_public_blob(&ml_dsa_spki(MlDsa::MlDsa44, &[0; 1312])).unwrap();
        assert!(ml_dsa_spki_from_blob(&blob[..blob.len() - 1]).is_none());
    }

    #[test]
    fn ml_kem_blob_layout() {
        use const_oid::db::fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768};
        for (oid, name, key_len) in [
            (ID_ALG_ML_KEM_512, "512", 800),
            (ID_ALG_ML_KEM_768, "768", 1184),
            (ID_ALG_ML_KEM_1024, "1024", 1568),
        ] {
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            let spki = SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid,
                    parameters: None,
                },
                subject_public_key: BitString::from_bytes(&key).unwrap(),
            };
            let (set, blob) = ml_kem_public_blob(&spki).unwrap();
            assert_eq!(set.parameter_set(), name);
            assert_eq!(le(&blob, 0), MLKEM_PUBLIC_MAGIC);
            // The digits and a null, each a UTF-16 code unit.
            let name_len = 2 * (name.len() + 1);
            assert_eq!(le(&blob, 1) as usize, name_len);
            assert_eq!(le(&blob, 2) as usize, key_len);
            let utf16: Vec<u8> = name.bytes().flat_map(|b| [b, 0]).chain([0, 0]).collect();
            assert_eq!(&blob[12..12 + name_len], utf16.as_slice());
            assert_eq!(&blob[12 + name_len..], key.as_slice());
            // A key of another parameter set's length, or with parameters, is refused.
            let mut short = spki.clone();
            short.subject_public_key = BitString::from_bytes(&key[1..]).unwrap();
            assert!(ml_kem_public_blob(&short).is_none());
            let mut with_parameters = spki;
            with_parameters.algorithm.parameters = Some(Any::null());
            assert!(ml_kem_public_blob(&with_parameters).is_none());
        }
    }

    #[cfg(feature = "cms")]
    #[test]
    fn ml_kem_private_blob_takes_the_seed_where_there_is_one() {
        use certval_cms::{SeedAndExpandedKey, SeedOrExpandedKey};
        use der::asn1::OctetString;
        for set in [MlKem::MlKem512, MlKem::MlKem768, MlKem::MlKem1024] {
            let seed = OctetString::new(vec![0x5a; 64]).unwrap();
            let expanded = OctetString::new(vec![0xa5; set.private_key_len()]).unwrap();
            let name_len = 2 * (set.parameter_set().len() + 1);
            for key in [
                SeedOrExpandedKey::Seed(seed.clone()),
                SeedOrExpandedKey::Both(SeedAndExpandedKey {
                    seed: seed.clone(),
                    expanded_key: expanded.clone(),
                }),
            ] {
                let (kind, blob) = ml_kem_private_blob(set, &key).unwrap();
                assert_eq!(kind, MlKemPrivateBlob::Seed);
                assert_eq!(le(&blob, 0), MLKEM_PRIVATE_SEED_MAGIC);
                assert_eq!(le(&blob, 1) as usize, name_len);
                assert_eq!(le(&blob, 2), 64);
                assert_eq!(&blob[12 + name_len..], seed.as_bytes());
            }
            let (kind, blob) =
                ml_kem_private_blob(set, &SeedOrExpandedKey::ExpandedKey(expanded.clone()))
                    .unwrap();
            assert_eq!(kind, MlKemPrivateBlob::Expanded);
            assert_eq!(le(&blob, 0), MLKEM_PRIVATE_MAGIC);
            assert_eq!(le(&blob, 2) as usize, set.private_key_len());
            assert_eq!(&blob[12 + name_len..], expanded.as_bytes());
            // A seed or key of another length is refused.
            let short = OctetString::new(vec![0; 63]).unwrap();
            assert!(ml_kem_private_blob(set, &SeedOrExpandedKey::Seed(short)).is_none());
            let other = OctetString::new(vec![0; 1632 + 1]).unwrap();
            assert!(ml_kem_private_blob(set, &SeedOrExpandedKey::ExpandedKey(other)).is_none());
        }
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
        assert_eq!(ECDH_PUBLIC_P256_MAGIC, c::BCRYPT_ECDH_PUBLIC_P256_MAGIC);
        assert_eq!(ECDH_PUBLIC_P384_MAGIC, c::BCRYPT_ECDH_PUBLIC_P384_MAGIC);
        assert_eq!(ECDH_PUBLIC_P521_MAGIC, c::BCRYPT_ECDH_PUBLIC_P521_MAGIC);
    }
}
