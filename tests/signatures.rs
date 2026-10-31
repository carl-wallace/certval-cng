//! Verifies signatures made by an independent implementation, through both interfaces, and checks
//! every verdict against certval's software verifier.
//!
//! The elliptic curve signatures come from RustCrypto with fixed private scalars, so they are the
//! same on every run. RSA has no deterministic key generation in reach, so the RSA keys are
//! generated in memory by CNG itself; the software verifier is then what keeps those tests from
//! being circular, because it reads the same `SubjectPublicKeyInfo` and must agree.

#![cfg(windows)]
#![allow(unsafe_code)]

use certval::{
    verify_signature_digest_rust_crypto, verify_signature_message_rust_crypto, CalculateHash,
    Error, PathValidationStatus, PkiEnvironment, VerifySignatureDigest, VerifySignatureMessage,
    PKIXALG_ECDSA_WITH_SHA256, PKIXALG_ECDSA_WITH_SHA384, PKIXALG_ECDSA_WITH_SHA512,
    PKIXALG_EC_PUBLIC_KEY, PKIXALG_MGF1, PKIXALG_RSASSA_PSS, PKIXALG_RSA_ENCRYPTION,
    PKIXALG_SECP256R1, PKIXALG_SECP384R1, PKIXALG_SECP521R1, PKIXALG_SHA1, PKIXALG_SHA256,
    PKIXALG_SHA256_WITH_RSA_ENCRYPTION, PKIXALG_SHA384, PKIXALG_SHA384_WITH_RSA_ENCRYPTION,
    PKIXALG_SHA512,
};
use certval_cng::CngCrypto;
use const_oid::ObjectIdentifier;
use der::asn1::{Any, BitString, UintRef};
use der::Encode;
use sha2::Digest;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const MESSAGE: &[u8] = b"a to-be-signed structure stands in here";

/// One signature together with what is needed to check it.
struct Case {
    spki: SubjectPublicKeyInfoOwned,
    alg: AlgorithmIdentifierOwned,
    signature: Vec<u8>,
    digest: Vec<u8>,
}

fn pe() -> PkiEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe
}

fn bits(bytes: &[u8]) -> BitString {
    BitString::from_bytes(bytes).unwrap()
}

fn plain(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}

fn ec_spki(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: PKIXALG_EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&curve).unwrap()),
        },
        subject_public_key: bits(point),
    }
}

macro_rules! ec_case {
    ($curve:ident, $curve_oid:expr, $sig_oid:expr, $digest:ty, $scalar:expr) => {{
        use signature::hazmat::PrehashSigner;
        let key = $curve::ecdsa::SigningKey::from_slice(&$scalar).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let digest = <$digest>::digest(MESSAGE).to_vec();
        let signature: $curve::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        Case {
            spki: ec_spki($curve_oid, point.as_bytes()),
            alg: plain($sig_oid),
            signature: signature.to_der().as_bytes().to_vec(),
            digest,
        }
    }};
}

fn ec_cases() -> Vec<(&'static str, Case)> {
    vec![
        (
            "P-256",
            ec_case!(
                p256,
                PKIXALG_SECP256R1,
                PKIXALG_ECDSA_WITH_SHA256,
                sha2::Sha256,
                [0x11u8; 32]
            ),
        ),
        (
            "P-384",
            ec_case!(
                p384,
                PKIXALG_SECP384R1,
                PKIXALG_ECDSA_WITH_SHA384,
                sha2::Sha384,
                [0x22u8; 48]
            ),
        ),
        (
            "P-521",
            ec_case!(
                p521,
                PKIXALG_SECP521R1,
                PKIXALG_ECDSA_WITH_SHA512,
                sha2::Sha512,
                {
                    // A P-521 scalar is 521 bits, so the top byte holds a single bit.
                    let mut s = [0x33u8; 66];
                    s[0] = 0x01;
                    s
                }
            ),
        ),
    ]
}

/// An RSA key pair generated in memory by CNG, used only to make test signatures.
mod rsa_signer {
    use windows_sys::core::PCWSTR;
    use windows_sys::Win32::Security::Cryptography::*;

    pub struct Signer(BCRYPT_KEY_HANDLE);

    impl Drop for Signer {
        fn drop(&mut self) {
            unsafe {
                BCryptDestroyKey(self.0);
            }
        }
    }

    pub enum Pad {
        Pkcs1,
        Pss(u32),
    }

    impl Signer {
        pub fn generate(bits: u32) -> Self {
            let mut key: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
            unsafe {
                assert!(BCryptGenerateKeyPair(BCRYPT_RSA_ALG_HANDLE, &mut key, bits, 0) >= 0);
                assert!(BCryptFinalizeKeyPair(key, 0) >= 0);
            }
            Signer(key)
        }

        /// Returns the public exponent and modulus, big-endian, from a `BCRYPT_RSAPUBLIC_BLOB`.
        pub fn public(&self) -> (Vec<u8>, Vec<u8>) {
            let mut len = 0u32;
            unsafe {
                assert!(
                    BCryptExportKey(
                        self.0,
                        std::ptr::null_mut(),
                        BCRYPT_RSAPUBLIC_BLOB,
                        std::ptr::null_mut(),
                        0,
                        &mut len,
                        0
                    ) >= 0
                );
            }
            let mut blob = vec![0u8; len as usize];
            unsafe {
                assert!(
                    BCryptExportKey(
                        self.0,
                        std::ptr::null_mut(),
                        BCRYPT_RSAPUBLIC_BLOB,
                        blob.as_mut_ptr(),
                        len,
                        &mut len,
                        0
                    ) >= 0
                );
            }
            let field =
                |i: usize| u32::from_le_bytes(blob[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
            let (exp_len, mod_len) = (field(2), field(3));
            let exponent = blob[24..24 + exp_len].to_vec();
            let modulus = blob[24 + exp_len..24 + exp_len + mod_len].to_vec();
            (exponent, modulus)
        }

        pub fn sign(&self, hash: PCWSTR, pad: Pad, digest: &[u8]) -> Vec<u8> {
            let pkcs1 = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: hash };
            let pss_info = BCRYPT_PSS_PADDING_INFO {
                pszAlgId: hash,
                cbSalt: match pad {
                    Pad::Pss(salt) => salt,
                    Pad::Pkcs1 => 0,
                },
            };
            let (info, flags): (*const core::ffi::c_void, u32) = match pad {
                Pad::Pkcs1 => (
                    (&pkcs1 as *const BCRYPT_PKCS1_PADDING_INFO).cast(),
                    BCRYPT_PAD_PKCS1,
                ),
                Pad::Pss(_) => (
                    (&pss_info as *const BCRYPT_PSS_PADDING_INFO).cast(),
                    BCRYPT_PAD_PSS,
                ),
            };
            let mut len = 0u32;
            let mut out = vec![0u8; 1024];
            unsafe {
                assert!(
                    BCryptSignHash(
                        self.0,
                        info,
                        digest.as_ptr(),
                        digest.len() as u32,
                        out.as_mut_ptr(),
                        out.len() as u32,
                        &mut len,
                        flags
                    ) >= 0
                );
            }
            out.truncate(len as usize);
            out
        }
    }
}

use rsa_signer::{Pad, Signer};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALGORITHM,
};

fn rsa_spki(signer: &Signer, oid: ObjectIdentifier) -> SubjectPublicKeyInfoOwned {
    #[derive(der::Sequence)]
    struct RsaPublicKey<'a> {
        modulus: UintRef<'a>,
        public_exponent: UintRef<'a>,
    }
    let (exponent, modulus) = signer.public();
    let key = RsaPublicKey {
        modulus: UintRef::new(&modulus).unwrap(),
        public_exponent: UintRef::new(&exponent).unwrap(),
    };
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid,
            parameters: (oid == PKIXALG_RSA_ENCRYPTION).then(Any::null),
        },
        subject_public_key: bits(&key.to_der().unwrap()),
    }
}

fn pss_alg(hash: ObjectIdentifier, salt_len: u32) -> AlgorithmIdentifierOwned {
    #[derive(der::Sequence)]
    struct Params {
        #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
        hash: AlgorithmIdentifierOwned,
        #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
        mask_gen: AlgorithmIdentifierOwned,
        #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
        salt_len: u32,
    }
    let hash_alg = AlgorithmIdentifierOwned {
        oid: hash,
        parameters: Some(Any::null()),
    };
    let params = Params {
        hash: hash_alg.clone(),
        mask_gen: AlgorithmIdentifierOwned {
            oid: PKIXALG_MGF1,
            parameters: Some(Any::encode_from(&hash_alg).unwrap()),
        },
        salt_len,
    };
    AlgorithmIdentifierOwned {
        oid: PKIXALG_RSASSA_PSS,
        parameters: Some(Any::encode_from(&params).unwrap()),
    }
}

fn rsa_cases() -> Vec<(&'static str, Case)> {
    let key = Signer::generate(2048);
    let key3072 = Signer::generate(3072);
    let spki = rsa_spki(&key, PKIXALG_RSA_ENCRYPTION);
    let spki3072 = rsa_spki(&key3072, PKIXALG_RSA_ENCRYPTION);
    let sha256 = sha2::Sha256::digest(MESSAGE).to_vec();
    let sha384 = sha2::Sha384::digest(MESSAGE).to_vec();
    vec![
        (
            "RSA-2048 PKCS #1 SHA-256",
            Case {
                spki: spki.clone(),
                alg: plain(PKIXALG_SHA256_WITH_RSA_ENCRYPTION),
                signature: key.sign(BCRYPT_SHA256_ALGORITHM, Pad::Pkcs1, &sha256),
                digest: sha256.clone(),
            },
        ),
        (
            "RSA-3072 PKCS #1 SHA-384",
            Case {
                spki: spki3072.clone(),
                alg: plain(PKIXALG_SHA384_WITH_RSA_ENCRYPTION),
                signature: key3072.sign(BCRYPT_SHA384_ALGORITHM, Pad::Pkcs1, &sha384),
                digest: sha384.clone(),
            },
        ),
        (
            "RSA-2048 PSS SHA-256, 32-byte salt",
            Case {
                spki: spki.clone(),
                alg: pss_alg(PKIXALG_SHA256, 32),
                signature: key.sign(BCRYPT_SHA256_ALGORITHM, Pad::Pss(32), &sha256),
                digest: sha256.clone(),
            },
        ),
        (
            // Unlike Security.framework, CNG takes the salt length as a parameter, so a salt other
            // than the hash length is verified rather than left to software.
            "RSA-2048 PSS SHA-256, 20-byte salt",
            Case {
                spki: spki.clone(),
                alg: pss_alg(PKIXALG_SHA256, 20),
                signature: key.sign(BCRYPT_SHA256_ALGORITHM, Pad::Pss(20), &sha256),
                digest: sha256,
            },
        ),
        (
            "RSA-3072 PSS SHA-384 under an id-RSASSA-PSS key",
            Case {
                spki: rsa_spki(&key3072, PKIXALG_RSASSA_PSS),
                alg: pss_alg(PKIXALG_SHA384, 48),
                signature: key3072.sign(BCRYPT_SHA384_ALGORITHM, Pad::Pss(48), &sha384),
                digest: sha384,
            },
        ),
    ]
}

fn all_cases() -> Vec<(&'static str, Case)> {
    let mut cases = ec_cases();
    cases.extend(rsa_cases());
    cases
}

fn is_rejection(result: &certval::Result<()>) -> bool {
    matches!(
        result,
        Err(Error::PathValidation(
            PathValidationStatus::SignatureVerificationFailure
        ))
    )
}

#[test]
fn fips_mode_can_be_queried() {
    let mode = CngCrypto::fips_mode_enabled();
    println!("CNG FIPS-approved mode: {mode:?}");
    assert!(mode.is_some());
}

#[test]
fn hashes_match_software() {
    let pe = pe();
    let crypto = CngCrypto::new();
    let cases: [(ObjectIdentifier, Vec<u8>); 3] = [
        (PKIXALG_SHA256, sha2::Sha256::digest(MESSAGE).to_vec()),
        (PKIXALG_SHA384, sha2::Sha384::digest(MESSAGE).to_vec()),
        (PKIXALG_SHA512, sha2::Sha512::digest(MESSAGE).to_vec()),
    ];
    for (oid, expected) in cases {
        let got = crypto.calculate_hash(&pe, &plain(oid), MESSAGE).unwrap();
        assert_eq!(got, expected, "{oid}");
    }

    // certval's software hash has no SHA-1 to compare against, so SHA-1 is checked against the
    // FIPS 180 example instead: SHA-1("abc").
    let sha1_abc = [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2,
        0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    ];
    let got = crypto
        .calculate_hash(&pe, &plain(PKIXALG_SHA1), b"abc")
        .unwrap();
    assert_eq!(got, sha1_abc);
}

#[test]
fn good_signatures_verify_through_both_interfaces() {
    let pe = pe();
    let crypto = CngCrypto::new();
    for (name, case) in all_cases() {
        let signature = bits(&case.signature);

        let platform =
            crypto.verify_signature_message(&pe, MESSAGE, &signature, &case.alg, &case.spki);
        assert!(platform.is_ok(), "{name}, message: {platform:?}");
        let software =
            verify_signature_message_rust_crypto(&pe, MESSAGE, &signature, &case.alg, &case.spki);
        assert!(
            software.is_ok(),
            "{name}, software disagrees on the message: {software:?}"
        );

        let platform =
            crypto.verify_signature_digest(&pe, &case.digest, &signature, &case.alg, &case.spki);
        assert!(platform.is_ok(), "{name}, digest: {platform:?}");
    }
}

#[test]
fn a_changed_message_is_a_verdict_not_a_refusal() {
    let pe = pe();
    let crypto = CngCrypto::new();
    let other = b"a different to-be-signed structure";
    for (name, case) in all_cases() {
        let signature = bits(&case.signature);
        let platform =
            crypto.verify_signature_message(&pe, other, &signature, &case.alg, &case.spki);
        assert!(is_rejection(&platform), "{name}: {platform:?}");
        let software =
            verify_signature_message_rust_crypto(&pe, other, &signature, &case.alg, &case.spki);
        assert!(
            software.is_err(),
            "{name}: software accepted a changed message"
        );
    }
}

#[test]
fn a_changed_signature_is_a_verdict_not_a_refusal() {
    let pe = pe();
    let crypto = CngCrypto::new();
    for (name, case) in all_cases() {
        let mut tampered = case.signature.clone();
        // The last byte is inside the signature value for every encoding here: the low byte of `s`
        // for a DER ECDSA signature, and the low byte of the integer for RSA.
        *tampered.last_mut().unwrap() ^= 0x01;
        let signature = bits(&tampered);

        let platform =
            crypto.verify_signature_message(&pe, MESSAGE, &signature, &case.alg, &case.spki);
        assert!(is_rejection(&platform), "{name}, message: {platform:?}");

        let platform =
            crypto.verify_signature_digest(&pe, &case.digest, &signature, &case.alg, &case.spki);
        assert!(is_rejection(&platform), "{name}, digest: {platform:?}");
    }
}

#[test]
fn a_pss_signature_with_the_wrong_salt_length_is_a_verdict() {
    let pe = pe();
    let crypto = CngCrypto::new();
    let key = Signer::generate(2048);
    let spki = rsa_spki(&key, PKIXALG_RSA_ENCRYPTION);
    let digest = sha2::Sha256::digest(MESSAGE).to_vec();
    let signature = key.sign(BCRYPT_SHA256_ALGORITHM, Pad::Pss(32), &digest);
    // The signature was made with a 32-byte salt, so a parameter block naming 20 describes a
    // different signature, and CNG, told 20, must find it invalid.
    let alg = pss_alg(PKIXALG_SHA256, 20);
    let result = crypto.verify_signature_digest(&pe, &digest, &bits(&signature), &alg, &spki);
    assert!(is_rejection(&result), "{result:?}");
    let software =
        verify_signature_digest_rust_crypto(&pe, &digest, &bits(&signature), &alg, &spki);
    assert!(software.is_err(), "software accepted the wrong salt length");
}

#[test]
fn a_pkcs1_signature_under_a_pss_key_is_left_to_software() {
    let pe = pe();
    let crypto = CngCrypto::new();
    let key = Signer::generate(2048);
    let spki = rsa_spki(&key, PKIXALG_RSASSA_PSS);
    let digest = sha2::Sha256::digest(MESSAGE).to_vec();
    let signature = key.sign(BCRYPT_SHA256_ALGORITHM, Pad::Pkcs1, &digest);
    let alg = plain(PKIXALG_SHA256_WITH_RSA_ENCRYPTION);

    let result = crypto.verify_signature_message(&pe, MESSAGE, &bits(&signature), &alg, &spki);
    assert!(matches!(result, Err(Error::Unrecognized)), "{result:?}");

    let software =
        verify_signature_message_rust_crypto(&pe, MESSAGE, &bits(&signature), &alg, &spki);
    assert!(is_rejection(&software), "{software:?}");
}

#[test]
fn a_digest_of_the_wrong_length_is_declined() {
    let pe = pe();
    let crypto = CngCrypto::new();
    for (name, case) in all_cases() {
        let short = &case.digest[..case.digest.len() - 1];
        let result = crypto.verify_signature_digest(
            &pe,
            short,
            &bits(&case.signature),
            &case.alg,
            &case.spki,
        );
        assert!(
            matches!(result, Err(Error::Unrecognized)),
            "{name}: {result:?}"
        );
    }
}

#[test]
fn registered_first_it_answers_and_software_agrees() {
    let mut pe = PkiEnvironment::default();
    pe.add_calculate_hash_callback(CngCrypto::new());
    pe.add_verify_signature_message_callback(CngCrypto::new());
    pe.add_verify_signature_digest_callback(CngCrypto::new());
    pe.populate_5280_pki_environment();

    for (name, case) in all_cases() {
        let signature = bits(&case.signature);
        assert!(
            pe.verify_signature_message(&pe, MESSAGE, &signature, &case.alg, &case.spki)
                .is_ok(),
            "{name}"
        );
        assert!(
            pe.verify_signature_digest(&pe, &case.digest, &signature, &case.alg, &case.spki)
                .is_ok(),
            "{name}"
        );
    }
}
