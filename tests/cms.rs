//! CMS through this provider, crossed with certval-cms's RustCrypto software in both directions.
//! Keys are generated in software and imported into the Microsoft Software Key Storage Provider,
//! so that both hold the same key.
//!
//! Enveloping: messages software builds are decrypted with only this provider registered and a
//! `CngRecipientKey`, and messages this provider builds are decrypted by software. Every key
//! transport algorithm with AES-CBC and AES-GCM content, and ECDH on P-256, P-384 and P-521 with each
//! KDF hash, wrap and user keying material.
//!
//! Signing: messages a `CngSigningKey` signs, a digest at a time, are verified by software, and
//! messages software signs are verified, and hashed, by this provider alone. A `CngKey`, with no
//! certificate, signs its own certificate request, which software verifies.

#![cfg(all(windows, feature = "cms"))]

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use certval::PkiEnvironment;
use certval_cms::{
    rsa_pss, CmsEnvironment, ContentEncryptionAlgorithm, DigestAlgorithm, EnvelopedDataBuilder,
    Error, KeyAgreeRecipient, KeyAgreementAlgorithm, KeyTransRecipient, KeyTransportAlgorithm,
    KeyWrapAlgorithm, RecipientCredential, SignedDataBuilder, Signer, SignerPolicy,
    SigningCredential, SoftwareRecipientKey, SoftwareSigningKey,
};
use certval_cng::{import_pkcs8, CngCrypto};
use cms::content_info::ContentInfo;
use const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER;
use der::{asn1::OctetString, Decode, Encode};
use elliptic_curve::Generate as _;
use getrandom::SysRng;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand_core::UnwrapErr;
use sha1::{Digest, Sha1};
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    ext::{pkix::SubjectKeyIdentifier, Extension},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
    Certificate, TbsCertificate,
};

type Rng = UnwrapErr<SysRng>;

const MESSAGE: &[u8] = b"certval-cng, longer than one AES block so that padding is exercised";

const CONTENT: [ContentEncryptionAlgorithm; 6] = [
    ContentEncryptionAlgorithm::Aes128Cbc,
    ContentEncryptionAlgorithm::Aes192Cbc,
    ContentEncryptionAlgorithm::Aes256Cbc,
    ContentEncryptionAlgorithm::Aes128Gcm,
    ContentEncryptionAlgorithm::Aes192Gcm,
    ContentEncryptionAlgorithm::Aes256Gcm,
];

const WRAPS: [KeyWrapAlgorithm; 3] = [
    KeyWrapAlgorithm::Aes128,
    KeyWrapAlgorithm::Aes192,
    KeyWrapAlgorithm::Aes256,
];

const DIGESTS: [DigestAlgorithm; 3] = [
    DigestAlgorithm::Sha256,
    DigestAlgorithm::Sha384,
    DigestAlgorithm::Sha512,
];

fn rng() -> Rng {
    UnwrapErr(SysRng)
}

/// RustCrypto for everything, over a PkiEnvironment of certval's software.
fn software() -> CmsEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut env = CmsEnvironment::new();
    env.populate_software();
    env.set_pki_environment(Arc::new(pe));
    env
}

/// This provider for everything it implements, with nothing to fall back to, over a PkiEnvironment
/// holding only this provider.
fn cng() -> CmsEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.add_calculate_hash_callback(CngCrypto::new());
    pe.add_verify_signature_message_callback(CngCrypto::new());
    pe.add_verify_signature_digest_callback(CngCrypto::new());
    let mut env = CmsEnvironment::new();
    env.set_pki_environment(Arc::new(pe));
    env.add_encrypt_content_callback(CngCrypto::new());
    env.add_decrypt_content_callback(CngCrypto::new());
    env.add_encrypt_key_transport_callback(CngCrypto::new());
    env.add_encrypt_key_agreement_callback(CngCrypto::new());
    env.add_encrypt_kem_callback(CngCrypto::new());
    env
}

/// Issues certificates with a subject key identifier from a throwaway P-256 CA.
struct Profile;

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        Name::from_str("CN=certval-cng test CA").unwrap()
    }
    fn get_subject(&self) -> Name {
        Name::from_str("CN=certval-cng test").unwrap()
    }
    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let skid = SubjectKeyIdentifier(
            OctetString::new(Sha1::digest(spk.subject_public_key.raw_bytes()).to_vec()).unwrap(),
        );
        Ok(vec![Extension {
            extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(skid.to_der().unwrap()).unwrap(),
        }])
    }
}

fn certificate(spki_der: &[u8]) -> Certificate {
    let ca = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    CertificateBuilder::new(
        Profile,
        SerialNumber::new(&[1]).unwrap(),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        SubjectPublicKeyInfoOwned::from_der(spki_der).unwrap(),
    )
    .unwrap()
    .build::<_, p256::ecdsa::DerSignature>(&ca)
    .unwrap()
}

/// A key generated in software, its certificate, and the key as PKCS #8.
struct Key {
    cert: Certificate,
    pkcs8: Vec<u8>,
}

impl Key {
    fn rsa() -> Self {
        let key = rsa::PrivateKey::new(&mut rng(), 2048).unwrap();
        let spki = key.to_public_key().to_public_key_der().unwrap();
        Self {
            cert: certificate(spki.as_bytes()),
            pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        }
    }
}

macro_rules! ec_key {
    ($curve:ident) => {{
        let key = $curve::SecretKey::generate_from_rng(&mut rng());
        let spki = key.public_key().to_public_key_der().unwrap();
        Key {
            cert: certificate(spki.as_bytes()),
            pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        }
    }};
}

fn envelop<'e>(
    env: &'e CmsEnvironment,
    alg: ContentEncryptionAlgorithm,
    recipient: impl certval_cms::RecipientInfoBuilder<Rng = Rng> + 'e,
) -> ContentInfo {
    if alg.is_authenticated() {
        certval_cms::AuthEnvelopedDataBuilder::new(MESSAGE, alg)
            .unwrap()
            .add_recipient(recipient)
            .build_content_info(env, &mut rng())
            .unwrap_or_else(|e| panic!("building: {e}"))
    } else {
        EnvelopedDataBuilder::new(MESSAGE, alg)
            .unwrap()
            .add_recipient(recipient)
            .build_content_info(env, &mut rng())
            .unwrap_or_else(|e| panic!("building: {e}"))
    }
}

fn assert_decrypts(
    env: &CmsEnvironment,
    ci: &ContentInfo,
    credential: &dyn RecipientCredential,
    name: &str,
) {
    let decrypted = env
        .decrypt_enveloped_data(ci, Some(credential))
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(decrypted.content.as_slice(), MESSAGE, "{name}");
}

#[test]
fn key_transport_with_each_algorithm_and_content_encryption() {
    let (software, platform) = (software(), cng());
    let key = Key::rsa();
    let (platform_key, _) = import_pkcs8(key.cert.clone(), &key.pkcs8).unwrap();
    let software_key = SoftwareRecipientKey::from_pkcs8_der(key.cert.clone(), &key.pkcs8).unwrap();
    for alg in [
        KeyTransportAlgorithm::RsaPkcs1v15,
        KeyTransportAlgorithm::RsaOaepSha1,
        KeyTransportAlgorithm::RsaOaepSha256,
        KeyTransportAlgorithm::RsaOaepSha384,
        KeyTransportAlgorithm::RsaOaepSha512,
    ] {
        for content in CONTENT {
            let name = format!("{alg:?} {content:?}");
            let r = KeyTransRecipient::from_certificate(&software, &key.cert, None, alg).unwrap();
            let ci = envelop(&software, content, r);
            assert_decrypts(
                &platform,
                &ci,
                &platform_key,
                &format!("software to CNG, {name}"),
            );

            let r = KeyTransRecipient::from_certificate(&platform, &key.cert, None, alg).unwrap();
            let ci = envelop(&platform, content, r);
            assert_decrypts(
                &software,
                &ci,
                &software_key,
                &format!("CNG to software, {name}"),
            );
        }
    }
}

fn key_agreement(key: Key, curve: &str) {
    let (software, platform) = (software(), cng());
    let (platform_key, _) = import_pkcs8(key.cert.clone(), &key.pkcs8).unwrap();
    let software_key = SoftwareRecipientKey::from_pkcs8_der(key.cert.clone(), &key.pkcs8).unwrap();
    for alg in [
        KeyAgreementAlgorithm::EcdhSha256,
        KeyAgreementAlgorithm::EcdhSha384,
        KeyAgreementAlgorithm::EcdhSha512,
    ] {
        for wrap in WRAPS {
            for ukm in [None, Some(b"user keying material".to_vec())] {
                let name = format!("{curve} {alg:?} {wrap:?} ukm={}", ukm.is_some());
                let r = KeyAgreeRecipient::from_certificate(
                    &software,
                    &key.cert,
                    None,
                    alg,
                    wrap,
                    ukm.clone(),
                )
                .unwrap();
                let ci = envelop(&software, ContentEncryptionAlgorithm::Aes256Gcm, r);
                assert_decrypts(
                    &platform,
                    &ci,
                    &platform_key,
                    &format!("software to CNG, {name}"),
                );

                let r =
                    KeyAgreeRecipient::from_certificate(&platform, &key.cert, None, alg, wrap, ukm)
                        .unwrap();
                let ci = envelop(&platform, ContentEncryptionAlgorithm::Aes128Cbc, r);
                assert_decrypts(
                    &software,
                    &ci,
                    &software_key,
                    &format!("CNG to software, {name}"),
                );
            }
        }
    }
}

#[test]
fn key_agreement_on_p256() {
    key_agreement(ec_key!(p256), "P-256");
}

#[test]
fn key_agreement_on_p384() {
    key_agreement(ec_key!(p384), "P-384");
}

#[test]
fn key_agreement_on_p521() {
    key_agreement(ec_key!(p521), "P-521");
}

fn assert_signs_across(
    signing: &CmsEnvironment,
    verifying: &CmsEnvironment,
    credential: &dyn SigningCredential,
    configure: impl Fn(Signer<'_>) -> Signer<'_>,
    name: &str,
) {
    let ci = SignedDataBuilder::new(MESSAGE)
        .add_signer(configure(Signer::explicit(credential)))
        .build(signing)
        .unwrap_or_else(|e| panic!("{name}: signing: {e}"))
        .content_info;
    let verified = verifying
        .verify_signed_data(&ci, None, None, SignerPolicy::All)
        .unwrap_or_else(|e| panic!("{name}: verifying: {e}"));
    assert_eq!(verified.content, MESSAGE, "{name}");
}

fn sign_both_ways(key: &Key, configure: impl Fn(Signer<'_>) -> Signer<'_> + Copy, name: &str) {
    let (software, platform) = (software(), cng());
    let (_, platform_key) = import_pkcs8(key.cert.clone(), &key.pkcs8).unwrap();
    let software_key = SoftwareSigningKey::from_pkcs8_der(key.cert.clone(), &key.pkcs8).unwrap();
    assert_signs_across(
        &platform,
        &software,
        &platform_key,
        configure,
        &format!("CNG signs, software verifies: {name}"),
    );
    assert_signs_across(
        &software,
        &platform,
        &software_key,
        configure,
        &format!("software signs, CNG verifies: {name}"),
    );
}

#[test]
fn rsa_pkcs1v15_and_pss_with_each_digest() {
    let key = Key::rsa();
    for digest in DIGESTS {
        sign_both_ways(
            &key,
            |s| s.digest(digest),
            &format!("PKCS #1 v1.5 {digest:?}"),
        );
        sign_both_ways(
            &key,
            |s| {
                s.digest(digest)
                    .signature_algorithm(rsa_pss(digest).unwrap())
            },
            &format!("PSS {digest:?}"),
        );
    }
}

#[test]
fn ecdsa_on_each_curve_with_each_digest() {
    for (key, curve) in [
        (ec_key!(p256), "P-256"),
        (ec_key!(p384), "P-384"),
        (ec_key!(p521), "P-521"),
    ] {
        for digest in DIGESTS {
            sign_both_ways(&key, |s| s.digest(digest), &format!("{curve} {digest:?}"));
        }
    }
}

// ---- keys without certificates

/// A key with no certificate signs its own certificate request through x509-cert's builder, with
/// only this provider registered, and software verifies it with the key's public key, which is the
/// one the request carries.
fn signs_its_request(
    key: &dyn certval_cms::SigningKey,
    digest: DigestAlgorithm,
    pss: bool,
    name: &str,
) {
    use certval_cms::{CredentialSignature, CredentialSigner};
    use x509_cert::request::RequestBuilder;
    let platform = cng();
    let signer = if pss {
        CredentialSigner::with_algorithm(&platform, key, digest, rsa_pss(digest).unwrap())
            .unwrap_or_else(|e| panic!("{name}: {e}"))
    } else {
        CredentialSigner::new(&platform, key, digest).unwrap_or_else(|e| panic!("{name}: {e}"))
    };
    let request = RequestBuilder::new(Name::from_str("CN=certval-cng request").unwrap())
        .unwrap()
        .build::<_, CredentialSignature>(&signer)
        .unwrap_or_else(|e| panic!("{name}: signing the request: {e}"));
    assert_eq!(&request.info.public_key, key.public_key(), "{name}");
    let software = software();
    let pe = software.pki_environment().unwrap();
    pe.verify_signature_message(
        pe,
        &request.info.to_der().unwrap(),
        &request.signature,
        &request.algorithm,
        &request.info.public_key,
    )
    .unwrap_or_else(|e| panic!("{name}: verifying the request: {e:?}"));
}

#[test]
fn imported_keys_without_certificates_sign_requests() {
    use certval_cms::SigningKey;
    use certval_cng::import_pkcs8_key;
    let rsa = Key::rsa();
    let key = import_pkcs8_key(&rsa.pkcs8).unwrap();
    // The public key CNG exports is the one the certificate carries.
    assert_eq!(
        key.public_key(),
        rsa.cert.tbs_certificate().subject_public_key_info(),
        "RSA"
    );
    for digest in DIGESTS {
        signs_its_request(&key, digest, false, &format!("RSA PKCS #1 v1.5 {digest:?}"));
        signs_its_request(&key, digest, true, &format!("RSA PSS {digest:?}"));
    }
    for (ec, curve) in [
        (ec_key!(p256), "P-256"),
        (ec_key!(p384), "P-384"),
        (ec_key!(p521), "P-521"),
    ] {
        let key = import_pkcs8_key(&ec.pkcs8).unwrap();
        assert_eq!(
            key.public_key(),
            ec.cert.tbs_certificate().subject_public_key_info(),
            "{curve}"
        );
        for digest in DIGESTS {
            signs_its_request(&key, digest, false, &format!("{curve} {digest:?}"));
        }
    }
}

// ---- ML-DSA, where this Windows' CNG offers it

#[cfg(feature = "pqc")]
mod cng_ml_dsa {
    use super::*;
    use certval_cms::SigningKey;
    use certval_cng::import_pkcs8_key;
    use ml_dsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
    use rand_core::Rng as _;
    use signature::Keypair;

    /// A software ML-DSA key as PKCS #8, and its certificate.
    macro_rules! ml_dsa_key {
        ($params:ty) => {{
            let mut seed = [0u8; 32];
            rng().fill_bytes(&mut seed);
            let key = ml_dsa::SigningKey::<$params>::from_seed(&seed.into());
            Key {
                cert: certificate(key.verifying_key().to_public_key_der().unwrap().as_bytes()),
                pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
            }
        }};
    }

    fn keys() -> [(Key, &'static str); 3] {
        [
            (ml_dsa_key!(MlDsa44), "ML-DSA-44"),
            (ml_dsa_key!(MlDsa65), "ML-DSA-65"),
            (ml_dsa_key!(MlDsa87), "ML-DSA-87"),
        ]
    }

    fn available() -> bool {
        let available = CngCrypto::ml_dsa_available();
        if !available {
            println!("ML-DSA: skipped, this Windows' CNG has no ML-DSA");
        }
        available
    }

    /// Runs `test` on a thread with an 8 MiB stack: software ML-DSA in a debug build exceeds the
    /// 2 MiB a test thread has by default.
    fn with_large_stack(test: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(test)
            .unwrap()
            .join()
            .unwrap();
    }

    /// CNG signs and software verifies, and software signs and CNG alone verifies: SignedData with
    /// signed attributes, pure ML-DSA over them, SHA-512 for their digest (RFC 9882).
    #[test]
    fn signs_and_verifies_with_each_parameter_set() {
        if !available() {
            return;
        }
        with_large_stack(|| {
            for (key, name) in keys() {
                sign_both_ways(&key, |s| s.digest(DigestAlgorithm::Sha512), name);
            }
        });
    }

    /// An ML-DSA key with no certificate signs its own certificate request, its public key the one
    /// the certificate carries.
    #[test]
    fn keys_without_certificates_sign_requests() {
        if !available() {
            return;
        }
        with_large_stack(|| {
            for (key, name) in keys() {
                let imported =
                    import_pkcs8_key(&key.pkcs8).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    imported.public_key(),
                    key.cert.tbs_certificate().subject_public_key_info(),
                    "{name}"
                );
                signs_its_request(&imported, DigestAlgorithm::Sha512, false, name);
            }
        });
    }
}

// ---- ML-KEM decryption, where this Windows' CNG offers it

#[cfg(feature = "pqc")]
mod cng_ml_kem {
    use super::*;
    use certval_cms::{EncryptKem, KdfAlgorithm, KemRecipient};
    use ml_kem::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use ml_kem::{Kem, MlKem1024, MlKem512, MlKem768};

    const KDFS: [KdfAlgorithm; 3] = [
        KdfAlgorithm::HkdfSha256,
        KdfAlgorithm::HkdfSha384,
        KdfAlgorithm::HkdfSha512,
    ];

    /// A software ML-KEM key as PKCS #8, and its certificate.
    macro_rules! ml_kem_key {
        ($kem:ty) => {{
            let (dk, ek) = <$kem as Kem>::generate_keypair_from_rng(&mut rng());
            Key {
                cert: certificate(ek.to_public_key_der().unwrap().as_bytes()),
                pkcs8: dk.to_pkcs8_der().unwrap().as_bytes().to_vec(),
            }
        }};
    }

    /// A message `env` encrypts to `key`'s certificate with `kdf`, `wrap`, `ukm` and `content`.
    fn kem_envelop(
        env: &CmsEnvironment,
        key: &Key,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        ukm: Option<Vec<u8>>,
        content: ContentEncryptionAlgorithm,
        case: &str,
    ) -> ContentInfo {
        let recipient = KemRecipient::from_certificate(env, &key.cert, None, kdf, wrap, ukm)
            .unwrap_or_else(|e| panic!("{case}: {e}"));
        envelop(env, content, recipient)
    }

    /// Every KDF and wrap, with and without user keying material, in CBC and GCM, three ways:
    /// software encrypts and a `CngRecipientKey` decrypts with only this provider registered; this
    /// provider alone encrypts, which it must since nothing else is registered, and software
    /// decrypts; and this provider encrypts and decrypts.
    fn crosses(key: &Key, name: &str) {
        let (software, platform) = (software(), cng());
        let (credential, _) =
            import_pkcs8(key.cert.clone(), &key.pkcs8).unwrap_or_else(|e| panic!("{name}: {e}"));
        let software_key = SoftwareRecipientKey::from_pkcs8_der(key.cert.clone(), &key.pkcs8)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        for kdf in KDFS {
            for wrap in WRAPS {
                for ukm in [None, Some(b"user keying material".to_vec())] {
                    for content in [
                        ContentEncryptionAlgorithm::Aes256Cbc,
                        ContentEncryptionAlgorithm::Aes256Gcm,
                    ] {
                        let case =
                            format!("{name} {kdf:?} {wrap:?} ukm={} {content:?}", ukm.is_some());
                        let ci =
                            kem_envelop(&software, key, kdf, wrap, ukm.clone(), content, &case);
                        assert_decrypts(
                            &platform,
                            &ci,
                            &credential,
                            &format!("software to CNG, {case}"),
                        );
                        let ci =
                            kem_envelop(&platform, key, kdf, wrap, ukm.clone(), content, &case);
                        assert_decrypts(
                            &software,
                            &ci,
                            &software_key,
                            &format!("CNG to software, {case}"),
                        );
                        assert_decrypts(
                            &platform,
                            &ci,
                            &credential,
                            &format!("CNG to CNG, {case}"),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn encrypts_and_decrypts_with_each_parameter_set() {
        if !CngCrypto::ml_kem_available() {
            println!("ML-KEM: skipped, this Windows' CNG has no ML-KEM");
            return;
        }
        for (key, name) in [
            (ml_kem_key!(MlKem512), "ML-KEM-512"),
            (ml_kem_key!(MlKem768), "ML-KEM-768"),
            (ml_kem_key!(MlKem1024), "ML-KEM-1024"),
        ] {
            crosses(&key, name);
        }
    }

    /// A key that is not ML-KEM, or a malformed one, is declined, so software can answer.
    #[test]
    fn a_key_other_than_ml_kem_is_declined() {
        let spki = Key::rsa()
            .cert
            .tbs_certificate()
            .subject_public_key_info()
            .clone();
        let result = CngCrypto::new().encrypt_kem(
            &cng(),
            KdfAlgorithm::HkdfSha256,
            KeyWrapAlgorithm::Aes256,
            &spki,
            None,
            &[0u8; 32],
        );
        assert!(
            matches!(result, Err(Error::Unrecognized)),
            "{:?}",
            result.err()
        );
    }

    /// A ciphertext changed in transit decapsulates, as ML-KEM's implicit rejection has it, to a
    /// different shared secret, so the key unwrap fails: an error, not a wrong key.
    #[test]
    fn a_changed_ciphertext_is_refused() {
        if !CngCrypto::ml_kem_available() {
            println!("ML-KEM: skipped, this Windows' CNG has no ML-KEM");
            return;
        }
        let key = ml_kem_key!(MlKem768);
        let (credential, _) = import_pkcs8(key.cert.clone(), &key.pkcs8).unwrap();
        let mut ct = vec![0u8; 1088];
        ct[0] = 1;
        let result = credential.decrypt_kem(
            &cng(),
            KdfAlgorithm::HkdfSha256,
            KeyWrapAlgorithm::Aes256,
            &ct,
            None,
            &[0u8; 40],
        );
        assert!(
            matches!(result, Err(Error::Crypto(_))),
            "{:?}",
            result.err()
        );
        let short = credential.decrypt_kem(
            &cng(),
            KdfAlgorithm::HkdfSha256,
            KeyWrapAlgorithm::Aes256,
            &ct[..1087],
            None,
            &[0u8; 40],
        );
        assert!(matches!(short, Err(Error::Crypto(_))), "{:?}", short.err());
    }
}

#[test]
fn aes_gcm_and_cbc_are_both_performed() {
    let platform = cng();
    for alg in CONTENT {
        assert!(
            !matches!(
                platform.encrypt_content(alg, MESSAGE, None),
                Err(Error::Unrecognized)
            ),
            "{alg:?}"
        );
    }
}
