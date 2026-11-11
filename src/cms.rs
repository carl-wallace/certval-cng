//! The provider's implementations of certval-cms's interfaces, under the `cms` feature: AES-CBC and
//! AES-GCM content encryption and decryption and RSA key transport by BCrypt; recipient and signing
//! credentials over NCrypt keys; and [`CertStoreIdentities`], which finds both in the current user's
//! certificate store, where CAPI and virtual smart card keys are found.
//!
//! CNG has no ANSI X9.63 KDF, so key agreement is split where certval-cms's helpers allow: BCrypt
//! or NCrypt performs the ECDH and returns the shared secret, from which
//! [`wrap_with_ecdh_secret`](certval_cms::wrap_with_ecdh_secret) wraps the content-encryption key,
//! or [`cek_from_ecdh_secret`](certval_cms::cek_from_ecdh_secret) recovers it.

use std::sync::Arc;

use certval_cms::{
    cek_from_ecdh_secret, cek_from_kem_secret, content_decryption_parameters, kem_other_info,
    recipient_matches, wrap_with_ecdh_secret, CmsEnvironment, ContentEncryptionAlgorithm,
    ContentEncryptionOutput, ContentParameters, DecryptContent, EncryptContent, EncryptKem,
    EncryptKeyAgreement, EncryptKeyTransport, Error, GcmParameters, KdfAlgorithm, KemOutput,
    KeyAgreeOutput, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
    RecipientCredential, RecipientCredentialSource, Result, SharedRecipientCredential,
    SharedSigningCredential, SigningCredential, SigningCredentialLookup, SigningCredentialSource,
    SigningKey,
};
use cms::enveloped_data::RecipientIdentifier;
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, ID_RSASSA_PSS, RSA_ENCRYPTION};
use der::{
    asn1::{Any, OctetString, Uint},
    Decode, Encode, Sequence, Tag,
};
use log::{debug, trace};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use windows_sys::core::{w, PCWSTR};
use windows_sys::Win32::Foundation::{
    NTSTATUS, STATUS_AUTH_TAG_MISMATCH, STATUS_INVALID_PARAMETER,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptDecrypt, BCryptDestroyKey, BCryptEncrypt, BCryptGenRandom, BCryptGenerateSymmetricKey,
    CertCloseStore, CertEnumCertificatesInStore, CertGetCertificateContextProperty,
    CertOpenSystemStoreW, CryptAcquireCertificatePrivateKey, NCryptDecrypt, NCryptDeriveKey,
    NCryptExportKey, NCryptFreeObject, NCryptGetProperty, NCryptImportKey, NCryptSecretAgreement,
    NCryptSignHash, BCRYPT_AES_CBC_ALG_HANDLE, BCRYPT_AES_GCM_ALG_HANDLE, BCRYPT_ALG_HANDLE,
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, BCRYPT_BLOCK_PADDING, BCRYPT_ECCPUBLIC_BLOB,
    BCRYPT_ECDH_PUBLIC_P256_MAGIC, BCRYPT_ECDH_PUBLIC_P384_MAGIC, BCRYPT_ECDH_PUBLIC_P521_MAGIC,
    BCRYPT_KDF_RAW_SECRET, BCRYPT_KEY_HANDLE, BCRYPT_OAEP_PADDING_INFO, BCRYPT_PAD_OAEP,
    BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO,
    BCRYPT_PUBLIC_KEY_BLOB, BCRYPT_RSAPUBLIC_BLOB, BCRYPT_USE_SYSTEM_PREFERRED_RNG, CERT_CONTEXT,
    CERT_KEY_PROV_INFO_PROP_ID, CERT_NCRYPT_KEY_SPEC, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
    CRYPT_ACQUIRE_SILENT_FLAG, NCRYPT_KEY_HANDLE, NCRYPT_PROVIDER_HANDLE_PROPERTY,
    NCRYPT_PROV_HANDLE, NCRYPT_SECRET_HANDLE,
};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use crate::algorithm::{signature_scheme, Hash, MlDsa, MlKem, Padding};
use crate::blob::{
    ecc_public_blob, ecc_spki_from_blob, ml_dsa_spki_from_blob, ml_kem_private_blob,
    ml_kem_public_blob, rsa_public_blob, rsa_spki_from_blob, Curve,
};
use crate::cng::{
    bcrypt_encapsulate, hash_name, import_ml_kem, import_rsa, ml_kem_private_blob_type,
    ncrypt_decapsulate, PqdsaPaddingInfo, PAD_PQDSA, PQDSA_PUBLIC_BLOB,
};
use crate::CngCrypto;

/// Length in octets of an AES-CBC IV.
const CBC_IV_LEN: usize = 16;
/// Length in octets of the GCM nonce generated for a message, the length RFC 5084 recommends.
const GCM_NONCE_LEN: usize = 12;
/// Length in octets of the GCM authentication tag produced for a message.
const GCM_TAG_LEN: usize = 16;

fn succeeded(status: i32) -> bool {
    status >= 0
}

fn content_decryption_failed() -> Error {
    Error::Crypto(String::from("content decryption failed"))
}

fn len32(buf: &[u8]) -> Result<u32> {
    u32::try_from(buf.len()).map_err(|_| Error::InvalidInput(String::from("input too long")))
}

fn random(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    // SAFETY: the buffer is live with the length passed; a null algorithm with
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG is the system's generator.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            len32(&buf)?,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if !succeeded(status) {
        return Err(Error::Crypto(format!("BCryptGenRandom: {status:#010x}")));
    }
    Ok(buf)
}

/// A BCrypt symmetric key, destroyed when dropped.
struct SymmetricKey(BCRYPT_KEY_HANDLE);

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        // SAFETY: the handle came from BCryptGenerateSymmetricKey and is destroyed once.
        unsafe { BCryptDestroyKey(self.0) };
    }
}

fn aes_key(gcm: bool, key: &[u8]) -> Result<SymmetricKey> {
    let algorithm = if gcm {
        BCRYPT_AES_GCM_ALG_HANDLE
    } else {
        BCRYPT_AES_CBC_ALG_HANDLE
    };
    symmetric_key(algorithm, key)
}

/// A BCrypt key of `algorithm` (a pseudo-handle) made from `secret`.
fn symmetric_key(algorithm: BCRYPT_ALG_HANDLE, key: &[u8]) -> Result<SymmetricKey> {
    let mut handle: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    // SAFETY: a null key object lets CNG allocate it; the secret is live with the length passed.
    let status = unsafe {
        BCryptGenerateSymmetricKey(
            algorithm,
            &mut handle,
            std::ptr::null_mut(),
            0,
            key.as_ptr(),
            len32(key)?,
            0,
        )
    };
    if !succeeded(status) || handle.is_null() {
        debug!("BCryptGenerateSymmetricKey declined: {status:#010x}");
        return Err(Error::Unrecognized);
    }
    Ok(SymmetricKey(handle))
}

/// HKDF (RFC 5869) by CNG: `len` octets from the input keying material `ikm`, with the salt absent
/// and `info`, as RFC 9629 has a KEMRecipientInfo's key-encryption key derived.
fn cng_hkdf(kdf: KdfAlgorithm, ikm: &[u8], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptBuffer, BCryptBufferDesc, BCryptKeyDerivation, BCryptSetProperty,
        BCRYPTBUFFER_VERSION, BCRYPT_HKDF_ALG_HANDLE, BCRYPT_HKDF_HASH_ALGORITHM,
        BCRYPT_HKDF_SALT_AND_FINALIZE, KDF_HKDF_INFO,
    };
    let hash = match kdf {
        KdfAlgorithm::HkdfSha256 => "SHA256",
        KdfAlgorithm::HkdfSha384 => "SHA384",
        KdfAlgorithm::HkdfSha512 => "SHA512",
        _ => return Err(Error::Unrecognized),
    };
    // The property takes the hash's CNG name as a wide string, its null terminator included.
    let hash: Vec<u16> = hash.encode_utf16().chain([0]).collect();
    let key = symmetric_key(BCRYPT_HKDF_ALG_HANDLE, ikm)?;
    let mut buffer = BCryptBuffer {
        cbBuffer: len32(info)?,
        BufferType: KDF_HKDF_INFO,
        pvBuffer: info.as_ptr().cast_mut().cast(),
    };
    let parameters = BCryptBufferDesc {
        ulVersion: BCRYPTBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut buffer,
    };
    let mut okm = Zeroizing::new(vec![0u8; len]);
    let mut written = 0u32;
    // SAFETY: the key is live; the hash name, the info and the output are live with the lengths
    // passed; a null salt, which the HKDF property allows, is the absent salt, and BCrypt only
    // reads the info buffer.
    let status = unsafe {
        let status = BCryptSetProperty(
            key.0,
            BCRYPT_HKDF_HASH_ALGORITHM,
            hash.as_ptr().cast(),
            u32::try_from(hash.len() * 2).unwrap_or(u32::MAX),
            0,
        );
        if !succeeded(status) {
            status
        } else {
            let status =
                BCryptSetProperty(key.0, BCRYPT_HKDF_SALT_AND_FINALIZE, std::ptr::null(), 0, 0);
            if !succeeded(status) {
                status
            } else {
                BCryptKeyDerivation(
                    key.0,
                    &parameters,
                    okm.as_mut_ptr(),
                    len32(&okm)?,
                    &mut written,
                    0,
                )
            }
        }
    };
    if !succeeded(status) || written as usize != len {
        debug!("CNG's HKDF declined: {status:#010x}");
        return Err(Error::Unrecognized);
    }
    Ok(okm)
}

/// AES key wrap (RFC 3394) by CNG: `cek` exported under `kek` as `BCRYPT_AES_WRAP_KEY_BLOB`. The
/// wrapping key must be in AES's default chaining mode, CBC: CNG refuses the export under an
/// ECB-mode key (`STATUS_INVALID_PARAMETER`), though the wrap uses no chaining mode of its own.
fn cng_aes_key_wrap(kek: &[u8], cek: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{BCryptExportKey, BCRYPT_AES_WRAP_KEY_BLOB};
    let kek = symmetric_key(BCRYPT_AES_CBC_ALG_HANDLE, kek)?;
    let cek_key = symmetric_key(BCRYPT_AES_CBC_ALG_HANDLE, cek)?;
    let mut wrapped = vec![0u8; cek.len() + 8];
    let mut written = 0u32;
    // SAFETY: both keys are live, and the output is live with the length passed; BCrypt reports
    // how many octets it wrote.
    let status = unsafe {
        BCryptExportKey(
            cek_key.0,
            kek.0,
            BCRYPT_AES_WRAP_KEY_BLOB,
            wrapped.as_mut_ptr(),
            len32(&wrapped)?,
            &mut written,
            0,
        )
    };
    if !succeeded(status) || written as usize != wrapped.len() {
        debug!("CNG's AES key wrap declined: {status:#010x}");
        return Err(Error::Unrecognized);
    }
    Ok(wrapped)
}

impl EncryptKem for CngCrypto {
    /// ML-KEM-512, -768 or -1024, where this Windows' CNG has ML-KEM, all by CNG:
    /// `BCryptEncapsulate` to the recipient's key, CNG's HKDF over the `CMSORIforKEMOtherInfo`
    /// (RFC 9629), and CNG's AES key wrap. The shared secret and key-encryption key pass through
    /// this process, as they do for AWS-LC and OpenSSL.
    fn encrypt_kem(
        &self,
        _env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KemOutput> {
        let Some((set, blob)) = ml_kem_public_blob(spki) else {
            return Err(Error::Unrecognized);
        };
        let Some(encapsulate) = bcrypt_encapsulate() else {
            return Err(Error::Unrecognized);
        };
        let Some(key) = import_ml_kem(&blob) else {
            return Err(Error::Unrecognized);
        };
        let mut ss = Zeroizing::new(vec![0u8; MlKem::SHARED_SECRET_LEN]);
        let mut ss_len = 0u32;
        let mut kem_ct = vec![0u8; set.ciphertext_len()];
        let mut kem_ct_len = 0u32;
        // SAFETY: the key is live, the function is bcrypt.dll's BCryptEncapsulate, and both outputs
        // are live with the lengths passed; BCrypt reports how many octets it wrote to each.
        let status = unsafe {
            encapsulate(
                key.handle(),
                ss.as_mut_ptr(),
                len32(&ss)?,
                &mut ss_len,
                kem_ct.as_mut_ptr(),
                len32(&kem_ct)?,
                &mut kem_ct_len,
                0,
            )
        };
        if !succeeded(status) || ss_len as usize != ss.len() || kem_ct_len as usize != kem_ct.len()
        {
            debug!("BCrypt could not encapsulate: {status:#010x}");
            return Err(Error::Unrecognized);
        }
        let info = kem_other_info(wrap, ukm)?;
        let kek = cng_hkdf(kdf, &ss, &info, wrap.kek_len())?;
        let encrypted_key = cng_aes_key_wrap(&kek, cek)?;
        trace!("CNG performed a {set:?} KEM with {kdf:?} and {wrap:?}");
        Ok(KemOutput {
            kem_ct,
            encrypted_key,
        })
    }
}

/// AES-CBC with PKCS #7 padding; `None` if BCrypt refuses, including malformed padding on
/// decryption.
/// AES-CBC with PKCS #7 padding, or the status BCrypt returned.
fn cbc(
    encrypt: bool,
    key: &SymmetricKey,
    iv: &[u8],
    input: &[u8],
) -> core::result::Result<Vec<u8>, NTSTATUS> {
    let mut iv = iv.to_vec();
    let mut output = vec![0u8; input.len() + CBC_IV_LEN];
    let mut written = 0u32;
    let (input_len, output_len, iv_len) = (
        u32::try_from(input.len()).map_err(|_| STATUS_INVALID_PARAMETER)?,
        u32::try_from(output.len()).map_err(|_| STATUS_INVALID_PARAMETER)?,
        u32::try_from(iv.len()).map_err(|_| STATUS_INVALID_PARAMETER)?,
    );
    // SAFETY: every buffer is live with the length passed; BCrypt updates the IV copy in place and
    // writes at most `output_len` octets, reporting how many.
    let status = unsafe {
        if encrypt {
            BCryptEncrypt(
                key.0,
                input.as_ptr(),
                input_len,
                std::ptr::null(),
                iv.as_mut_ptr(),
                iv_len,
                output.as_mut_ptr(),
                output_len,
                &mut written,
                BCRYPT_BLOCK_PADDING,
            )
        } else {
            BCryptDecrypt(
                key.0,
                input.as_ptr(),
                input_len,
                std::ptr::null(),
                iv.as_mut_ptr(),
                iv_len,
                output.as_mut_ptr(),
                output_len,
                &mut written,
                BCRYPT_BLOCK_PADDING,
            )
        }
    };
    if !succeeded(status) {
        debug!("BCrypt AES-CBC failed: {status:#010x}");
        return Err(status);
    }
    output.truncate(written as usize);
    Ok(output)
}

/// AES-GCM. On encryption `tag` receives the tag; on decryption it is checked. `None` if BCrypt
/// refuses, including a tag that does not verify.
/// AES-GCM, or the status BCrypt returned: `STATUS_AUTH_TAG_MISMATCH` when it checked the tag and
/// found it wrong, another status for a parameter it refused.
fn gcm(
    encrypt: bool,
    key: &SymmetricKey,
    nonce: &[u8],
    aad: &[u8],
    tag: &mut [u8],
    input: &[u8],
) -> core::result::Result<Vec<u8>, NTSTATUS> {
    let len32 = |n: usize| u32::try_from(n).map_err(|_| STATUS_INVALID_PARAMETER);
    let mut output = vec![0u8; input.len()];
    let mut written = 0u32;
    let info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: len32(std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>())?,
        dwInfoVersion: 1,
        pbNonce: nonce.as_ptr().cast_mut(),
        cbNonce: len32(nonce.len())?,
        pbAuthData: aad.as_ptr().cast_mut(),
        cbAuthData: len32(aad.len())?,
        pbTag: tag.as_mut_ptr(),
        cbTag: len32(tag.len())?,
        pbMacContext: std::ptr::null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    };
    let (input_len, output_len) = (len32(input.len())?, len32(output.len())?);
    // SAFETY: the mode info and every buffer it points to are live for the call; BCrypt writes at
    // most `output_len` octets, and on encryption the tag.
    let status = unsafe {
        if encrypt {
            BCryptEncrypt(
                key.0,
                input.as_ptr(),
                input_len,
                (&info as *const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO).cast(),
                std::ptr::null_mut(),
                0,
                output.as_mut_ptr(),
                output_len,
                &mut written,
                0,
            )
        } else {
            BCryptDecrypt(
                key.0,
                input.as_ptr(),
                input_len,
                (&info as *const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO).cast(),
                std::ptr::null_mut(),
                0,
                output.as_mut_ptr(),
                output_len,
                &mut written,
                0,
            )
        }
    };
    if !succeeded(status) {
        debug!("BCrypt AES-GCM failed: {status:#010x}");
        return Err(status);
    }
    output.truncate(written as usize);
    Ok(output)
}

impl EncryptContent for CngCrypto {
    /// AES-CBC and AES-GCM by BCrypt, with the key, IV and nonce from the system's generator.
    fn encrypt_content(
        &self,
        _env: &CmsEnvironment,
        alg: ContentEncryptionAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ContentEncryptionOutput> {
        if aad.is_some() && !alg.is_authenticated() {
            return Err(Error::InvalidInput(String::from(
                "associated data given for an algorithm that does not authenticate",
            )));
        }
        let key = random(alg.key_len())?;
        let handle = aes_key(alg.is_authenticated(), &key)?;
        let encrypted = if alg.is_authenticated() {
            let nonce = random(GCM_NONCE_LEN)?;
            let mut tag = vec![0u8; GCM_TAG_LEN];
            let ciphertext = gcm(
                true,
                &handle,
                &nonce,
                aad.unwrap_or_default(),
                &mut tag,
                plaintext,
            )
            .map_err(|_| Error::Crypto(String::from("content encryption failed")))?;
            let params = GcmParameters {
                nonce: OctetString::new(nonce.as_slice())?,
                icv_len: GCM_TAG_LEN as u8,
            };
            ContentEncryptionOutput {
                ciphertext,
                key,
                algorithm: AlgorithmIdentifierOwned {
                    oid: alg.oid(),
                    parameters: Some(Any::encode_from(&params)?),
                },
                tag: Some(tag),
            }
        } else {
            let iv = random(CBC_IV_LEN)?;
            let ciphertext = cbc(true, &handle, &iv, plaintext)
                .map_err(|_| Error::Crypto(String::from("content encryption failed")))?;
            ContentEncryptionOutput {
                ciphertext,
                key,
                algorithm: AlgorithmIdentifierOwned {
                    oid: alg.oid(),
                    parameters: Some(Any::new(Tag::OctetString, iv.as_slice())?),
                },
                tag: None,
            }
        };
        trace!("CNG encrypted content with {alg:?}");
        Ok(encrypted)
    }
}

impl DecryptContent for CngCrypto {
    /// AES-CBC and AES-GCM by BCrypt.
    fn decrypt_content(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (content_alg, parameters) = content_decryption_parameters(alg, key, aad, tag)?;
        let handle = aes_key(content_alg.is_authenticated(), key)?;
        let plaintext = match (parameters, tag) {
            (ContentParameters::Gcm { nonce }, Some(tag)) => {
                let mut tag = tag.to_vec();
                gcm(
                    false,
                    &handle,
                    &nonce,
                    aad.unwrap_or_default(),
                    &mut tag,
                    ciphertext,
                )
                .map_err(|status| {
                    // A tag BCrypt checked and found wrong is the verdict; a parameter it
                    // refused, e.g. a nonce of a length it does not take, is a decline, for
                    // another implementation to take up.
                    if status == STATUS_AUTH_TAG_MISMATCH {
                        content_decryption_failed()
                    } else {
                        Error::Unrecognized
                    }
                })?
            }
            (ContentParameters::Cbc { iv }, None) => {
                cbc(false, &handle, &iv, ciphertext).map_err(|_| content_decryption_failed())?
            }
            _ => return Err(Error::Unrecognized),
        };
        trace!("CNG decrypted content with {content_alg:?}");
        Ok(Zeroizing::new(plaintext))
    }
}

/// The OAEP hash a key transport algorithm uses, or `None` for RSAES-PKCS1-v1_5.
fn oaep_hash(alg: KeyTransportAlgorithm) -> Result<Option<Hash>> {
    match alg {
        KeyTransportAlgorithm::RsaPkcs1v15 => Ok(None),
        KeyTransportAlgorithm::RsaOaepSha1 => Ok(Some(Hash::Sha1)),
        KeyTransportAlgorithm::RsaOaepSha256 => Ok(Some(Hash::Sha256)),
        KeyTransportAlgorithm::RsaOaepSha384 => Ok(Some(Hash::Sha384)),
        KeyTransportAlgorithm::RsaOaepSha512 => Ok(Some(Hash::Sha512)),
        _ => Err(Error::Unrecognized),
    }
}

/// The padding information and flag for key transport. CNG's OAEP uses MGF1 with the same hash;
/// the label is empty (RFC 4055, section 4.1).
fn key_transport_padding(hash: Option<Hash>) -> (BCRYPT_OAEP_PADDING_INFO, u32) {
    match hash {
        Some(hash) => (
            BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: hash_name(hash),
                pbLabel: std::ptr::null_mut(),
                cbLabel: 0,
            },
            BCRYPT_PAD_OAEP,
        ),
        None => (
            BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: std::ptr::null(),
                pbLabel: std::ptr::null_mut(),
                cbLabel: 0,
            },
            BCRYPT_PAD_PKCS1,
        ),
    }
}

impl EncryptKeyTransport for CngCrypto {
    /// RSA key transport by BCrypt, to an `rsaEncryption` key.
    fn encrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        cek: &[u8],
    ) -> Result<Vec<u8>> {
        let hash = oaep_hash(alg)?;
        let blob = rsa_public_blob(spki, Padding::Pkcs1).ok_or(Error::Unrecognized)?;
        let key = import_rsa(&blob).ok_or(Error::Unrecognized)?;
        let (info, flag) = key_transport_padding(hash);
        let info_ptr: *const core::ffi::c_void = if hash.is_some() {
            (&info as *const BCRYPT_OAEP_PADDING_INFO).cast()
        } else {
            std::ptr::null()
        };
        let mut needed = 0u32;
        // SAFETY: the key is live and the padding info outlives the call; with no output buffer,
        // BCrypt reports the length the encrypted key needs, the modulus's.
        let status = unsafe {
            BCryptEncrypt(
                key.handle(),
                cek.as_ptr(),
                len32(cek)?,
                info_ptr,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                &mut needed,
                flag,
            )
        };
        if !succeeded(status) {
            debug!("BCrypt declined key transport: {status:#010x}");
            return Err(Error::Unrecognized);
        }
        let mut output = vec![0u8; needed as usize];
        let mut written = 0u32;
        // SAFETY: as above, and BCrypt writes at most the output's length, reporting how many
        // octets.
        let status = unsafe {
            BCryptEncrypt(
                key.handle(),
                cek.as_ptr(),
                len32(cek)?,
                info_ptr,
                std::ptr::null_mut(),
                0,
                output.as_mut_ptr(),
                len32(&output)?,
                &mut written,
                flag,
            )
        };
        if !succeeded(status) {
            debug!("BCrypt declined key transport: {status:#010x}");
            return Err(Error::Unrecognized);
        }
        output.truncate(written as usize);
        trace!("CNG performed key transport with {alg:?}");
        Ok(output)
    }
}

/// A BCrypt key pair or public key, destroyed when dropped.
struct AsymmetricKey(BCRYPT_KEY_HANDLE);

impl Drop for AsymmetricKey {
    fn drop(&mut self) {
        // SAFETY: the handle came from BCrypt and is destroyed once.
        unsafe { BCryptDestroyKey(self.0) };
    }
}

/// The BCrypt ECDH algorithm for a curve.
fn ecdh_algorithm(curve: Curve) -> windows_sys::Win32::Security::Cryptography::BCRYPT_ALG_HANDLE {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_ECDH_P256_ALG_HANDLE, BCRYPT_ECDH_P384_ALG_HANDLE, BCRYPT_ECDH_P521_ALG_HANDLE,
    };
    match curve {
        Curve::P256 => BCRYPT_ECDH_P256_ALG_HANDLE,
        Curve::P384 => BCRYPT_ECDH_P384_ALG_HANDLE,
        Curve::P521 => BCRYPT_ECDH_P521_ALG_HANDLE,
    }
}

/// The bit length CNG takes for a curve's key pair.
fn curve_bits(curve: Curve) -> u32 {
    match curve {
        Curve::P256 => 256,
        Curve::P384 => 384,
        Curve::P521 => 521,
    }
}

/// Ephemeral-static ECDH by BCrypt: a fresh key pair on `curve`, its public point uncompressed,
/// and the shared secret with `recipient_blob`, an ECDH public key blob, big-endian.
fn bcrypt_ecdh(curve: Curve, recipient_blob: &[u8]) -> Option<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptDeriveKey, BCryptDestroySecret, BCryptExportKey, BCryptFinalizeKeyPair,
        BCryptGenerateKeyPair, BCryptImportKeyPair, BCryptSecretAgreement, BCRYPT_SECRET_HANDLE,
    };
    let algorithm = ecdh_algorithm(curve);
    let field_len = curve.field_len();
    let mut ephemeral: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    let mut recipient: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    let mut blob = vec![0u8; 8 + 2 * field_len];
    let mut blob_len = 0u32;
    let mut z = Zeroizing::new(vec![0u8; field_len]);
    let mut z_len = 0u32;
    // SAFETY: each handle is written by BCrypt and destroyed by its owner below; every buffer is
    // live with the length passed.
    let status = unsafe {
        let mut status = BCryptGenerateKeyPair(algorithm, &mut ephemeral, curve_bits(curve), 0);
        if succeeded(status) {
            let _ephemeral_owner = AsymmetricKey(ephemeral);
            status = BCryptFinalizeKeyPair(ephemeral, 0);
            if succeeded(status) {
                status = BCryptExportKey(
                    ephemeral,
                    std::ptr::null_mut(),
                    BCRYPT_ECCPUBLIC_BLOB,
                    blob.as_mut_ptr(),
                    u32::try_from(blob.len()).ok()?,
                    &mut blob_len,
                    0,
                );
            }
            if succeeded(status) {
                status = BCryptImportKeyPair(
                    algorithm,
                    std::ptr::null_mut(),
                    BCRYPT_ECCPUBLIC_BLOB,
                    &mut recipient,
                    recipient_blob.as_ptr(),
                    u32::try_from(recipient_blob.len()).ok()?,
                    0,
                );
            }
            if succeeded(status) {
                let _recipient_owner = AsymmetricKey(recipient);
                let mut secret: BCRYPT_SECRET_HANDLE = std::ptr::null_mut();
                status = BCryptSecretAgreement(ephemeral, recipient, &mut secret, 0);
                if succeeded(status) {
                    status = BCryptDeriveKey(
                        secret,
                        BCRYPT_KDF_RAW_SECRET,
                        std::ptr::null(),
                        z.as_mut_ptr(),
                        u32::try_from(z.len()).ok()?,
                        &mut z_len,
                        0,
                    );
                    BCryptDestroySecret(secret);
                }
            }
        }
        status
    };
    if !succeeded(status) {
        debug!("BCrypt could not perform ECDH: {status:#010x}");
        return None;
    }
    // The exported blob is the magic and length, then X and Y.
    let mut point = Vec::with_capacity(1 + 2 * field_len);
    point.push(0x04);
    point.extend_from_slice(blob.get(8..8 + 2 * field_len)?);
    z.truncate(z_len as usize);
    // BCRYPT_KDF_RAW_SECRET returns the shared secret little-endian.
    z.reverse();
    Some((point, z))
}

impl EncryptKeyAgreement for CngCrypto {
    /// Ephemeral-static ECDH on P-256, P-384 or P-521 by BCrypt, then the X9.63 KDF and AES key
    /// wrap by certval-cms, CNG having no X9.63 KDF.
    fn encrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KeyAgreeOutput> {
        let (curve, mut blob) = ecc_public_blob(spki).ok_or(Error::Unrecognized)?;
        blob[..4].copy_from_slice(&ecdh_magic(curve).to_le_bytes());
        let (ephemeral_public_key, z) = bcrypt_ecdh(curve, &blob).ok_or(Error::Unrecognized)?;
        let encrypted_key = wrap_with_ecdh_secret(alg, wrap, &z, ukm, cek)?;
        trace!("CNG performed key agreement with {alg:?} and {wrap:?}");
        Ok(KeyAgreeOutput {
            ephemeral_public_key,
            encrypted_key,
        })
    }
}

/// An NCrypt key, freed when dropped. NCrypt key handles may be used from any thread.
struct NcryptKey(NCRYPT_KEY_HANDLE);

// SAFETY: an NCrypt key handle is an opaque value NCrypt serializes access to.
unsafe impl Send for NcryptKey {}
// SAFETY: as for Send.
unsafe impl Sync for NcryptKey {}

impl Drop for NcryptKey {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and freed once.
        unsafe { NCryptFreeObject(self.0) };
    }
}

/// An NCrypt secret, freed when dropped.
struct NcryptSecret(NCRYPT_SECRET_HANDLE);

impl Drop for NcryptSecret {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and freed once.
        unsafe { NCryptFreeObject(self.0) };
    }
}

/// `BCRYPT_ECDH_PUBLIC_*_MAGIC` for a curve: an ECDH public key blob is laid out as an ECDSA one,
/// with a magic of its own.
fn ecdh_magic(curve: Curve) -> u32 {
    match curve {
        Curve::P256 => BCRYPT_ECDH_PUBLIC_P256_MAGIC,
        Curve::P384 => BCRYPT_ECDH_PUBLIC_P384_MAGIC,
        Curve::P521 => BCRYPT_ECDH_PUBLIC_P521_MAGIC,
    }
}

/// A [`RecipientCredential`] whose private key is an NCrypt key, e.g. one in a certificate store or
/// on a smart card: RSA key transport by `NCryptDecrypt`, and ECDH by `NCryptSecretAgreement`, the
/// shared secret then taken to the content-encryption key by certval-cms.
pub struct CngRecipientKey {
    certificate: Certificate,
    key: Arc<NcryptKey>,
}

impl CngRecipientKey {
    fn key_algorithm(&self) -> const_oid::ObjectIdentifier {
        self.certificate
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid
    }
}

impl RecipientCredential for CngRecipientKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.key_algorithm() != RSA_ENCRYPTION {
            return Err(Error::Unrecognized);
        }
        let hash = oaep_hash(alg)?;
        let (info, flag) = key_transport_padding(hash);
        let info_ptr: *const core::ffi::c_void = if hash.is_some() {
            (&info as *const BCRYPT_OAEP_PADDING_INFO).cast()
        } else {
            std::ptr::null()
        };
        let mut output = Zeroizing::new(vec![0u8; encrypted_key.len()]);
        let mut written = 0u32;
        // SAFETY: the key is live, the padding info outlives the call, and NCrypt writes at most
        // the output's length, reporting how many octets.
        let status = unsafe {
            NCryptDecrypt(
                self.key.0,
                encrypted_key.as_ptr(),
                len32(encrypted_key)?,
                info_ptr,
                output.as_mut_ptr(),
                len32(&output)?,
                &mut written,
                flag,
            )
        };
        if !succeeded(status) {
            debug!("NCrypt could not decrypt a key transport: {status:#010x}");
            return Err(Error::Crypto(String::from("key transport failed")));
        }
        output.truncate(written as usize);
        trace!("CNG decrypted a key transport with {alg:?}");
        Ok(output)
    }

    fn decrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        originator: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.key_algorithm() != ID_EC_PUBLIC_KEY {
            return Err(Error::Unrecognized);
        }
        // The originator's ephemeral key is on the recipient's curve, which its algorithm
        // identifier need not name (RFC 5753), so the recipient's names it.
        let on_recipient_curve = SubjectPublicKeyInfoOwned {
            algorithm: self
                .certificate
                .tbs_certificate()
                .subject_public_key_info()
                .algorithm
                .clone(),
            subject_public_key: originator.subject_public_key.clone(),
        };
        let (curve, mut blob) = ecc_public_blob(&on_recipient_curve)
            .ok_or_else(|| Error::Crypto(String::from("key agreement failed")))?;
        blob[..4].copy_from_slice(&ecdh_magic(curve).to_le_bytes());

        // The originator's key is imported into the recipient key's own provider.
        let mut provider: NCRYPT_PROV_HANDLE = 0;
        let mut provider_len = 0u32;
        let mut originator_key: NCRYPT_KEY_HANDLE = 0;
        let mut secret: NCRYPT_SECRET_HANDLE = 0;
        let mut z = Zeroizing::new(vec![0u8; curve.field_len()]);
        let mut z_len = 0u32;
        // SAFETY: each handle is written by NCrypt and freed below or by its owner; every buffer is
        // live with the length passed.
        let status = unsafe {
            let status = NCryptGetProperty(
                self.key.0,
                NCRYPT_PROVIDER_HANDLE_PROPERTY,
                (&mut provider as *mut NCRYPT_PROV_HANDLE).cast(),
                u32::try_from(std::mem::size_of::<NCRYPT_PROV_HANDLE>()).unwrap_or(8),
                &mut provider_len,
                0,
            );
            if !succeeded(status) {
                status
            } else {
                let status = NCryptImportKey(
                    provider,
                    0,
                    BCRYPT_ECCPUBLIC_BLOB,
                    std::ptr::null(),
                    &mut originator_key,
                    blob.as_ptr(),
                    len32(&blob)?,
                    0,
                );
                NCryptFreeObject(provider);
                if !succeeded(status) {
                    status
                } else {
                    let originator_key = NcryptKey(originator_key);
                    let status =
                        NCryptSecretAgreement(self.key.0, originator_key.0, &mut secret, 0);
                    if !succeeded(status) {
                        status
                    } else {
                        let secret = NcryptSecret(secret);
                        NCryptDeriveKey(
                            secret.0,
                            BCRYPT_KDF_RAW_SECRET,
                            std::ptr::null(),
                            z.as_mut_ptr(),
                            len32(&z)?,
                            &mut z_len,
                            0,
                        )
                    }
                }
            }
        };
        if !succeeded(status) {
            debug!("NCrypt could not perform key agreement: {status:#010x}");
            return Err(Error::Crypto(String::from("key agreement failed")));
        }
        z.truncate(z_len as usize);
        // BCRYPT_KDF_RAW_SECRET returns the shared secret little-endian.
        z.reverse();
        let cek = cek_from_ecdh_secret(alg, wrap, &z, ukm, encrypted_key)?;
        trace!("CNG decrypted a key agreement with {alg:?} and {wrap:?}");
        Ok(cek)
    }

    /// ML-KEM-512, -768 or -1024: `NCryptDecapsulate` recovers the shared secret, from which
    /// certval-cms's `cek_from_kem_secret` derives the key-encryption key and unwraps the
    /// content-encryption key. The shared secret therefore leaves CNG, as it leaves a PKCS #11
    /// token.
    fn decrypt_kem(
        &self,
        _env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        kem_ct: &[u8],
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let Some(set) = MlKem::from_oid(&self.key_algorithm()) else {
            return Err(Error::Unrecognized);
        };
        let Some(decapsulate) = ncrypt_decapsulate() else {
            return Err(Error::Unrecognized);
        };
        if kem_ct.len() != set.ciphertext_len() {
            return Err(Error::Crypto(String::from(
                "the KEM ciphertext is not the recipient's parameter set's length",
            )));
        }
        let mut ss = Zeroizing::new(vec![0u8; MlKem::SHARED_SECRET_LEN]);
        let mut written = 0u32;
        // SAFETY: the key is live, the function is ncrypt.dll's NCryptDecapsulate, and both buffers
        // are live with the lengths passed; NCrypt reports how many octets it wrote.
        let status = unsafe {
            decapsulate(
                self.key.0,
                kem_ct.as_ptr(),
                len32(kem_ct)?,
                ss.as_mut_ptr(),
                len32(&ss)?,
                &mut written,
                0,
            )
        };
        if !succeeded(status) {
            debug!("NCrypt could not decapsulate: {status:#010x}");
            return Err(Error::Crypto(String::from("KEM decapsulation failed")));
        }
        ss.truncate(written as usize);
        let cek = cek_from_kem_secret(kdf, wrap, &ss, ukm, encrypted_key)?;
        trace!("CNG decapsulated a {set:?} KEM with {kdf:?} and {wrap:?}");
        Ok(cek)
    }
}

/// An ECDSA signature as CMS carries it.
#[derive(Sequence)]
struct EcdsaSignature {
    r: Uint,
    s: Uint,
}

/// A [`SigningCredential`] whose private key is an NCrypt key, by `NCryptSignHash`: RSA PKCS #1
/// v1.5 or RSASSA-PSS, or ECDSA, over a digest the environment's `PkiEnvironment` computes, and
/// pure ML-DSA, where this Windows' CNG offers it, over the message.
pub struct CngSigningKey {
    certificate: Certificate,
    key: Arc<NcryptKey>,
}

impl CngSigningKey {
    fn key_algorithm(&self) -> const_oid::ObjectIdentifier {
        self.certificate
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid
    }
}

impl SigningCredential for CngSigningKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        ncrypt_sign_message(&self.key, self.key_algorithm(), alg, message)
    }

    fn sign_digest(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        ncrypt_sign_digest(&self.key, self.key_algorithm(), alg, digest)
    }
}

/// A [`SigningKey`] whose private key is an NCrypt key, with no certificate: e.g. a key signing its
/// own certificate request or a self-signed certificate. It signs as [`CngSigningKey`] does, and
/// its public key is the one CNG exports for it.
pub struct CngKey {
    public_key: SubjectPublicKeyInfoOwned,
    key: Arc<NcryptKey>,
}

impl CngKey {
    /// A key for `key`, its public key read back from CNG: RSA, EC on P-256, P-384 or P-521, or
    /// ML-DSA. Any other key is declined.
    fn new(key: NcryptKey) -> Result<Self> {
        let public_key = export_public(&key, BCRYPT_RSAPUBLIC_BLOB)
            .and_then(|blob| rsa_spki_from_blob(&blob))
            .or_else(|| {
                export_public(&key, BCRYPT_ECCPUBLIC_BLOB)
                    .and_then(|blob| ecc_spki_from_blob(&blob))
            })
            .or_else(|| {
                // NCrypt's generic public key blob for a post-quantum key is the BCrypt one.
                export_public(&key, PQDSA_PUBLIC_BLOB)
                    .or_else(|| export_public(&key, BCRYPT_PUBLIC_KEY_BLOB))
                    .and_then(|blob| ml_dsa_spki_from_blob(&blob))
            })
            .ok_or(Error::Unrecognized)?;
        Ok(Self {
            public_key,
            key: Arc::new(key),
        })
    }
}

impl SigningKey for CngKey {
    fn public_key(&self) -> &SubjectPublicKeyInfoOwned {
        &self.public_key
    }

    fn sign_digest(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        ncrypt_sign_digest(&self.key, self.public_key.algorithm.oid, alg, digest)
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        ncrypt_sign_message(&self.key, self.public_key.algorithm.oid, alg, message)
    }
}

/// Signs `message` with the NCrypt `key`, whose public key is identified as `key_alg`: pure
/// ML-DSA with an empty context string, by `NCryptSignHash`, which takes the message itself.
/// `alg` must name the key's parameter set. Anything else is declined, for RSA and ECDSA sign
/// a digest.
fn ncrypt_sign_message(
    key: &NcryptKey,
    key_alg: const_oid::ObjectIdentifier,
    alg: &AlgorithmIdentifierOwned,
    message: &[u8],
) -> Result<Vec<u8>> {
    let Some(set) = MlDsa::from_algorithm(alg) else {
        return Err(Error::Unrecognized);
    };
    if set.oid() != key_alg {
        return Err(Error::Unrecognized);
    }
    let padding = PqdsaPaddingInfo::pure();
    let mut signature = vec![0u8; set.signature_len()];
    let mut written = 0u32;
    // SAFETY: the key is live, the padding info outlives the call, and NCrypt writes at most the
    // signature buffer's length, reporting how many octets.
    let status = unsafe {
        NCryptSignHash(
            key.0,
            (&padding as *const PqdsaPaddingInfo).cast(),
            message.as_ptr(),
            len32(message)?,
            signature.as_mut_ptr(),
            len32(&signature)?,
            &mut written,
            PAD_PQDSA,
        )
    };
    if !succeeded(status) {
        debug!("NCrypt could not sign with ML-DSA: {status:#010x}");
        return Err(Error::Crypto(String::from("signing failed")));
    }
    signature.truncate(written as usize);
    trace!("CNG signed with {}", alg.oid);
    Ok(signature)
}

/// The public half of `key` as a `blob_type` blob, or `None` when NCrypt does not export it as
/// one, e.g. an RSA blob for an EC key.
fn export_public(key: &NcryptKey, blob_type: PCWSTR) -> Option<Vec<u8>> {
    let mut len = 0u32;
    // SAFETY: the key is live; a null output buffer asks only for the length.
    let status = unsafe {
        NCryptExportKey(
            key.0,
            0,
            blob_type,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            &mut len,
            0,
        )
    };
    if !succeeded(status) || len == 0 {
        return None;
    }
    let mut blob = vec![0u8; len as usize];
    // SAFETY: the key is live and the buffer is live with the length passed; NCrypt reports how
    // many octets it wrote.
    let status = unsafe {
        NCryptExportKey(
            key.0,
            0,
            blob_type,
            std::ptr::null(),
            blob.as_mut_ptr(),
            len,
            &mut len,
            0,
        )
    };
    if !succeeded(status) {
        debug!("NCrypt could not export a public key: {status:#010x}");
        return None;
    }
    blob.truncate(len as usize);
    Some(blob)
}

/// Signs `digest` with the NCrypt `key`, whose public key is identified as `key_alg`: RSA PKCS #1
/// v1.5 or RSASSA-PSS, or ECDSA, by `NCryptSignHash`, as `alg` says. Anything else is declined.
fn ncrypt_sign_digest(
    key: &NcryptKey,
    key_alg: const_oid::ObjectIdentifier,
    alg: &AlgorithmIdentifierOwned,
    digest: &[u8],
) -> Result<Vec<u8>> {
    let Some(scheme) = signature_scheme(alg) else {
        return Err(Error::Unrecognized);
    };
    if digest.len() != scheme.hash.len() {
        return Err(Error::Unrecognized);
    }
    let fits = match scheme.padding {
        Padding::Pkcs1 => key_alg == RSA_ENCRYPTION,
        Padding::Pss { .. } => key_alg == RSA_ENCRYPTION || key_alg == ID_RSASSA_PSS,
        Padding::Ecdsa => key_alg == ID_EC_PUBLIC_KEY,
    };
    if !fits {
        return Err(Error::Unrecognized);
    }
    let pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: hash_name(scheme.hash),
    };
    let pss = BCRYPT_PSS_PADDING_INFO {
        pszAlgId: hash_name(scheme.hash),
        cbSalt: match scheme.padding {
            Padding::Pss { salt_len } => salt_len,
            _ => 0,
        },
    };
    let (info, flag): (*const core::ffi::c_void, u32) = match scheme.padding {
        Padding::Pkcs1 => (
            (&pkcs1 as *const BCRYPT_PKCS1_PADDING_INFO).cast(),
            BCRYPT_PAD_PKCS1,
        ),
        Padding::Pss { .. } => (
            (&pss as *const BCRYPT_PSS_PADDING_INFO).cast(),
            BCRYPT_PAD_PSS,
        ),
        Padding::Ecdsa => (std::ptr::null(), 0),
    };
    let mut needed = 0u32;
    // SAFETY: the key is live and the padding info outlives the call; with no signature buffer,
    // NCrypt reports the length the signature needs, from the key's size.
    let status = unsafe {
        NCryptSignHash(
            key.0,
            info,
            digest.as_ptr(),
            len32(digest)?,
            std::ptr::null_mut(),
            0,
            &mut needed,
            flag,
        )
    };
    if !succeeded(status) {
        debug!("NCrypt could not size a signature: {status:#010x}");
        return Err(Error::Crypto(String::from("signing failed")));
    }
    let mut signature = vec![0u8; needed as usize];
    let mut written = 0u32;
    // SAFETY: as above, and NCrypt writes at most the signature buffer's length, reporting how
    // many octets.
    let status = unsafe {
        NCryptSignHash(
            key.0,
            info,
            digest.as_ptr(),
            len32(digest)?,
            signature.as_mut_ptr(),
            len32(&signature)?,
            &mut written,
            flag,
        )
    };
    if !succeeded(status) {
        debug!("NCrypt could not sign: {status:#010x}");
        return Err(Error::Crypto(String::from("signing failed")));
    }
    signature.truncate(written as usize);
    if scheme.padding == Padding::Ecdsa {
        // CNG gives ECDSA as fixed-width r‖s; CMS carries it DER-encoded.
        let (r, s) = signature.split_at(signature.len() / 2);
        signature = EcdsaSignature {
            r: Uint::new(r)?,
            s: Uint::new(s)?,
        }
        .to_der()?;
    }
    trace!("CNG signed with {}", alg.oid);
    Ok(signature)
}

/// The current user's personal certificate store ("MY"), each certificate there with an NCrypt
/// private key a credential, as a source of both recipient and signing credentials. A decryption
/// key is found by its certificate's issuer and serial number or subject key identifier, and
/// signing keys by any [`SigningCredentialLookup`].
#[derive(Clone, Copy, Debug, Default)]
pub struct CertStoreIdentities {
    _private: (),
}

impl CertStoreIdentities {
    /// A source over the current user's personal certificate store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Calls `visit` with each certificate in the store that decodes, and its context, which is
    /// live for the call.
    fn visit(mut visit: impl FnMut(Certificate, *const CERT_CONTEXT)) -> Result<()> {
        const MY: PCWSTR = w!("MY");
        // SAFETY: a zero provider is the default; the store is closed below.
        let store = unsafe { CertOpenSystemStoreW(0, MY) };
        if store.is_null() {
            return Err(Error::Crypto(String::from(
                "the certificate store could not be opened",
            )));
        }
        let mut context: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            // SAFETY: the store is open; enumeration frees the previous context.
            context = unsafe { CertEnumCertificatesInStore(store, context) };
            if context.is_null() {
                break;
            }
            // SAFETY: the context is live until the next enumeration or its free, and its encoded
            // certificate is live with it.
            let encoded = unsafe {
                std::slice::from_raw_parts(
                    (*context).pbCertEncoded,
                    (*context).cbCertEncoded as usize,
                )
            };
            if let Ok(certificate) = Certificate::from_der(encoded) {
                visit(certificate, context);
            }
        }
        // SAFETY: the store is closed once.
        unsafe { CertCloseStore(store, 0) };
        Ok(())
    }

    /// Every certificate in the store that `matches` and has an NCrypt private key, with that key.
    /// The key is opened silently: one whose provider would put up a dialog to open it, e.g. for a
    /// smart card that is not inserted, is passed over.
    fn find(
        &self,
        matches: impl Fn(&Certificate) -> bool,
    ) -> Result<Vec<(Certificate, NcryptKey)>> {
        let mut found = vec![];
        Self::visit(|certificate, context| {
            if !matches(&certificate) {
                return;
            }
            let mut key = 0usize;
            let mut key_spec = 0u32;
            let mut caller_frees = 0i32;
            // SAFETY: the context is live; NCrypt writes the handle and whether the caller owns it.
            let acquired = unsafe {
                CryptAcquireCertificatePrivateKey(
                    context,
                    CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                    std::ptr::null(),
                    &mut key,
                    &mut key_spec,
                    &mut caller_frees,
                )
            };
            if acquired == 0 || key_spec != CERT_NCRYPT_KEY_SPEC {
                return;
            }
            if caller_frees == 0 {
                // The handle is the certificate context's and goes with it, so it cannot be
                // held past this call.
                debug!(
                    "passing over a certificate whose key handle the store owns: {}",
                    certificate.tbs_certificate().subject()
                );
                return;
            }
            found.push((certificate, NcryptKey(key)));
        })?;
        Ok(found)
    }

    /// Every certificate in the store with a private key reference, for a caller to list or choose
    /// among. No key is opened, so the list is made without dialogs and holds certificates whose
    /// keys are on smart cards not inserted; whether a key opens is learned when a credential for
    /// its certificate is found through either source interface, by its identifier.
    pub fn certificates(&self) -> Result<Vec<Certificate>> {
        let mut found = vec![];
        Self::visit(|certificate, context| {
            let mut size = 0u32;
            // SAFETY: the context is live; with no buffer, the call reports whether the property
            // is present and its size.
            let has_key = unsafe {
                CertGetCertificateContextProperty(
                    context,
                    CERT_KEY_PROV_INFO_PROP_ID,
                    std::ptr::null_mut(),
                    &mut size,
                )
            } != 0;
            if has_key {
                found.push(certificate);
            }
        })?;
        Ok(found)
    }
}

impl RecipientCredentialSource for CertStoreIdentities {
    fn find_recipient_credential(
        &self,
        _env: &CmsEnvironment,
        rid: &RecipientIdentifier,
    ) -> Result<Option<SharedRecipientCredential>> {
        Ok(self
            .find(|c| recipient_matches(rid, c))?
            .into_iter()
            .next()
            .map(|(certificate, key)| {
                Arc::new(CngRecipientKey {
                    certificate,
                    key: Arc::new(key),
                }) as SharedRecipientCredential
            }))
    }
}

impl SigningCredentialSource for CertStoreIdentities {
    fn find_signing_credentials(
        &self,
        _env: &CmsEnvironment,
        lookup: SigningCredentialLookup<'_>,
    ) -> Result<Vec<SharedSigningCredential>> {
        Ok(self
            .find(|c| lookup.matches(c))?
            .into_iter()
            .map(|(certificate, key)| {
                Arc::new(CngSigningKey {
                    certificate,
                    key: Arc::new(key),
                }) as SharedSigningCredential
            })
            .collect())
    }
}

/// Credentials for a key imported into the Microsoft Software Key Storage Provider from PKCS #8,
/// e.g. for testing, or for a key held in software that should be used through CNG. An ML-KEM
/// key, whose PKCS #8 form the provider does not import, goes in as CNG's own seed or
/// decapsulation-key blob, in whichever of RFC 9935's forms the PKCS #8 holds it.
pub fn import_pkcs8(
    certificate: Certificate,
    pkcs8: &[u8],
) -> Result<(CngRecipientKey, CngSigningKey)> {
    let key = Arc::new(import_into_software_ksp(pkcs8)?);
    Ok((
        CngRecipientKey {
            certificate: certificate.clone(),
            key: key.clone(),
        },
        CngSigningKey { certificate, key },
    ))
}

/// Imports the PKCS #8 (RFC 5958) private key `pkcs8`, RSA, EC on P-256, P-384 or P-521, or ML-DSA
/// where this Windows' CNG offers it, into the Microsoft Software Key Storage Provider, as a key
/// with no certificate, e.g. to sign its own certificate request. The key is not persisted. CNG
/// derives the public key from the private one, so an EC key need not carry its public key. A key
/// of another type, including ML-KEM, which cannot sign, is declined.
pub fn import_pkcs8_key(pkcs8: &[u8]) -> Result<CngKey> {
    CngKey::new(import_into_software_ksp(pkcs8)?)
}

/// Imports `pkcs8` into the Microsoft Software Key Storage Provider, as an unnamed key that is not
/// persisted: as PKCS #8, which the provider finalizes after import, except an ML-KEM key, which
/// the provider's PKCS #8 import does not take and so goes in as CNG's own seed or
/// decapsulation-key blob (`BCRYPT_MLKEM_KEY_BLOB`), as .NET's ML-KEM does.
fn import_into_software_ksp(pkcs8: &[u8]) -> Result<NcryptKey> {
    use certval_cms::SeedOrExpandedKey;
    use pkcs8::PrivateKeyInfoRef;
    use windows_sys::Win32::Security::Cryptography::{
        NCryptFinalizeKey, NCryptOpenStorageProvider, MS_KEY_STORAGE_PROVIDER,
        NCRYPT_DO_NOT_FINALIZE_FLAG, NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
    };
    let info = PrivateKeyInfoRef::from_der(pkcs8)?;
    let ml_kem_blob;
    let (blob_type, blob, flags): (PCWSTR, &[u8], u32) = match MlKem::from_oid(&info.algorithm.oid)
    {
        Some(set) => {
            let key = SeedOrExpandedKey::from_der(info.private_key.as_bytes())?;
            let (kind, blob) = ml_kem_private_blob(set, &key).ok_or_else(|| {
                Error::InvalidInput(String::from(
                    "an ML-KEM private key is not its parameter set's length",
                ))
            })?;
            ml_kem_blob = blob;
            (ml_kem_private_blob_type(kind), &ml_kem_blob, 0)
        }
        None => (
            NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
            pkcs8,
            NCRYPT_DO_NOT_FINALIZE_FLAG,
        ),
    };
    let finalize = flags == NCRYPT_DO_NOT_FINALIZE_FLAG;
    let mut provider: NCRYPT_PROV_HANDLE = 0;
    let mut key: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: the provider is freed below; the key is owned by the returned NcryptKey; the blob is
    // live with the length passed.
    let status = unsafe {
        let status = NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0);
        if !succeeded(status) {
            status
        } else {
            let status = NCryptImportKey(
                provider,
                0,
                blob_type,
                std::ptr::null(),
                &mut key,
                blob.as_ptr(),
                len32(blob)?,
                flags,
            );
            NCryptFreeObject(provider);
            if succeeded(status) && finalize {
                NCryptFinalizeKey(key, 0)
            } else {
                status
            }
        }
    };
    if !succeeded(status) {
        if key != 0 {
            drop(NcryptKey(key));
        }
        return Err(Error::Crypto(format!(
            "NCrypt could not import a key: {status:#010x}"
        )));
    }
    Ok(NcryptKey(key))
}
