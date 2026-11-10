//! The calls into bcrypt.dll.
//!
//! Every algorithm handle used here is a CNG pseudo-handle (`BCRYPT_SHA256_ALG_HANDLE` and so on),
//! available from Windows 10. A pseudo-handle needs no `BCryptOpenAlgorithmProvider` and no
//! closing, and is usable from any thread, so the provider holds no handles of its own.

use crate::algorithm::{Hash, MlDsa, Padding};
use crate::blob::{ml_dsa_public_blob, Curve};
use log::debug;
use std::sync::OnceLock;
use windows_sys::core::{s, w, PCWSTR};
use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_INVALID_SIGNATURE};
use windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE;
use windows_sys::Win32::Security::Cryptography::{
    BCryptDestroyKey, BCryptGetFipsAlgorithmMode, BCryptHash, BCryptImportKeyPair,
    BCryptVerifySignature, BCRYPT_ALG_HANDLE, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALG_HANDLE,
    BCRYPT_ECDSA_P384_ALG_HANDLE, BCRYPT_ECDSA_P521_ALG_HANDLE, BCRYPT_KEY_HANDLE,
    BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO,
    BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSA_ALG_HANDLE, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA1_ALG_HANDLE,
    BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA256_ALG_HANDLE, BCRYPT_SHA384_ALGORITHM,
    BCRYPT_SHA384_ALG_HANDLE, BCRYPT_SHA512_ALGORITHM, BCRYPT_SHA512_ALG_HANDLE,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

fn succeeded(status: NTSTATUS) -> bool {
    status >= 0
}

// ML-DSA, from the Windows 11 SDK's bcrypt.h (10.0.26100), which windows-sys 0.61 does not bind.

/// `BCRYPT_MLDSA_ALG_HANDLE`, the ML-DSA pseudo-handle.
const MLDSA_ALG_HANDLE: BCRYPT_ALG_HANDLE = 0x0000_0471 as BCRYPT_ALG_HANDLE;
/// `BCRYPT_PQDSA_PUBLIC_BLOB`.
pub(crate) const PQDSA_PUBLIC_BLOB: PCWSTR = w!("PQDSAPUBLICBLOB");
/// `BCRYPT_PAD_PQDSA` (and `NCRYPT_PAD_PQDSA_FLAG`): the padding information is a
/// [`PqdsaPaddingInfo`].
pub(crate) const PAD_PQDSA: u32 = 0x0000_0020;

/// `BCRYPT_PQDSA_PADDING_INFO`: the context string, and the hash of a pre-hashed (HashML-DSA)
/// signature, null for pure ML-DSA.
#[repr(C)]
pub(crate) struct PqdsaPaddingInfo {
    pb_ctx: *mut u8,
    cb_ctx: u32,
    psz_prehash_alg_id: PCWSTR,
}

impl PqdsaPaddingInfo {
    /// Pure ML-DSA with an empty context string, as RFC 9881 and RFC 9882 require.
    pub(crate) fn pure() -> Self {
        Self {
            pb_ctx: std::ptr::null_mut(),
            cb_ctx: 0,
            psz_prehash_alg_id: std::ptr::null(),
        }
    }
}

fn hash_handle(hash: Hash) -> BCRYPT_ALG_HANDLE {
    match hash {
        Hash::Sha1 => BCRYPT_SHA1_ALG_HANDLE,
        Hash::Sha256 => BCRYPT_SHA256_ALG_HANDLE,
        Hash::Sha384 => BCRYPT_SHA384_ALG_HANDLE,
        Hash::Sha512 => BCRYPT_SHA512_ALG_HANDLE,
    }
}

pub(crate) fn hash_name(hash: Hash) -> PCWSTR {
    match hash {
        Hash::Sha1 => BCRYPT_SHA1_ALGORITHM,
        Hash::Sha256 => BCRYPT_SHA256_ALGORITHM,
        Hash::Sha384 => BCRYPT_SHA384_ALGORITHM,
        Hash::Sha512 => BCRYPT_SHA512_ALGORITHM,
    }
}

/// Hashes `data`, or returns `None` when CNG refuses.
pub(crate) fn hash(hash: Hash, data: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; hash.len()];
    let input_len = u32::try_from(data.len()).ok()?;
    let output_len = u32::try_from(out.len()).ok()?;
    // SAFETY: the handle is a pseudo-handle, both buffers are live for the call and their lengths
    // are the lengths passed, and no secret is supplied for an unkeyed hash.
    let status = unsafe {
        BCryptHash(
            hash_handle(hash),
            std::ptr::null(),
            0,
            data.as_ptr(),
            input_len,
            out.as_mut_ptr(),
            output_len,
        )
    };
    if succeeded(status) {
        Some(out)
    } else {
        debug!("BCryptHash failed: {status:#010x}");
        None
    }
}

/// An imported public key, destroyed when dropped.
pub(crate) struct Key(BCRYPT_KEY_HANDLE);

impl Key {
    /// The BCrypt handle, live while the key is.
    #[cfg(feature = "cms")]
    pub(crate) fn handle(&self) -> BCRYPT_KEY_HANDLE {
        self.0
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful BCryptImportKeyPair and is destroyed once.
        unsafe {
            BCryptDestroyKey(self.0);
        }
    }
}

fn import(algorithm: BCRYPT_ALG_HANDLE, blob_type: PCWSTR, blob: &[u8]) -> Option<Key> {
    let mut key: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    let blob_len = u32::try_from(blob.len()).ok()?;
    // SAFETY: the algorithm is a pseudo-handle, the blob type is a static wide string, `key` is a
    // valid out-pointer, and the blob is live for the call with the length passed.
    let status = unsafe {
        BCryptImportKeyPair(
            algorithm,
            std::ptr::null_mut(),
            blob_type,
            &mut key,
            blob.as_ptr(),
            blob_len,
            0,
        )
    };
    if succeeded(status) && !key.is_null() {
        Some(Key(key))
    } else {
        debug!("BCryptImportKeyPair declined a public key: {status:#010x}");
        None
    }
}

/// Imports a `BCRYPT_RSAPUBLIC_BLOB`.
pub(crate) fn import_rsa(blob: &[u8]) -> Option<Key> {
    import(BCRYPT_RSA_ALG_HANDLE, BCRYPT_RSAPUBLIC_BLOB, blob)
}

/// Imports a `BCRYPT_ECCPUBLIC_BLOB` on `curve`.
pub(crate) fn import_ecdsa(curve: Curve, blob: &[u8]) -> Option<Key> {
    let algorithm = match curve {
        Curve::P256 => BCRYPT_ECDSA_P256_ALG_HANDLE,
        Curve::P384 => BCRYPT_ECDSA_P384_ALG_HANDLE,
        Curve::P521 => BCRYPT_ECDSA_P521_ALG_HANDLE,
    };
    import(algorithm, BCRYPT_ECCPUBLIC_BLOB, blob)
}

// ML-KEM. Its entry points are new to ncrypt.dll and bcrypt.dll: a binary that linked them would
// not even load on a Windows without them, so they are looked up when first needed instead. The
// other definitions are from the Windows 11 SDK's bcrypt.h (10.0.26100), which windows-sys 0.61
// does not bind.

/// `BCRYPT_MLKEM_ALG_HANDLE`, the ML-KEM pseudo-handle.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
const MLKEM_ALG_HANDLE: BCRYPT_ALG_HANDLE = 0x0000_0481 as BCRYPT_ALG_HANDLE;
/// `BCRYPT_MLKEM_PUBLIC_BLOB`, which is also `BCRYPT_MLKEM_ENCAPSULATION_BLOB`.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
const MLKEM_PUBLIC_BLOB: PCWSTR = w!("MLKEMPUBLICBLOB");

/// Imports a `BCRYPT_MLKEM_PUBLIC_BLOB` of an ML-KEM encapsulation key.
#[cfg_attr(not(feature = "cms"), allow(dead_code))]
pub(crate) fn import_ml_kem(blob: &[u8]) -> Option<Key> {
    import(MLKEM_ALG_HANDLE, MLKEM_PUBLIC_BLOB, blob)
}

/// The blob type an ML-KEM private key imports as: `BCRYPT_MLKEM_PRIVATE_SEED_BLOB` or
/// `BCRYPT_MLKEM_PRIVATE_BLOB`.
#[cfg(feature = "cms")]
pub(crate) fn ml_kem_private_blob_type(kind: crate::blob::MlKemPrivateBlob) -> PCWSTR {
    match kind {
        crate::blob::MlKemPrivateBlob::Seed => w!("MLKEMPRIVATESEEDBLOB"),
        crate::blob::MlKemPrivateBlob::Expanded => w!("MLKEMPRIVATEBLOB"),
    }
}

/// `name` from the system library `dll`, or `None` where it does not export it.
///
/// # Safety
///
/// The caller transmutes the result to the signature the SDK declares for `name`.
unsafe fn system_proc(
    dll: PCWSTR,
    name: windows_sys::core::PCSTR,
) -> Option<unsafe extern "system" fn() -> isize> {
    // SAFETY: the library is a system one, loaded once and never freed, so the address stays
    // valid; both names are static strings with a null terminator. The search is confined to
    // System32, so a library of the same name beside the executable is never the one loaded.
    unsafe {
        let module = LoadLibraryExW(dll, std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if module.is_null() {
            return None;
        }
        GetProcAddress(module, name)
    }
}

/// `BCryptEncapsulate`, from bcrypt.h.
pub(crate) type BCryptEncapsulateFn = unsafe extern "system" fn(
    hkey: BCRYPT_KEY_HANDLE,
    pb_secret_key: *mut u8,
    cb_secret_key: u32,
    pcb_secret_key: *mut u32,
    pb_cipher_text: *mut u8,
    cb_cipher_text: u32,
    pcb_cipher_text: *mut u32,
    dw_flags: u32,
) -> NTSTATUS;

/// bcrypt.dll's `BCryptEncapsulate`, or `None` on a Windows whose CNG has no ML-KEM.
pub(crate) fn bcrypt_encapsulate() -> Option<BCryptEncapsulateFn> {
    static ENCAPSULATE: OnceLock<Option<BCryptEncapsulateFn>> = OnceLock::new();
    *ENCAPSULATE.get_or_init(|| {
        // SAFETY: the address is bcrypt.dll's BCryptEncapsulate, whose signature bcrypt.h
        // declares as this one.
        unsafe {
            let proc = system_proc(w!("bcrypt.dll"), s!("BCryptEncapsulate"))?;
            Some(std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                BCryptEncapsulateFn,
            >(proc))
        }
    })
}

/// `NCryptDecapsulate`, from the Windows 11 SDK's ncrypt.h (10.0.26100).
pub(crate) type NCryptDecapsulateFn = unsafe extern "system" fn(
    hkey: NCRYPT_KEY_HANDLE,
    pb_cipher_text: *const u8,
    cb_cipher_text: u32,
    pb_secret_key: *mut u8,
    cb_secret_key: u32,
    pcb_secret_key: *mut u32,
    dw_flags: u32,
) -> i32;

/// ncrypt.dll's `NCryptDecapsulate`, or `None` on a Windows whose CNG has no ML-KEM.
pub(crate) fn ncrypt_decapsulate() -> Option<NCryptDecapsulateFn> {
    static DECAPSULATE: OnceLock<Option<NCryptDecapsulateFn>> = OnceLock::new();
    *DECAPSULATE.get_or_init(|| {
        // SAFETY: the address is ncrypt.dll's NCryptDecapsulate, whose signature ncrypt.h
        // declares as this one.
        unsafe {
            let proc = system_proc(w!("ncrypt.dll"), s!("NCryptDecapsulate"))?;
            Some(std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                NCryptDecapsulateFn,
            >(proc))
        }
    })
}

/// Whether CNG offers ML-KEM: whether bcrypt.dll exports `BCryptEncapsulate` and ncrypt.dll
/// `NCryptDecapsulate`.
pub(crate) fn ml_kem_available() -> bool {
    bcrypt_encapsulate().is_some() && ncrypt_decapsulate().is_some()
}

/// Imports a `BCRYPT_PQDSA_PUBLIC_BLOB` of an ML-DSA key.
pub(crate) fn import_ml_dsa(blob: &[u8]) -> Option<Key> {
    import(MLDSA_ALG_HANDLE, PQDSA_PUBLIC_BLOB, blob)
}

/// Whether CNG offers ML-DSA, as recent Windows 11 builds do: whether it imports a public key of
/// each parameter set, found out once. A public key is any string of bytes of the right length,
/// so one of zeros serves.
pub(crate) fn ml_dsa_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        MlDsa::ALL.into_iter().all(|set| {
            let spki = spki::SubjectPublicKeyInfoOwned {
                algorithm: spki::AlgorithmIdentifierOwned {
                    oid: set.oid(),
                    parameters: None,
                },
                subject_public_key: der::asn1::BitString::from_bytes(&vec![
                    0;
                    set.public_key_len()
                ])
                .expect("a bit string of whole octets"),
            };
            ml_dsa_public_blob(&spki).is_some_and(|(_, blob)| import_ml_dsa(&blob).is_some())
        })
    })
}

/// Verifies a pure ML-DSA `signature` over `message` with `key`.
pub(crate) fn verify_ml_dsa(key: &Key, message: &[u8], signature: &[u8]) -> Verdict {
    let (Ok(message_len), Ok(signature_len)) =
        (u32::try_from(message.len()), u32::try_from(signature.len()))
    else {
        return Verdict::Declined(0);
    };
    let padding = PqdsaPaddingInfo::pure();
    // SAFETY: the key handle is live for the borrow, the padding structure outlives the call, and
    // both buffers are live with the lengths passed. For pure ML-DSA, CNG takes the message where
    // it otherwise takes a hash.
    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            (&padding as *const PqdsaPaddingInfo).cast(),
            message.as_ptr(),
            message_len,
            signature.as_ptr(),
            signature_len,
            PAD_PQDSA,
        )
    };
    verdict(status)
}

fn verdict(status: NTSTATUS) -> Verdict {
    if succeeded(status) {
        Verdict::Valid
    } else if status == STATUS_INVALID_SIGNATURE {
        Verdict::Invalid
    } else {
        Verdict::Declined(status)
    }
}

/// What `BCryptVerifySignature` made of a signature.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Verdict {
    /// The signature is valid.
    Valid,
    /// CNG checked the signature and found it invalid (`STATUS_INVALID_SIGNATURE`).
    Invalid,
    /// CNG refused to check, with the status it returned.
    Declined(NTSTATUS),
}

/// Verifies `signature` over `digest` with `key`.
pub(crate) fn verify(
    key: &Key,
    padding: Padding,
    hash: Hash,
    digest: &[u8],
    signature: &[u8],
) -> Verdict {
    let (Ok(digest_len), Ok(signature_len)) =
        (u32::try_from(digest.len()), u32::try_from(signature.len()))
    else {
        return Verdict::Declined(0);
    };

    let pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: hash_name(hash),
    };
    let pss = match padding {
        Padding::Pss { salt_len } => BCRYPT_PSS_PADDING_INFO {
            pszAlgId: hash_name(hash),
            cbSalt: salt_len,
        },
        _ => BCRYPT_PSS_PADDING_INFO {
            pszAlgId: std::ptr::null(),
            cbSalt: 0,
        },
    };
    let (padding_info, flags): (*const core::ffi::c_void, u32) = match padding {
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

    // SAFETY: the key handle is live for the borrow, the padding structure (if any) and the wide
    // string it points to outlive the call, and both buffers are live with the lengths passed.
    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            padding_info,
            digest.as_ptr(),
            digest_len,
            signature.as_ptr(),
            signature_len,
            flags,
        )
    };
    verdict(status)
}

/// Reports whether CNG is in FIPS-approved mode, or `None` when the query fails.
pub(crate) fn fips_mode_enabled() -> Option<bool> {
    let mut enabled = 0u8;
    // SAFETY: `enabled` is a valid out-pointer for the BOOLEAN the call writes.
    let status = unsafe { BCryptGetFipsAlgorithmMode(&mut enabled) };
    succeeded(status).then_some(enabled != 0)
}
