//! The calls into bcrypt.dll.
//!
//! Every algorithm handle used here is a CNG pseudo-handle (`BCRYPT_SHA256_ALG_HANDLE` and so on),
//! available from Windows 10. A pseudo-handle needs no `BCryptOpenAlgorithmProvider` and no
//! closing, and is usable from any thread, so the provider holds no handles of its own.

use crate::algorithm::{Hash, Padding};
use crate::blob::Curve;
use log::debug;
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_INVALID_SIGNATURE};
use windows_sys::Win32::Security::Cryptography::{
    BCryptDestroyKey, BCryptGetFipsAlgorithmMode, BCryptHash, BCryptImportKeyPair,
    BCryptVerifySignature, BCRYPT_ALG_HANDLE, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALG_HANDLE,
    BCRYPT_ECDSA_P384_ALG_HANDLE, BCRYPT_ECDSA_P521_ALG_HANDLE, BCRYPT_KEY_HANDLE,
    BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO,
    BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSA_ALG_HANDLE, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA1_ALG_HANDLE,
    BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA256_ALG_HANDLE, BCRYPT_SHA384_ALGORITHM,
    BCRYPT_SHA384_ALG_HANDLE, BCRYPT_SHA512_ALGORITHM, BCRYPT_SHA512_ALG_HANDLE,
};

fn succeeded(status: NTSTATUS) -> bool {
    status >= 0
}

fn hash_handle(hash: Hash) -> BCRYPT_ALG_HANDLE {
    match hash {
        Hash::Sha1 => BCRYPT_SHA1_ALG_HANDLE,
        Hash::Sha256 => BCRYPT_SHA256_ALG_HANDLE,
        Hash::Sha384 => BCRYPT_SHA384_ALG_HANDLE,
        Hash::Sha512 => BCRYPT_SHA512_ALG_HANDLE,
    }
}

fn hash_name(hash: Hash) -> PCWSTR {
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

    if succeeded(status) {
        Verdict::Valid
    } else if status == STATUS_INVALID_SIGNATURE {
        Verdict::Invalid
    } else {
        Verdict::Declined(status)
    }
}

/// Reports whether CNG is in FIPS-approved mode, or `None` when the query fails.
pub(crate) fn fips_mode_enabled() -> Option<bool> {
    let mut enabled = 0u8;
    // SAFETY: `enabled` is a valid out-pointer for the BOOLEAN the call writes.
    let status = unsafe { BCryptGetFipsAlgorithmMode(&mut enabled) };
    succeeded(status).then_some(enabled != 0)
}
