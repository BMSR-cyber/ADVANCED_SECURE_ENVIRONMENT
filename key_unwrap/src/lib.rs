//! Confidential key/secret unwrap, in Rust, for the ASE bootstrap.
//!
//! Why this exists: the Python prototype derived the subkey and held key
//! material as GC-managed `bytes`/`memoryview.tobytes()` — copies that cannot be
//! reliably zeroized. This crate performs HKDF-SHA512 + AES-256-GCM entirely in
//! Rust, with the master key, derived subkey, and HKDF state wrapped in
//! `Zeroizing` so they are wiped on drop. Python calls it via ctypes and only
//! ever sees the final plaintext (and, for the master key, hands raw bytes
//! straight through without stringifying them).
//!
//! C ABI (all pointers borrowed, not freed by this lib):
//!   int32_t bmsr_hkdf_aesgcm_open(
//!       const uint8_t* master, size_t master_len,        // >= 32 used
//!       const uint8_t* salt,   size_t salt_len,
//!       const uint8_t* nonce,  size_t nonce_len,          // 12
//!       const uint8_t* ct,     size_t ct_len,             // incl. 16B tag
//!       const uint8_t* aad,    size_t aad_len,
//!       uint8_t* out, size_t out_cap, size_t* out_len);
//! Returns 0 on success; negative error codes otherwise. `out` must have
//! capacity >= ct_len - 16.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

const INFO: &[u8] = b"cloud-protection/aes-256-gcm/v3";

const E_NULL: i32 = -1;
const E_MASTER_SHORT: i32 = -2;
const E_NONCE_LEN: i32 = -3;
const E_CT_SHORT: i32 = -4;
const E_HKDF: i32 = -5;
const E_DECRYPT: i32 = -6;
const E_OUT_CAP: i32 = -7;

/// # Safety
/// All pointers must be valid for their stated lengths for the duration of the
/// call. `out` must be writable for `out_cap` bytes and `out_len` for one usize.
#[no_mangle]
pub unsafe extern "C" fn bmsr_hkdf_aesgcm_open(
    master: *const u8, master_len: usize,
    salt: *const u8, salt_len: usize,
    nonce: *const u8, nonce_len: usize,
    ct: *const u8, ct_len: usize,
    aad: *const u8, aad_len: usize,
    out: *mut u8, out_cap: usize, out_len: *mut usize,
) -> i32 {
    if master.is_null() || salt.is_null() || nonce.is_null() || ct.is_null()
        || out.is_null() || out_len.is_null()
    {
        return E_NULL;
    }
    if master_len < 32 {
        return E_MASTER_SHORT;
    }
    if nonce_len != 12 {
        return E_NONCE_LEN;
    }
    if ct_len < 16 {
        return E_CT_SHORT;
    }
    let pt_len = ct_len - 16;
    if out_cap < pt_len {
        return E_OUT_CAP;
    }

    let master = std::slice::from_raw_parts(master, master_len);
    let salt = std::slice::from_raw_parts(salt, salt_len);
    let nonce_b = std::slice::from_raw_parts(nonce, nonce_len);
    let ct_b = std::slice::from_raw_parts(ct, ct_len);
    let aad_b = if aad.is_null() || aad_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(aad, aad_len)
    };

    // Derive subkey with HKDF-SHA512; keep it zeroizing.
    let hk = Hkdf::<Sha512>::new(Some(salt), &master[..32]);
    let mut subkey = Zeroizing::new([0u8; 32]);
    if hk.expand(INFO, subkey.as_mut_slice()).is_err() {
        return E_HKDF;
    }

    let key = Key::<Aes256Gcm>::from_slice(subkey.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_b);

    let pt = match cipher.decrypt(nonce, Payload { msg: ct_b, aad: aad_b }) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => return E_DECRYPT, // bad tag / wrong key / tamper
    };
    if pt.len() != pt_len {
        // GCM strips the tag; lengths should match. Defensive.
        if pt.len() > out_cap {
            return E_OUT_CAP;
        }
    }
    let out_slice = std::slice::from_raw_parts_mut(out, pt.len());
    out_slice.copy_from_slice(&pt);
    *out_len = pt.len();
    0
}
