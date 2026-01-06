use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::Result;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
    CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_FIND_SUBJECT_CERT,
    CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
    CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureInfo {
    pub is_signed: bool,
    pub is_valid: bool,
    pub signer_name: Option<String>,
    pub issuer_name: Option<String>,
    pub timestamp: Option<std::time::SystemTime>,
    pub catalog_signed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    Valid,
    Invalid,
    NotSigned,
    CatalogSigned,
    Untrusted,
    Expired,
}

impl SignatureInfo {
    pub fn status(&self) -> SignatureStatus {
        if !self.is_signed {
            return SignatureStatus::NotSigned;
        }

        if self.is_valid {
            if self.catalog_signed {
                return SignatureStatus::CatalogSigned;
            }
            return SignatureStatus::Valid;
        }

        match self.error.as_deref() {
            Some("Expired") => SignatureStatus::Expired,
            Some("Untrusted") => SignatureStatus::Untrusted,
            _ => SignatureStatus::Invalid,
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
struct WintrustFileInfo {
    cbStruct: u32,
    pcwszFilePath: *const u16,
    hFile: HANDLE,
    pgKnownSubject: *const WintrustGuid,
}

#[repr(C)]
#[allow(non_snake_case)]
struct WintrustData {
    cbStruct: u32,
    pPolicyCallbackData: *mut c_void,
    pSIPClientData: *mut c_void,
    dwUIChoice: u32,
    fdwRevocationChecks: u32,
    dwUnionChoice: u32,
    pFile: *mut WintrustFileInfo,
    dwStateAction: u32,
    hWVTStateData: HANDLE,
    pwszURLReference: *const u16,
    dwProvFlags: u32,
    dwUIContext: u32,
    pSignatureSettings: *mut c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
#[allow(clippy::upper_case_acronyms)]
struct WintrustGuid {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [u8; 8],
}

const WTD_UI_NONE: u32 = 2;
const WTD_REVOKE_NONE: u32 = 0;
const WTD_CHOICE_FILE: u32 = 1;
const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;
const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x00000004;

const WINTRUST_ACTION_GENERIC_VERIFY_V2: WintrustGuid = WintrustGuid {
    Data1: 0x00AAC56B,
    Data2: 0xCD44,
    Data3: 0x11d0,
    Data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

const TRUST_E_NOSIGNATURE: i32 = -0x7FF6FE00_i32; // 0x800B0100
const TRUST_E_EXPLICIT_DISTRUST: i32 = -0x7FF6FDFC_i32; // 0x800B0104
const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = -0x7FF6FDFE_i32; // 0x800B0102
const CRYPT_E_SECURITY_SETTINGS: i32 = -0x7FF6CFFD_i32; // 0x80092003
const CERT_E_EXPIRED: i32 = -0x7FF4FEFF_i32; // 0x800B0101
const CERT_E_UNTRUSTEDROOT: i32 = -0x7FF4FEF7_i32; // 0x800B0109

#[link(name = "wintrust")]
extern "system" {
    fn WinVerifyTrust(
        hwnd: HANDLE,
        pgActionID: *const WintrustGuid,
        pWVTData: *mut WintrustData,
    ) -> i32;
}

fn classify_winverifytrust_error(code: i32) -> &'static str {
    match code {
        CERT_E_EXPIRED => "Expired",
        TRUST_E_EXPLICIT_DISTRUST | TRUST_E_SUBJECT_NOT_TRUSTED | CERT_E_UNTRUSTEDROOT => {
            "Untrusted"
        }
        CRYPT_E_SECURITY_SETTINGS => "Untrusted",
        _ => "Invalid",
    }
}

fn winverifytrust_path(path: &Path) -> Result<i32> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: WinVerifyTrust FFI call with proper pointer lifetime management:
    // - `wide_path` is a null-terminated UTF-16 string valid for the entire unsafe block
    // - `wide_path.as_ptr()` stored in `file_info.pcwszFilePath` remains valid during both WinVerifyTrust calls
    // - `file_info` and `wvt_data` are stack-allocated and live for the duration of the calls
    // - Struct sizes computed correctly with `mem::size_of`
    // - `pFile` pointer to `file_info` is valid as both structs are in the same scope
    // - WinVerifyTrust is called per Microsoft documentation with proper state management
    // - Second call with STATEACTION_CLOSE properly releases resources allocated by first call
    // - No concurrent access to these structures
    unsafe {
        let mut file_info = WintrustFileInfo {
            cbStruct: std::mem::size_of::<WintrustFileInfo>() as u32,
            pcwszFilePath: wide_path.as_ptr(),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null(),
        };

        let mut wvt_data = WintrustData {
            cbStruct: std::mem::size_of::<WintrustData>() as u32,
            pPolicyCallbackData: std::ptr::null_mut(),
            pSIPClientData: std::ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            pFile: &mut file_info,
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: HANDLE::default(),
            pwszURLReference: std::ptr::null(),
            // Avoid network retrieval in UI tooling contexts.
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            dwUIContext: 0,
            pSignatureSettings: std::ptr::null_mut(),
        };

        let action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let result = WinVerifyTrust(HANDLE::default(), &action_guid, &mut wvt_data);

        wvt_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(HANDLE::default(), &action_guid, &mut wvt_data);

        Ok(result)
    }
}

fn try_extract_signer_names(path: &Path) -> Option<(String, String)> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut store: HCERTSTORE = HCERTSTORE::default();
    let mut msg: *mut c_void = std::ptr::null_mut();

    // SAFETY: CryptQueryObject FFI call with valid pointer arguments:
    // - `wide_path` is a null-terminated UTF-16 string living for the entire function scope
    // - Cast to `*const c_void` is required by the API and safe for read-only access
    // - `store` and `msg` are valid mutable references for output parameters
    // - API will either populate these handles or leave them null on failure
    // - No data races as all parameters are locally owned
    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            PCWSTR(wide_path.as_ptr()).0 as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store as *mut _),
            Some(&mut msg as *mut _),
            None,
        )
    };

    if ok.is_err() {
        return None;
    }

    let mut signer_info_size: u32 = 0;
    // SAFETY: CryptMsgGetParam size query with valid message handle:
    // - `msg` was populated by successful CryptQueryObject call above
    // - Passing None for buffer is the standard pattern to query required size
    // - `signer_info_size` is a valid mutable reference for output
    let ok_size = unsafe {
        CryptMsgGetParam(
            msg as *const c_void,
            CMSG_SIGNER_INFO_PARAM,
            0,
            None,
            &mut signer_info_size,
        )
    };
    if ok_size.is_err() || signer_info_size == 0 {
        // SAFETY: Cleanup of resources acquired from CryptQueryObject:
        // - `msg` null check prevents passing invalid handle to CryptMsgClose
        // - `store` handle is valid from CryptQueryObject or default-initialized
        // - Both cleanup functions are safe to call with their respective handle types
        unsafe {
            let _ = CryptMsgClose(if msg.is_null() {
                None
            } else {
                Some(msg as *const c_void)
            });
            let _ = CertCloseStore(store, 0);
        }
        return None;
    }

    let mut signer_info_buf = vec![0u8; signer_info_size as usize];
    // SAFETY: CryptMsgGetParam data retrieval with properly sized buffer:
    // - Buffer allocated with exact size returned by previous size query
    // - `msg` handle remains valid from CryptQueryObject
    // - Buffer pointer valid for the duration of the call
    // - `signer_info_size` is updated with actual bytes written
    let ok_param = unsafe {
        CryptMsgGetParam(
            msg as *const c_void,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(signer_info_buf.as_mut_ptr() as *mut c_void),
            &mut signer_info_size,
        )
    };
    if ok_param.is_err() {
        // SAFETY: Resource cleanup on error - same safety invariants as above
        unsafe {
            let _ = CryptMsgClose(if msg.is_null() {
                None
            } else {
                Some(msg as *const c_void)
            });
            let _ = CertCloseStore(store, 0);
        }
        return None;
    }

    // SAFETY: Casting buffer to CMSG_SIGNER_INFO structure:
    // - Buffer was populated by CryptMsgGetParam with CMSG_SIGNER_INFO_PARAM
    // - Microsoft API guarantees proper structure layout and alignment
    // - Buffer size validated to be at least signer_info_size bytes
    // - Reference lifetime bound to buffer lifetime (within this function)
    let signer_info = unsafe { &*(signer_info_buf.as_ptr() as *const CMSG_SIGNER_INFO) };

    let mut cert_info = windows::Win32::Security::Cryptography::CERT_INFO {
        Issuer: signer_info.Issuer,
        SerialNumber: signer_info.SerialNumber,
        ..Default::default()
    };

    // SAFETY: CertFindCertificateInStore with valid certificate store and search criteria:
    // - `store` handle is valid from CryptQueryObject
    // - `cert_info` is properly initialized with Issuer and SerialNumber from signer_info
    // - Cast to `*const c_void` required by API for search parameter
    // - Returns certificate context pointer or null if not found
    // - No ownership transfer - we must free the returned certificate
    let cert = unsafe {
        CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&mut cert_info as *mut _ as *const c_void),
            None,
        )
    };

    let out = if cert.is_null() {
        None
    } else {
        let cert_ptr = cert as *const windows::Win32::Security::Cryptography::CERT_CONTEXT;
        let subject = cert_get_name_string(cert_ptr, 0);
        let issuer = cert_get_name_string(cert_ptr, CERT_NAME_ISSUER_FLAG);
        // SAFETY: Freeing certificate context obtained from CertFindCertificateInStore:
        // - `cert` pointer is non-null (verified above) and valid
        // - Certificate context was allocated by Windows and must be freed
        // - After this call, `cert` pointer must not be used
        unsafe {
            let _ = CertFreeCertificateContext(Some(
                cert as *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
            ));
        }
        match (subject, issuer) {
            (Some(subject), Some(issuer)) => Some((subject, issuer)),
            _ => None,
        }
    };

    // SAFETY: Final cleanup of cryptography handles:
    // - `msg` null check prevents invalid handle usage
    // - `store` handle valid from CryptQueryObject or default
    // - Both cleanup functions safe to call with valid or default handles
    // - Must be called to prevent resource leaks
    unsafe {
        let _ = CryptMsgClose(if msg.is_null() {
            None
        } else {
            Some(msg as *const c_void)
        });
        let _ = CertCloseStore(store, 0);
    }

    out
}

fn cert_get_name_string(
    cert: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
    flags: u32,
) -> Option<String> {
    // SAFETY: CertGetNameStringW size query with valid certificate context:
    // - `cert` pointer must be valid CERT_CONTEXT from CertFindCertificateInStore
    // - Passing None for buffer is standard pattern to query required string length
    // - Returns character count needed including null terminator
    let len = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None) };
    if len <= 1 {
        return None;
    }

    let mut buf = vec![0u16; len as usize];
    // SAFETY: CertGetNameStringW data retrieval with properly sized buffer:
    // - Buffer allocated with exact length from previous size query
    // - `cert` pointer remains valid (same context)
    // - Buffer will be populated with null-terminated UTF-16 string
    // - Returns actual characters written including null terminator
    let len2 = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            None,
            Some(buf.as_mut_slice()),
        )
    };
    if len2 <= 1 {
        return None;
    }

    let s = String::from_utf16_lossy(&buf[..(len2 as usize).saturating_sub(1)]);
    let s = s.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn has_embedded_signature(path: &Path) -> bool {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut store: HCERTSTORE = HCERTSTORE::default();
    let mut msg: *mut c_void = std::ptr::null_mut();

    // SAFETY: CryptQueryObject call to check for embedded signature:
    // - `wide_path` is null-terminated UTF-16 string valid for the call
    // - Cast to `*const c_void` required by API for file path
    // - `store` and `msg` are valid output parameters
    // - Only checking for signature presence, not extracting data
    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            PCWSTR(wide_path.as_ptr()).0 as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store as *mut _),
            Some(&mut msg as *mut _),
            None,
        )
    };

    if ok.is_ok() {
        // SAFETY: Cleanup of acquired handles after successful query:
        // - `msg` null check prevents invalid handle usage
        // - `store` handle valid from CryptQueryObject
        // - Both resources must be freed to prevent leaks
        unsafe {
            let _ = CryptMsgClose(if msg.is_null() {
                None
            } else {
                Some(msg as *const c_void)
            });
            let _ = CertCloseStore(store, 0);
        }
        true
    } else {
        false
    }
}

/// Verify Authenticode signature for a file path.
///
/// - Uses `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)`.
/// - Best-effort signer extraction via `CryptQueryObject` (embedded signatures only).
/// - Avoids network retrieval (cache-only) to keep checks fast/offline-friendly.
pub fn verify_signature(path: &Path) -> Result<SignatureInfo> {
    if !path.exists() {
        return Ok(SignatureInfo::default());
    }

    let embedded = has_embedded_signature(path);
    let verify_code = winverifytrust_path(path)?;

    if verify_code == 0 {
        let (signer_name, issuer_name) = if embedded {
            if let Some((signer, issuer)) = try_extract_signer_names(path) {
                (Some(signer), Some(issuer))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        return Ok(SignatureInfo {
            is_signed: true,
            is_valid: true,
            signer_name,
            issuer_name,
            timestamp: None,
            catalog_signed: !embedded,
            error: None,
        });
    }

    if verify_code == TRUST_E_NOSIGNATURE {
        return Ok(SignatureInfo::default());
    }

    let classified = classify_winverifytrust_error(verify_code).to_string();
    Ok(SignatureInfo {
        is_signed: true,
        is_valid: false,
        signer_name: None,
        issuer_name: None,
        timestamp: None,
        catalog_signed: !embedded,
        error: Some(classified),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status() {
        let valid = SignatureInfo {
            is_signed: true,
            is_valid: true,
            ..Default::default()
        };
        assert_eq!(valid.status(), SignatureStatus::Valid);

        let invalid = SignatureInfo {
            is_signed: true,
            is_valid: false,
            ..Default::default()
        };
        assert_eq!(invalid.status(), SignatureStatus::Invalid);

        let not_signed = SignatureInfo::default();
        assert_eq!(not_signed.status(), SignatureStatus::NotSigned);

        let catalog = SignatureInfo {
            is_signed: true,
            is_valid: true,
            catalog_signed: true,
            ..Default::default()
        };
        assert_eq!(catalog.status(), SignatureStatus::CatalogSigned);

        let untrusted = SignatureInfo {
            is_signed: true,
            is_valid: false,
            error: Some("Untrusted".to_string()),
            ..Default::default()
        };
        assert_eq!(untrusted.status(), SignatureStatus::Untrusted);

        let expired = SignatureInfo {
            is_signed: true,
            is_valid: false,
            error: Some("Expired".to_string()),
            ..Default::default()
        };
        assert_eq!(expired.status(), SignatureStatus::Expired);
    }
}
