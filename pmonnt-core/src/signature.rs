//! Authenticode signature results (platform-independent data types).
//!
//! Verification itself lives in `win::signature`; these types are shared with the view model.

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
