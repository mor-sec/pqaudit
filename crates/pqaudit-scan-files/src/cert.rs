//! Read X.509 certificates from PEM and DER data.
//!
//! The code reads only `CERTIFICATE` blocks. It never decodes other blocks, for example private keys.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
pub(crate) use pqaudit_core::x509::{parse_certificate, sha256_hex, CertError};
use pqaudit_core::CertInfo;

use crate::messages;

use crate::pem::{find, BEGIN as PEM_ANY_BEGIN, CERT_LABELS, DASHES as PEM_DASHES};

/// One certificate from a file.
#[derive(Debug)]
pub struct Found {
    /// The facts about the certificate.
    pub info: CertInfo,
    /// The line of the start line of the PEM block. A DER file has no line.
    pub line: Option<u32>,
}

/// The result of the read of PEM data.
#[derive(Debug, Default)]
pub struct PemResult {
    /// The valid certificates.
    pub certs: Vec<Found>,
    /// The number of certificate blocks that are not valid.
    pub bad: usize,
    /// The number of PEM blocks of other types, for example keys. The tool does not read them.
    pub other: usize,
    /// The reason for the first bad block.
    pub first_problem: Option<String>,
}

/// Return true if the data has the start line of any PEM block.
pub fn has_any_pem(data: &[u8]) -> bool {
    find(data, PEM_ANY_BEGIN, 0).is_some()
}

/// Read all certificate blocks of PEM data.
pub fn parse_pem(data: &[u8]) -> PemResult {
    let mut result = PemResult::default();
    let mut cursor = 0;
    let mut line = 1u32;
    let mut counted = 0;
    while let Some(start) = find(data, PEM_ANY_BEGIN, cursor) {
        let label_start = start + PEM_ANY_BEGIN.len();
        let Some(label_end) = find(data, PEM_DASHES, label_start) else {
            break;
        };
        let label = &data[label_start..label_end];
        let body_start = label_end + PEM_DASHES.len();
        if !CERT_LABELS.contains(&label) {
            result.other += 1;
            cursor = body_start;
            continue;
        }
        // Count the line breaks between the last counted place and this block.
        line = line.saturating_add(count_lines(&data[counted..start]));
        counted = start;
        let mut end_marker = b"-----END ".to_vec();
        end_marker.extend_from_slice(label);
        end_marker.extend_from_slice(PEM_DASHES);
        let Some(end) = find(data, &end_marker, body_start) else {
            result.problem(messages::PEM_NOT_CLOSED.to_string());
            break;
        };
        let index = result.certs.len() + result.bad;
        match decode_block(&data[body_start..end]) {
            Some(der) => match parse_certificate(&der, index) {
                Ok(info) => result.certs.push(Found {
                    info,
                    line: Some(line),
                }),
                Err(error) => result.problem(error.reason()),
            },
            None => result.problem(messages::PEM_BAD_BASE64.to_string()),
        }
        cursor = end + end_marker.len();
    }
    result
}

impl PemResult {
    fn problem(&mut self, reason: String) {
        self.bad += 1;
        self.first_problem.get_or_insert(reason);
    }
}

fn count_lines(data: &[u8]) -> u32 {
    u32::try_from(data.iter().filter(|byte| **byte == b'\n').count()).unwrap_or(u32::MAX)
}

/// Decode the base64 text between the start line and the end line.
fn decode_block(body: &[u8]) -> Option<Vec<u8>> {
    let text: Vec<u8> = body
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    STANDARD.decode(text).ok()
}

/// Read one DER certificate.
pub fn parse_der(data: &[u8]) -> Result<CertInfo, String> {
    parse_certificate(data, 0).map_err(|error| match error {
        CertError::Invalid => messages::DER_INVALID.to_string(),
        other => other.reason(),
    })
}
