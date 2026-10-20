//! Map the algorithm identifier of a key to the name that the rules pack uses.
//!
//! Certificates, PEM keys, and SSH keys share this code. It lives in `pqaudit-core`.

pub(crate) use pqaudit_core::x509::{elliptic, from_oid, Parts};
