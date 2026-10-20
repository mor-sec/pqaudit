//! Network scanning for pqaudit: the scope file, the target plan, the runtime, and the probes.
//!
//! This crate opens sockets to client systems. The safety model of the spec binds it:
//! the tool connects only to planned targets, obeys the limits, and audits each connection.

pub mod audit;
mod findings;
pub mod messages;
pub mod runtime;
pub mod scope;
pub mod tls;
pub mod tls_legacy;
