//! OAuth/OIDC building blocks shared by idElephant and idFrog.
//!
//! Applications own authentication, account and group lookup, HTTP routing,
//! sessions, grant storage, and signing-key storage and rotation. This crate
//! operates on protocol values and has no dependency on an application's user
//! directory, database, or web framework.

pub mod client_metadata;
pub mod discovery;
pub mod protocol;
pub mod token;
