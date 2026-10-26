//! HTTP infrastructure without application configuration, identity policy, or storage.
pub mod http;
pub mod shutdown;
pub mod tls;

#[cfg(feature = "telemetry")]
pub mod telemetry;
