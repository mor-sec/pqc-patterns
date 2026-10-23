//! Pattern KX-01: TLS 1.3 configuration that negotiates a hybrid
//! post-quantum key exchange (RFC 10024) with rustls and aws-lc-rs.
//!
//! - [`Mode::Strict`]: only hybrid groups. Peers that cannot do post-quantum
//!   key exchange fail the handshake. Use for service-to-service traffic you
//!   control.
//! - [`Mode::Compatible`]: hybrid groups first, classical X25519 as fallback.
//!   Use for public endpoints until your clients are upgraded.
//!
//! Certificates stay classical (ECDSA P-256 in the tests). Harvest-now,
//! decrypt-later attacks target key exchange, not authentication; track
//! pattern PKI-01 for ML-DSA certificates.

use std::sync::Arc;

use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, CommonState, NamedGroup, RootCertStore, ServerConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Strict,
    Compatible,
}

/// Post-quantum hybrid groups in preference order. rustls's aws-lc-rs
/// provider does not offer SecP384r1MLKEM1024 yet, so CNSA 2.0 systems need
/// a different stack for now.
pub const HYBRID: &[NamedGroup] = &[NamedGroup::X25519MLKEM768, NamedGroup::secp256r1MLKEM768];

#[derive(Debug, PartialEq, Eq)]
pub struct ClassicalKeyExchange;

/// The aws-lc-rs provider restricted to the groups allowed by `mode`.
pub fn provider(mode: Mode) -> Arc<CryptoProvider> {
    let mut kx: Vec<&'static dyn SupportedKxGroup> =
        vec![kx_group::X25519MLKEM768, kx_group::SECP256R1MLKEM768];
    if mode == Mode::Compatible {
        kx.push(kx_group::X25519);
    }
    Arc::new(CryptoProvider {
        kx_groups: kx,
        ..aws_lc_rs::default_provider()
    })
}

/// A TLS 1.3-only server configuration.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    mode: Mode,
) -> Result<ServerConfig, rustls::Error> {
    ServerConfig::builder_with_provider(provider(mode))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)
}

/// A TLS 1.3-only client configuration that trusts `roots`.
pub fn client_config(roots: RootCertStore, mode: Mode) -> Result<ClientConfig, rustls::Error> {
    Ok(ClientConfig::builder_with_provider(provider(mode))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Checks a completed handshake. Call it from monitoring to alert on, or
/// close, classical-only connections.
pub fn require_hybrid(conn: &CommonState) -> Result<(), ClassicalKeyExchange> {
    match conn.negotiated_key_exchange_group() {
        Some(g) if HYBRID.contains(&g.name()) => Ok(()),
        _ => Err(ClassicalKeyExchange),
    }
}
