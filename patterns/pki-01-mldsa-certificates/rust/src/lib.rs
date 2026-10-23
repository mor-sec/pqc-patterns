//! Pattern PKI-01: ML-DSA certificates (RFC 9881) and fully post-quantum
//! TLS 1.3, where both the key exchange (hybrid ML-KEM) and the
//! authentication (ML-DSA certificate signatures) resist quantum attacks.
//!
//! - [`generate_key`] and [`csr`] create an ML-DSA-65 key and a certificate
//!   signing request for your CA.
//! - [`server_config`] and [`client_config`] accept only ML-DSA signatures
//!   on certificates and in the handshake, and only hybrid key exchange.
//!   Use them between services whose certificates you have already moved
//!   to ML-DSA.
//!
//! ML-DSA signature schemes for TLS 1.3 (0x0904 to 0x0906) are specified in
//! draft-ietf-tls-mldsa; the certificate format is RFC 9881.

use std::sync::Arc;

use rcgen::{CertificateParams, CertificateSigningRequest, KeyPair, PKCS_ML_DSA_65};
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SignatureScheme};

/// Only ML-DSA is accepted for certificate and handshake signatures.
/// ML-DSA-87 is included for CNSA 2.0 peers.
static ML_DSA_ONLY: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[webpki::aws_lc_rs::ML_DSA_65, webpki::aws_lc_rs::ML_DSA_87],
    mapping: &[
        (SignatureScheme::ML_DSA_65, &[webpki::aws_lc_rs::ML_DSA_65]),
        (SignatureScheme::ML_DSA_87, &[webpki::aws_lc_rs::ML_DSA_87]),
    ],
};

/// The aws-lc-rs provider restricted to hybrid key exchange and ML-DSA
/// signatures.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        kx_groups: vec![kx_group::X25519MLKEM768, kx_group::SECP256R1MLKEM768],
        signature_verification_algorithms: ML_DSA_ONLY,
        ..aws_lc_rs::default_provider()
    })
}

/// A new ML-DSA-65 key pair. `key.serialize_der()` is the PKCS#8 form to
/// keep in your secret store.
pub fn generate_key() -> Result<KeyPair, rcgen::Error> {
    KeyPair::generate_for(&PKCS_ML_DSA_65)
}

/// A PKCS#10 certificate signing request for `dns_names`, signed by `key`.
pub fn csr(key: &KeyPair, dns_names: Vec<String>) -> Result<CertificateSigningRequest, rcgen::Error> {
    CertificateParams::new(dns_names)?.serialize_request(key)
}

/// A TLS 1.3-only server configuration that presents an ML-DSA chain.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, rustls::Error> {
    ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)
}

/// A TLS 1.3-only client configuration that accepts only ML-DSA-signed
/// chains from `roots`.
pub fn client_config(roots: RootCertStore) -> Result<ClientConfig, rustls::Error> {
    Ok(ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth())
}
