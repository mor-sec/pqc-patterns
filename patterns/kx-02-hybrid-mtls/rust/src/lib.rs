//! Pattern KX-02: mutual TLS 1.3 between services, with a post-quantum
//! hybrid key exchange (RFC 10024) and an allow-list of client identities
//! checked inside the handshake.
//!
//! Each workload has a certificate from an internal CA. Clients are named by
//! a single URI SAN, such as `spiffe://example.org/billing`. Trusting the CA
//! proves who a client is; the allow-list decides whether it may connect.
//!
//! Certificates stay classical (ECDSA). Harvest-now, decrypt-later attacks
//! target key exchange, not authentication; track pattern PKI-01 for ML-DSA
//! certificates.

use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, ClientConfig, CommonState, DigitallySignedStruct, DistinguishedName, Error,
    RootCertStore, ServerConfig, SignatureScheme,
};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// The aws-lc-rs provider restricted to hybrid groups. There is no classical
/// fallback: both ends are services you control.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        kx_groups: vec![kx_group::X25519MLKEM768, kx_group::SECP256R1MLKEM768],
        ..aws_lc_rs::default_provider()
    })
}

/// A TLS 1.3-only server configuration that requires a client certificate
/// issued by `client_roots` and naming one of `allowed`.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_roots: RootCertStore,
    allowed: Vec<String>,
) -> Result<ServerConfig, Error> {
    let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider())
        .build()
        .map_err(|e| Error::General(e.to_string()))?;
    ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AllowList { inner, allowed }))
        .with_single_cert(chain, key)
}

/// A TLS 1.3-only client configuration that presents `chain` and verifies
/// the server against `roots`.
pub fn client_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    roots: RootCertStore,
) -> Result<ClientConfig, Error> {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
}

/// The URI SAN of the peer's leaf certificate, once the handshake has
/// verified it. Use it in handlers for decisions finer than the allow-list.
pub fn peer_identity(conn: &CommonState) -> Option<String> {
    identity(conn.peer_certificates()?.first()?)
}

/// The single URI SAN of a certificate, or `None` if it has none or several.
fn identity(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    let mut uris = san.value.general_names.iter().filter_map(|n| match n {
        GeneralName::URI(u) => Some(*u),
        _ => None,
    });
    match (uris.next(), uris.next()) {
        (Some(u), None) => Some(u.to_string()),
        _ => None,
    }
}

/// Wraps the WebPKI verifier: the chain is checked first, then the identity.
#[derive(Debug)]
struct AllowList {
    inner: Arc<dyn ClientCertVerifier>,
    allowed: Vec<String>,
}

impl ClientCertVerifier for AllowList {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let verified = self.inner.verify_client_cert(end_entity, intermediates, now)?;
        match identity(end_entity) {
            Some(id) if self.allowed.contains(&id) => Ok(verified),
            _ => Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
