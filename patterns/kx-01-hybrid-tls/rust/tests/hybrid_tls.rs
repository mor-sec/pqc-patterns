use std::sync::Arc;

use kx_01_hybrid_tls::*;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection};

fn test_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["svc.internal".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
    (ck.cert.der().clone(), key.into())
}

fn roots(cert: &CertificateDer<'static>) -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(cert.clone()).unwrap();
    r
}

/// Runs a handshake in memory. Returns the client connection on success.
fn handshake(server: ServerConfig, client: ClientConfig) -> Result<ClientConnection, rustls::Error> {
    let mut srv = ServerConnection::new(Arc::new(server))?;
    let mut cli = ClientConnection::new(Arc::new(client), ServerName::try_from("svc.internal").unwrap())?;
    for _ in 0..10 {
        let mut buf = Vec::new();
        cli.write_tls(&mut buf).unwrap();
        srv.read_tls(&mut buf.as_slice()).unwrap();
        srv.process_new_packets()?;
        buf.clear();
        srv.write_tls(&mut buf).unwrap();
        cli.read_tls(&mut buf.as_slice()).unwrap();
        cli.process_new_packets()?;
        if !cli.is_handshaking() && !srv.is_handshaking() {
            return Ok(cli);
        }
    }
    panic!("handshake did not finish");
}

fn classical_client(roots: RootCertStore) -> ClientConfig {
    let p = CryptoProvider {
        kx_groups: vec![kx_group::X25519, kx_group::SECP256R1],
        ..aws_lc_rs::default_provider()
    };
    ClientConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[test]
fn strict_negotiates_hybrid() {
    let (cert, key) = test_cert();
    let cli = handshake(
        server_config(vec![cert.clone()], key, Mode::Strict).unwrap(),
        client_config(roots(&cert), Mode::Strict).unwrap(),
    )
    .unwrap();
    assert_eq!(
        cli.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::X25519MLKEM768
    );
    assert_eq!(require_hybrid(&cli), Ok(()));
}

#[test]
fn strict_rejects_classical_client() {
    let (cert, key) = test_cert();
    let result = handshake(
        server_config(vec![cert.clone()], key, Mode::Strict).unwrap(),
        classical_client(roots(&cert)),
    );
    assert!(result.is_err(), "strict server accepted a classical-only client");
}

#[test]
fn compatible_falls_back_and_is_detected() {
    let (cert, key) = test_cert();
    let cli = handshake(
        server_config(vec![cert.clone()], key, Mode::Compatible).unwrap(),
        classical_client(roots(&cert)),
    )
    .unwrap();
    assert_eq!(require_hybrid(&cli), Err(ClassicalKeyExchange));
}
