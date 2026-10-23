use std::sync::Arc;

use pki_01_mldsa_certificates::*;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection};

struct Ca {
    issuer: Issuer<'static, KeyPair>,
    der: CertificateDer<'static>,
}

fn new_ca(name: &str, key: KeyPair) -> Ca {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let der = params.self_signed(&key).unwrap().der().clone();
    Ca {
        issuer: Issuer::new(params, key),
        der,
    }
}

fn roots(ca: &Ca) -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(ca.der.clone()).unwrap();
    r
}

/// A leaf for `key`, issued by the test CA. A real CA would issue it from
/// the CSR that `csr` produces; rcgen cannot parse ML-DSA CSRs yet.
fn server_leaf(ca: &Ca, key: KeyPair) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = CertificateParams::new(vec!["ledger.internal".to_string()])
        .unwrap()
        .signed_by(&key, &ca.issuer)
        .unwrap();
    let key = PrivatePkcs8KeyDer::from(key.serialize_der());
    (vec![cert.der().clone()], key.into())
}

fn handshake(server: ServerConfig, roots: RootCertStore) -> Result<ClientConnection, rustls::Error> {
    let mut srv = ServerConnection::new(Arc::new(server))?;
    let mut cli = ClientConnection::new(
        Arc::new(client_config(roots)?),
        ServerName::try_from("ledger.internal").unwrap(),
    )?;
    // ML-DSA certificates and signatures are several KB, so flights span
    // many TLS records: drain each side completely on every round.
    for _ in 0..10 {
        let mut buf = Vec::new();
        while cli.wants_write() {
            cli.write_tls(&mut buf).unwrap();
        }
        let mut rd = buf.as_slice();
        while !rd.is_empty() {
            srv.read_tls(&mut rd).unwrap();
            srv.process_new_packets()?;
        }
        buf.clear();
        while srv.wants_write() {
            srv.write_tls(&mut buf).unwrap();
        }
        let mut rd = buf.as_slice();
        while !rd.is_empty() {
            cli.read_tls(&mut rd).unwrap();
            cli.process_new_packets()?;
        }
        if !cli.is_handshaking() && !srv.is_handshaking() {
            return Ok(cli);
        }
    }
    panic!("handshake did not finish");
}

#[test]
fn fully_post_quantum_handshake() {
    let ca = new_ca("Ledger CA", generate_key().unwrap());
    let (chain, key) = server_leaf(&ca, generate_key().unwrap());
    let cli = handshake(server_config(chain, key).unwrap(), roots(&ca)).unwrap();
    assert_eq!(
        cli.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::X25519MLKEM768
    );
}

#[test]
fn rejects_classical_server_certificate() {
    // A classical CA and leaf: the strict client must refuse them.
    let ca = new_ca(
        "Classical CA",
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
    );
    let (chain, key) = server_leaf(&ca, KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap());
    let srv = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let err = handshake(srv, roots(&ca)).err().unwrap();
    // The client offers only ML-DSA signature schemes, so an ECDSA server
    // has nothing it may sign the handshake with.
    assert!(
        matches!(
            err,
            rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoSignatureSchemesInCommon)
        ),
        "{err:?}"
    );
}

#[test]
fn rejects_ml_dsa_leaf_under_classical_ca() {
    // The leaf key is ML-DSA but the CA signed it with ECDSA: the chain is
    // only as strong as its weakest signature, so it is refused.
    let ca = new_ca(
        "Classical CA",
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
    );
    let (chain, key) = server_leaf(&ca, generate_key().unwrap());
    let err = handshake(server_config(chain, key).unwrap(), roots(&ca))
        .err()
        .unwrap();
    assert!(matches!(err, rustls::Error::InvalidCertificate(_)), "{err:?}");
}

#[test]
fn rejects_untrusted_ca() {
    let ca = new_ca("Ledger CA", generate_key().unwrap());
    let other = new_ca("Other CA", generate_key().unwrap());
    let (chain, key) = server_leaf(&ca, generate_key().unwrap());
    let err = handshake(server_config(chain, key).unwrap(), roots(&other))
        .err()
        .unwrap();
    assert!(
        matches!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        ),
        "{err:?}"
    );
}

#[test]
fn csr_is_ml_dsa() {
    let key = generate_key().unwrap();
    let req = csr(&key, vec!["ledger.internal".into()]).unwrap();
    // id-ml-dsa-65, 2.16.840.1.101.3.4.3.18 (RFC 9881)
    let oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
    assert!(req.der().windows(oid.len()).any(|w| w == oid));
    assert!(
        req.pem()
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----")
    );
}
