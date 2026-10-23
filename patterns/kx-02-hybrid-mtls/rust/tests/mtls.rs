use std::sync::Arc;

use kx_02_hybrid_mtls::*;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType};
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, Error, NamedGroup, RootCertStore, ServerConfig, ServerConnection,
};

const BILLING: &str = "spiffe://example.org/billing";

struct Ca {
    issuer: Issuer<'static, KeyPair>,
    der: CertificateDer<'static>,
}

type Leaf = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

fn new_ca() -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let der = params.self_signed(&key).unwrap().der().clone();
    Ca {
        issuer: Issuer::new(params, key),
        der,
    }
}

impl Ca {
    fn roots(&self) -> RootCertStore {
        let mut r = RootCertStore::empty();
        r.add(self.der.clone()).unwrap();
        r
    }

    fn server(&self, name: &str) -> Leaf {
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        self.sign(params)
    }

    fn client(&self, uri: &str) -> Leaf {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(uri.try_into().unwrap())];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        self.sign(params)
    }

    fn sign(&self, params: CertificateParams) -> Leaf {
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        let key = PrivatePkcs8KeyDer::from(key.serialize_der());
        (vec![cert.der().clone()], key.into())
    }
}

/// Runs a handshake in memory. Returns the server connection on success.
fn handshake(server: ServerConfig, client: ClientConfig, name: &str) -> Result<ServerConnection, Error> {
    let mut srv = ServerConnection::new(Arc::new(server))?;
    let mut cli = ClientConnection::new(Arc::new(client), ServerName::try_from(name.to_string()).unwrap())?;
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
            return Ok(srv);
        }
    }
    panic!("handshake did not finish");
}

fn setup() -> (Ca, ServerConfig) {
    let ca = new_ca();
    let (chain, key) = ca.server("ledger.internal");
    let srv = server_config(chain, key, ca.roots(), vec![BILLING.to_string()]).unwrap();
    (ca, srv)
}

#[test]
fn mutual_handshake() {
    let (ca, srv) = setup();
    let (chain, key) = ca.client(BILLING);
    let conn = handshake(
        srv,
        client_config(chain, key, ca.roots()).unwrap(),
        "ledger.internal",
    )
    .unwrap();
    assert_eq!(
        conn.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::X25519MLKEM768
    );
    assert_eq!(peer_identity(&conn).as_deref(), Some(BILLING));
}

#[test]
fn rejects_client_without_certificate() {
    let (ca, srv) = setup();
    let cli = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(ca.roots())
        .with_no_client_auth();
    assert!(handshake(srv, cli, "ledger.internal").is_err());
}

#[test]
fn rejects_client_from_other_ca() {
    let (ca, srv) = setup();
    let (chain, key) = new_ca().client(BILLING);
    let cli = client_config(chain, key, ca.roots()).unwrap();
    assert!(handshake(srv, cli, "ledger.internal").is_err());
}

#[test]
fn rejects_identity_not_on_allow_list() {
    let (ca, srv) = setup();
    let (chain, key) = ca.client("spiffe://example.org/reports");
    let cli = client_config(chain, key, ca.roots()).unwrap();
    assert!(matches!(
        handshake(srv, cli, "ledger.internal"),
        Err(Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure
        ))
    ));
}

#[test]
fn rejects_classical_client() {
    let (ca, srv) = setup();
    let (chain, key) = ca.client(BILLING);
    let classical = CryptoProvider {
        kx_groups: vec![kx_group::X25519, kx_group::SECP256R1],
        ..aws_lc_rs::default_provider()
    };
    let cli = ClientConfig::builder_with_provider(Arc::new(classical))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(ca.roots())
        .with_client_auth_cert(chain, key)
        .unwrap();
    assert!(handshake(srv, cli, "ledger.internal").is_err());
}

#[test]
fn client_rejects_wrong_server_name() {
    let (ca, srv) = setup();
    let (chain, key) = ca.client(BILLING);
    let cli = client_config(chain, key, ca.roots()).unwrap();
    assert!(handshake(srv, cli, "payments.internal").is_err());
}
