package mtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

const billing = "spiffe://example.org/billing"

type ca struct {
	cert *x509.Certificate
	key  crypto.Signer
	pool *x509.CertPool
}

func newCA(t *testing.T) ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test internal CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return ca{cert, key, pool}
}

// issue makes a leaf for a server (dnsName set) or a client (uri set).
func (c ca) issue(t *testing.T, dnsName, uri string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if dnsName != "" {
		tmpl.DNSNames = []string{dnsName}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake runs a TLS handshake over an in-memory pipe and returns the
// server's view of the connection and both sides' errors.
func handshake(server, client *tls.Config) (tls.ConnectionState, error, error) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	srv := tls.Server(a, server)
	errc := make(chan error, 1)
	go func() { errc <- tls.Client(b, client).Handshake(); b.Close() }()
	serr := srv.Handshake()
	a.Close()
	return srv.ConnectionState(), serr, <-errc
}

func setup(t *testing.T) (ca, *tls.Config) {
	root := newCA(t)
	srv := ServerConfig(root.issue(t, "ledger.internal", ""), root.pool, []string{billing})
	return root, srv
}

func TestMutualHandshake(t *testing.T) {
	root, srv := setup(t)
	cli := ClientConfig(root.issue(t, "", billing), root.pool, "ledger.internal")
	cs, serr, cerr := handshake(srv, cli)
	if serr != nil || cerr != nil {
		t.Fatalf("handshake failed: server=%v client=%v", serr, cerr)
	}
	if cs.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("negotiated %v, want X25519MLKEM768", cs.CurveID)
	}
	if id, err := PeerIdentity(cs); err != nil || id != billing {
		t.Fatalf("peer identity %q, %v", id, err)
	}
}

func TestRejectsClientWithoutCertificate(t *testing.T) {
	root, srv := setup(t)
	cli := ClientConfig(tls.Certificate{}, root.pool, "ledger.internal")
	cli.Certificates = nil
	if _, serr, _ := handshake(srv, cli); serr == nil {
		t.Fatal("server accepted a client without a certificate")
	}
}

func TestRejectsClientFromOtherCA(t *testing.T) {
	root, srv := setup(t)
	rogue := newCA(t)
	cli := ClientConfig(rogue.issue(t, "", billing), root.pool, "ledger.internal")
	if _, serr, _ := handshake(srv, cli); serr == nil {
		t.Fatal("server accepted a client certificate from an untrusted CA")
	}
}

func TestRejectsIdentityNotOnAllowList(t *testing.T) {
	root, srv := setup(t)
	cli := ClientConfig(root.issue(t, "", "spiffe://example.org/reports"), root.pool, "ledger.internal")
	if _, serr, _ := handshake(srv, cli); !errors.Is(serr, ErrNotAllowed) {
		t.Fatalf("want ErrNotAllowed, got %v", serr)
	}
}

func TestRejectsClassicalClient(t *testing.T) {
	root, srv := setup(t)
	cli := ClientConfig(root.issue(t, "", billing), root.pool, "ledger.internal")
	cli.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	if _, serr, _ := handshake(srv, cli); serr == nil {
		t.Fatal("server accepted a classical-only key exchange")
	}
}

func TestClientRejectsWrongServerName(t *testing.T) {
	root, srv := setup(t)
	cli := ClientConfig(root.issue(t, "", billing), root.pool, "payments.internal")
	if _, _, cerr := handshake(srv, cli); cerr == nil {
		t.Fatal("client accepted a server certificate for another name")
	}
}
