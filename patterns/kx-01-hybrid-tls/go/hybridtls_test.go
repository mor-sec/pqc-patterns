package hybridtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svc.internal"},
		DNSNames:              []string{"svc.internal"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// handshake runs a TLS handshake over an in-memory pipe and returns the
// client's view of the connection and both sides' errors.
func handshake(server, client *tls.Config) (tls.ConnectionState, error, error) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	srv := tls.Server(a, server)
	errc := make(chan error, 1)
	go func() { errc <- srv.Handshake(); a.Close() }()
	cli := tls.Client(b, client)
	cerr := cli.Handshake()
	b.Close()
	return cli.ConnectionState(), cerr, <-errc
}

func TestStrictNegotiatesHybrid(t *testing.T) {
	cert, roots := testCert(t)
	cs, cerr, serr := handshake(ServerConfig(cert, Strict), ClientConfig(roots, "svc.internal", Strict))
	if cerr != nil || serr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", cerr, serr)
	}
	if cs.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("negotiated %v, want X25519MLKEM768", cs.CurveID)
	}
	if err := RequireHybrid(cs); err != nil {
		t.Fatal(err)
	}
}

func TestStrictRejectsClassicalClient(t *testing.T) {
	cert, roots := testCert(t)
	legacy := ClientConfig(roots, "svc.internal", Strict)
	legacy.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	if _, cerr, _ := handshake(ServerConfig(cert, Strict), legacy); cerr == nil {
		t.Fatal("strict server accepted a classical-only client")
	}
}

func TestCompatibleFallsBackAndIsDetected(t *testing.T) {
	cert, roots := testCert(t)
	legacy := ClientConfig(roots, "svc.internal", Compatible)
	legacy.CurvePreferences = []tls.CurveID{tls.X25519}
	cs, cerr, serr := handshake(ServerConfig(cert, Compatible), legacy)
	if cerr != nil || serr != nil {
		t.Fatalf("compatible mode should accept classical clients: %v %v", cerr, serr)
	}
	if err := RequireHybrid(cs); err == nil {
		t.Fatal("classical connection not flagged")
	}
}

func TestRejectsTLS12(t *testing.T) {
	cert, roots := testCert(t)
	old := ClientConfig(roots, "svc.internal", Compatible)
	old.MinVersion, old.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if _, cerr, _ := handshake(ServerConfig(cert, Compatible), old); cerr == nil {
		t.Fatal("TLS 1.2 accepted")
	}
}
