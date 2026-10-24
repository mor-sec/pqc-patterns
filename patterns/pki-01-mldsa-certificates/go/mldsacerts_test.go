package mldsacerts

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

const host = "ledger.internal"

type ca struct {
	cert *x509.Certificate
	key  *mldsa.PrivateKey
}

func newCA(t *testing.T, name string) ca {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	root, err := NewRoot(key, name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ca{root, key}
}

func (c ca) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// leaf runs the real flow: key and request on the service, checks and
// issuance on the CA.
func (c ca) leaf(t *testing.T, names ...string) (*x509.Certificate, *mldsa.PrivateKey) {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := CSR(key, names[0], names)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseCSR(der)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := Issue(req, c.cert, c.key, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func (c ca) server(t *testing.T) *tls.Config {
	t.Helper()
	cert, key := c.leaf(t, host)
	cfg, err := ServerConfig([]*x509.Certificate{cert}, key)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// classicalCert makes a certificate with any key and issuer, bypassing the
// package, to stand in for what an attacker or a misconfigured server sends.
func classicalCert(t *testing.T, pub crypto.PublicKey, issuer *x509.Certificate, issuerKey crypto.Signer, isCA bool, names ...string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "classical"},
		DNSNames:              names,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if issuer == nil {
		issuer = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func rawConfig(chain []*x509.Certificate, key crypto.Signer) *tls.Config {
	cert := tls.Certificate{PrivateKey: key}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
}

// handshake runs both sides over loopback TCP. net.Pipe is unbuffered, so a
// client that fails mid-flight and a server still writing would deadlock.
func handshake(t *testing.T, server, client *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		_ = tls.Server(conn, server).Handshake()
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	cli := tls.Client(conn, client)
	err = cli.Handshake()
	conn.Close()
	<-done
	return cli.ConnectionState(), err
}

func TestFullyPostQuantumHandshake(t *testing.T) {
	ca := newCA(t, "test ML-DSA root")
	cs, err := handshake(t, ca.server(t), ClientConfig(ca.pool(), host))
	if err != nil {
		t.Fatal(err)
	}
	if cs.Version != tls.VersionTLS13 || cs.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("version %x, group %v", cs.Version, cs.CurveID)
	}
	leaf := cs.PeerCertificates[0]
	if leaf.SignatureAlgorithm != x509.MLDSA65 || leaf.PublicKeyAlgorithm != x509.MLDSA {
		t.Fatalf("leaf %v with %v key", leaf.SignatureAlgorithm, leaf.PublicKeyAlgorithm)
	}
	if size := len(leaf.Raw); size < 5000 {
		t.Fatalf("leaf is %d bytes, expected an ML-DSA-65 certificate of about 5.5 KB", size)
	}
}

func TestCSRIsMLDSA(t *testing.T) {
	key, _ := GenerateKey()
	der, err := CSR(key, "ledger", []string{host, "ledger.example"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseCSR(der)
	if err != nil {
		t.Fatal(err)
	}
	if req.SignatureAlgorithm != x509.MLDSA65 || !slices.Equal(req.DNSNames, []string{host, "ledger.example"}) {
		t.Fatalf("got %v %v", req.SignatureAlgorithm, req.DNSNames)
	}
}

func TestParseCSRRefusesBadRequests(t *testing.T) {
	key, _ := GenerateKey()
	der, _ := CSR(key, "ledger", []string{host})
	// Change the requested name without re-signing: proof of possession fails.
	tampered := bytes.Replace(der, []byte(host), []byte("ledger.internaX"), 1)
	if bytes.Equal(tampered, der) {
		t.Fatal("test did not change the request")
	}
	if _, err := ParseCSR(tampered); err == nil || !strings.Contains(err.Error(), "request signature") {
		t.Fatalf("broken signature: got %v", err)
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, ec)
	if _, err := ParseCSR(ecDER); !errors.Is(err, ErrNotMLDSA) {
		t.Fatalf("ECDSA request: got %v", err)
	}

	small, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	smallDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, small)
	if _, err := ParseCSR(smallDER); !errors.Is(err, ErrNotMLDSA) {
		t.Fatalf("ML-DSA-44 request: got %v", err)
	}
}

func TestIssueRefusesWrongCAKey(t *testing.T) {
	ca, other := newCA(t, "root"), newCA(t, "other")
	key, _ := GenerateKey()
	der, _ := CSR(key, host, []string{host})
	req, _ := ParseCSR(der)
	if _, err := Issue(req, ca.cert, other.key, time.Hour); err == nil {
		t.Fatal("issued with a key that does not match the CA certificate")
	}
}

func TestServerConfigRefusesClassicalChain(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecRoot := classicalCert(t, &ec.PublicKey, nil, ec, true)
	key, _ := GenerateKey()
	leaf := classicalCert(t, key.PublicKey(), ecRoot, ec, false, host)
	if _, err := ServerConfig([]*x509.Certificate{leaf}, key); !errors.Is(err, ErrNotMLDSA) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsClassicalServerCertificate(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := classicalCert(t, &ec.PublicKey, nil, ec, true)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := classicalCert(t, &leafKey.PublicKey, root, ec, false, host)
	// The client trusts the classical root too, so only the ML-DSA policy
	// stands between it and this server.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := handshake(t, rawConfig([]*x509.Certificate{leaf}, leafKey), ClientConfig(roots, host)); !errors.Is(err, ErrNotMLDSA) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsMLDSALeafUnderClassicalCA(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := classicalCert(t, &ec.PublicKey, nil, ec, true)
	key, _ := GenerateKey()
	leaf := classicalCert(t, key.PublicKey(), root, ec, false, host)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := handshake(t, rawConfig([]*x509.Certificate{leaf}, key), ClientConfig(roots, host)); !errors.Is(err, ErrNotMLDSA) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsUntrustedCA(t *testing.T) {
	trusted, rogue := newCA(t, "trusted"), newCA(t, "rogue")
	_, err := handshake(t, rogue.server(t), ClientConfig(trusted.pool(), host))
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsWrongHostname(t *testing.T) {
	ca := newCA(t, "root")
	cert, key := ca.leaf(t, "elsewhere.internal")
	server, err := ServerConfig([]*x509.Certificate{cert}, key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = handshake(t, server, ClientConfig(ca.pool(), host))
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsClassicalKeyExchange(t *testing.T) {
	ca := newCA(t, "root")
	server := ca.server(t)
	server.CurvePreferences = []tls.CurveID{tls.X25519}
	if _, err := handshake(t, server, ClientConfig(ca.pool(), host)); err == nil {
		t.Fatal("connected over a classical-only key exchange")
	}
}

func TestRequireMLDSAAcceptsOneFullChain(t *testing.T) {
	ca := newCA(t, "root")
	leaf, _ := ca.leaf(t, host)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	classical := classicalCert(t, &ec.PublicKey, nil, ec, true)

	mixed := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, classical}, {leaf, ca.cert}}}
	if err := RequireMLDSA(mixed); err != nil {
		t.Fatalf("one ML-DSA chain should pass: %v", err)
	}
	onlyClassical := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, classical}}}
	if err := RequireMLDSA(onlyClassical); !errors.Is(err, ErrNotMLDSA) {
		t.Fatalf("got %v", err)
	}
	if err := RequireMLDSA(tls.ConnectionState{}); !errors.Is(err, ErrNotMLDSA) {
		t.Fatalf("no verified chain: got %v", err)
	}
}
