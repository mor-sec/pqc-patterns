// Package mldsacerts implements pattern PKI-01: ML-DSA certificates and TLS
// 1.3 connections that are post-quantum in both halves, the key exchange
// (hybrid ML-KEM, as in KX-01) and the authentication (ML-DSA signatures on
// the handshake and on every certificate in the chain).
//
// It covers the whole lifecycle with the standard library only (Go 1.27+):
//
//   - GenerateKey and CSR on the service, so the private key never leaves it.
//   - NewRoot, ParseCSR and Issue on the CA, which checks the request's
//     signature before it signs anything.
//   - ServerConfig and ClientConfig for the connection.
//
// crypto/tls has no setting that limits the signature schemes a client
// offers, so ClientConfig enforces the policy after verification instead: a
// connection succeeds only if a verified chain uses ML-DSA keys and
// signatures throughout. The leaf's ML-DSA key also forces an ML-DSA
// handshake signature, because TLS 1.3 signs the handshake with the leaf key.
package mldsacerts

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// hybrid lists the key exchange groups, as in pattern KX-01's strict mode.
// Add tls.SecP384r1MLKEM1024 first for CNSA 2.0 systems.
var hybrid = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768}

// ErrNotMLDSA reports a key, request, certificate or chain that is not
// ML-DSA-65 or ML-DSA-87 throughout.
var ErrNotMLDSA = errors.New("mldsacerts: not ML-DSA-65 or ML-DSA-87")

// GenerateKey returns a new ML-DSA-65 key. Store it with
// x509.MarshalPKCS8PrivateKey, or as in pattern KEY-01.
func GenerateKey() (*mldsa.PrivateKey, error) {
	return mldsa.GenerateKey(mldsa.MLDSA65())
}

// CSR returns a DER PKCS#10 request for dnsNames, signed by key. Send it to
// your CA; the key stays with the service.
func CSR(key *mldsa.PrivateKey, commonName string, dnsNames []string) ([]byte, error) {
	if !allowedKey(key.PublicKey()) {
		return nil, ErrNotMLDSA
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}, key)
}

// NewRoot returns a self-signed ML-DSA root certificate for a private CA.
// Keep its key offline or in an HSM.
func NewRoot(key *mldsa.PrivateKey, commonName string, lifetime time.Duration) (*x509.Certificate, error) {
	if !allowedKey(key.PublicKey()) {
		return nil, ErrNotMLDSA
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(lifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ParseCSR parses a request and checks its signature, which proves the
// requester holds the private key. It refuses anything but ML-DSA. Check that
// the requester may use req.DNSNames before you call Issue.
func ParseCSR(der []byte) (*x509.CertificateRequest, error) {
	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	if err := checkRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

func checkRequest(req *x509.CertificateRequest) error {
	if err := req.CheckSignature(); err != nil {
		return fmt.Errorf("mldsacerts: request signature: %w", err)
	}
	pub, ok := req.PublicKey.(*mldsa.PublicKey)
	if !ok || !allowedKey(pub) || !allowedSignature(req.SignatureAlgorithm) {
		return ErrNotMLDSA
	}
	return nil
}

// Issue signs a TLS server certificate for a request from ParseCSR. Only the
// request's key and DNS names are copied; the CA sets everything else. It
// checks the request again, so a request that skipped ParseCSR is still
// refused if its signature or key is wrong.
func Issue(req *x509.CertificateRequest, ca *x509.Certificate, caKey *mldsa.PrivateKey, lifetime time.Duration) (*x509.Certificate, error) {
	if err := checkRequest(req); err != nil {
		return nil, err
	}
	if !isMLDSA(ca) || !ca.IsCA || !caKey.PublicKey().Equal(ca.PublicKey) {
		return nil, ErrNotMLDSA
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.Subject.CommonName},
		DNSNames:     req.DNSNames,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, req.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ServerConfig returns a TLS 1.3-only server configuration that presents
// chain (leaf first, then intermediates) with key. It refuses a chain with
// any certificate that is not ML-DSA.
func ServerConfig(chain []*x509.Certificate, key *mldsa.PrivateKey) (*tls.Config, error) {
	if len(chain) == 0 || !key.PublicKey().Equal(chain[0].PublicKey) {
		return nil, errors.New("mldsacerts: key does not match the leaf certificate")
	}
	cert := tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, c := range chain {
		if !isMLDSA(c) {
			return nil, ErrNotMLDSA
		}
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: append([]tls.CurveID(nil), hybrid...),
	}, nil
}

// ClientConfig returns a TLS 1.3-only client configuration that trusts roots
// and accepts a server only if a verified chain is ML-DSA throughout.
func ClientConfig(roots *x509.CertPool, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		RootCAs:          roots,
		ServerName:       serverName,
		CurvePreferences: append([]tls.CurveID(nil), hybrid...),
		VerifyConnection: RequireMLDSA,
	}
}

// RequireMLDSA checks a verified connection. ClientConfig installs it; call
// it from your own VerifyConnection hook if you build the config yourself.
//
// One fully ML-DSA chain is enough: a classical chain that also verifies
// (for example through a cross-signed CA during migration) does not help an
// attacker who would still have to forge the ML-DSA one.
func RequireMLDSA(cs tls.ConnectionState) error {
	for _, chain := range cs.VerifiedChains {
		if allMLDSA(chain) {
			return nil
		}
	}
	return ErrNotMLDSA
}

func allMLDSA(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	for _, c := range chain {
		if !isMLDSA(c) {
			return false
		}
	}
	return true
}

// isMLDSA reports whether c has an allowed ML-DSA key and is signed with an
// allowed ML-DSA algorithm. For a root this covers its self-signature.
func isMLDSA(c *x509.Certificate) bool {
	pub, ok := c.PublicKey.(*mldsa.PublicKey)
	return ok && allowedKey(pub) && allowedSignature(c.SignatureAlgorithm)
}

// ML-DSA-44 is left out, as in the Rust and Java versions: NIST category 2
// is below this catalog's minimum.
func allowedKey(pub *mldsa.PublicKey) bool {
	p := pub.Parameters()
	return p == mldsa.MLDSA65() || p == mldsa.MLDSA87()
}

func allowedSignature(a x509.SignatureAlgorithm) bool {
	return a == x509.MLDSA65 || a == x509.MLDSA87
}

// serialNumber returns a random positive 127-bit serial, well inside the
// 20-octet limit of RFC 5280.
func serialNumber() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}
