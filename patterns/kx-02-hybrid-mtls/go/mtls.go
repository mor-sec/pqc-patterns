// Package mtls implements pattern KX-02: mutual TLS 1.3 between services,
// with a post-quantum hybrid key exchange (RFC 10024) and an allow-list of
// client identities checked inside the handshake.
//
// Each workload has a certificate from an internal CA. Clients are named by
// a single URI SAN, such as spiffe://example.org/billing. Trusting the CA
// proves who a client is; the allow-list decides whether it may connect.
//
// Certificates stay classical (ECDSA). Harvest-now, decrypt-later attacks
// target key exchange, not authentication; track pattern PKI-01 for ML-DSA
// certificates.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"
)

// hybrid lists the post-quantum hybrid groups in preference order. There is
// no classical fallback: both ends are services you control.
var hybrid = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768}

var (
	ErrNoIdentity  = errors.New("mtls: peer certificate must carry exactly one URI SAN")
	ErrNotAllowed  = errors.New("mtls: client identity is not on the allow-list")
	ErrNotVerified = errors.New("mtls: no verified client certificate")
)

// ServerConfig returns a TLS 1.3-only server configuration that requires a
// client certificate issued by clientCAs and naming one of allowed.
func ServerConfig(cert tls.Certificate, clientCAs *x509.CertPool, allowed []string) *tls.Config {
	allowed = slices.Clone(allowed)
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: slices.Clone(hybrid),
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        clientCAs,
		// Runs after chain verification, on every handshake including
		// resumptions, so a rejected identity never reaches the handler.
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := PeerIdentity(cs)
			if err != nil {
				return err
			}
			if !slices.Contains(allowed, id) {
				return ErrNotAllowed
			}
			return nil
		},
	}
}

// ClientConfig returns a TLS 1.3-only client configuration that presents
// cert and verifies the server against roots and serverName.
func ClientConfig(cert tls.Certificate, roots *x509.CertPool, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		RootCAs:          roots,
		ServerName:       serverName,
		CurvePreferences: slices.Clone(hybrid),
	}
}

// PeerIdentity returns the URI SAN of the peer's verified leaf certificate.
// Use it in handlers for authorisation decisions finer than the allow-list.
func PeerIdentity(cs tls.ConnectionState) (string, error) {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return "", ErrNotVerified
	}
	leaf := cs.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 {
		return "", ErrNoIdentity
	}
	return leaf.URIs[0].String(), nil
}
