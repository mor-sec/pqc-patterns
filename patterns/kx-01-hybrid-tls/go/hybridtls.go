// Package hybridtls implements pattern KX-01: TLS 1.3 configuration that
// negotiates a hybrid post-quantum key exchange (RFC 10024).
//
// Go 1.24+ already offers X25519MLKEM768 by default. This package makes the
// policy explicit and testable, so a GODEBUG flag, a dependency, or a
// copy-pasted CurvePreferences list cannot silently downgrade it:
//
//   - Strict: only hybrid groups. Peers that cannot do post-quantum key
//     exchange fail the handshake. Use for service-to-service traffic you
//     control.
//   - Compatible: hybrid groups first, classical X25519 as fallback. Use for
//     public endpoints until your clients are upgraded.
//
// Certificates and signatures remain classical (ECDSA P-256 here). That is
// acceptable today: harvest-now-decrypt-later attacks target key exchange,
// not authentication. Track pattern PKI-01 for ML-DSA certificates.
package hybridtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

type Mode int

const (
	Strict Mode = iota
	Compatible
)

// Hybrid lists the post-quantum hybrid groups in preference order. Add
// tls.SecP384r1MLKEM1024 first for CNSA 2.0 systems.
var Hybrid = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768}

func curves(m Mode) []tls.CurveID {
	c := append([]tls.CurveID(nil), Hybrid...)
	if m == Compatible {
		c = append(c, tls.X25519)
	}
	return c
}

// ServerConfig returns a TLS 1.3-only server configuration.
func ServerConfig(cert tls.Certificate, m Mode) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: curves(m),
	}
}

// ClientConfig returns a TLS 1.3-only client configuration that trusts roots.
func ClientConfig(roots *x509.CertPool, serverName string, m Mode) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		RootCAs:          roots,
		ServerName:       serverName,
		CurvePreferences: curves(m),
	}
}

// ErrClassicalKeyExchange reports a connection that did not use a hybrid group.
var ErrClassicalKeyExchange = errors.New("hybridtls: connection did not negotiate a post-quantum hybrid key exchange")

// RequireHybrid checks a completed handshake. Call it from monitoring or a
// VerifyConnection hook to alert on, or refuse, classical-only connections.
func RequireHybrid(cs tls.ConnectionState) error {
	for _, c := range Hybrid {
		if cs.CurveID == c {
			return nil
		}
	}
	return ErrClassicalKeyExchange
}
