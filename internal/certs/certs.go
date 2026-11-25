// Package certs generates short-lived, self-signed TLS certificates for the
// lab server, so that no private key ever needs to be committed.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Generated is a freshly generated certificate.
type Generated struct {
	// TLS is ready to use in tls.Config.Certificates.
	TLS tls.Certificate
	// CertPEM is the PEM-encoded certificate (no private key). Clients add
	// it to their root pool.
	CertPEM []byte
}

// SelfSigned creates an ECDSA P-256 certificate valid for hosts (DNS names
// or IP addresses) from now-1m until now+validFor.
func SelfSigned(hosts []string, now time.Time, validFor time.Duration) (Generated, error) {
	if len(hosts) == 0 {
		return Generated{}, errors.New("certs: at least one host is required")
	}
	if validFor <= 0 {
		return Generated{}, errors.New("certs: validity must be positive")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Generated{}, fmt.Errorf("certs: generating key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return Generated{}, fmt.Errorf("certs: generating serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0], Organization: []string{"quic_research lab"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed, so it is its own trust anchor
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return Generated{}, fmt.Errorf("certs: creating certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return Generated{}, fmt.Errorf("certs: parsing certificate: %w", err)
	}
	return Generated{
		TLS:     tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// PoolFromPEM returns a certificate pool containing the certificates in data.
func PoolFromPEM(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("certs: no PEM certificates found")
	}
	return pool, nil
}
