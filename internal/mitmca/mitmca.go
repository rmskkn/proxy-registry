// Package mitmca generates a local root CA, persisted to disk, and signs
// per-hostname leaf certificates on demand. This lets the proxy terminate
// HTTPS for clients that have been pointed at it out-of-band (e.g. via
// /etc/hosts), since it doesn't hold the real upstream's certificate. The
// root certificate must be installed into every client's trust store for
// this to work - see README.
package mitmca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA signs leaf certificates against a root key/cert pair, caching the
// result per hostname so repeat handshakes don't re-sign.
type CA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// CertPath is where the root certificate is written, in PEM form, for
// installing into a client's trust store.
func CertPath(dir string) string { return filepath.Join(dir, "ca-cert.pem") }

func keyPath(dir string) string { return filepath.Join(dir, "ca-key.pem") }

// Load reads a root CA from dir. The CA must already exist there as
// ca-cert.pem / ca-key.pem (see README for generating one with openssl) -
// this package never generates one itself.
func Load(dir string) (*CA, error) {
	cp, kp := CertPath(dir), keyPath(dir)

	certPEM, err := os.ReadFile(cp)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate %s (generate one with openssl and place it here - see README): %w", cp, err)
	}
	keyPEM, err := os.ReadFile(kp)
	if err != nil {
		return nil, fmt.Errorf("reading CA key %s (generate one with openssl and place it here - see README): %w", kp, err)
	}
	cert, key, err := decode(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, leafs: map[string]*tls.Certificate{}}, nil
}

func decode(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid CA key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		return cert, key, nil
	}
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := pkcs8Key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not an RSA key")
	}
	return cert, key, nil
}

// GetCertificate implements tls.Config.GetCertificate, signing (and
// caching) a leaf certificate for the requested SNI hostname on first use.
func (ca *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		return nil, fmt.Errorf("mitmca: client sent no SNI hostname")
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()
	if leaf, ok := ca.leafs[name]; ok {
		return leaf, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  key,
	}
	ca.leafs[name] = leaf
	return leaf, nil
}
