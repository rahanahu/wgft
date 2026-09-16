// Package agentapi はエージェント用 API(仕様 5 節)。公開で、登録と stream だけを受ける。
// TLS 証明書は初回起動で作る有効期限 10 年の自己署名で、秘密鍵ごと SQLite に保存する。
// エージェントは CA ではなく証明書の SHA-256(接続文字列に入っている)で検証する。
package agentapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

const (
	certMeta = "agent_api_cert_pem"
	keyMeta  = "agent_api_key_pem"
)

// LoadOrCreateCert は SQLite の証明書を読み、なければ作って保存する。
func LoadOrCreateCert(st *store.Store) (tls.Certificate, error) {
	certPEM, err := st.GetMeta(certMeta)
	if errors.Is(err, store.ErrNotFound) {
		return createCert(st)
	}
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := st.GetMeta(keyMeta)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate private key: %w", err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func createCert(st *store.Store) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "wgft agent api"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := st.SetMeta(certMeta, certPEM); err != nil {
		return tls.Certificate{}, err
	}
	if err := st.SetMeta(keyMeta, keyPEM); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// Fingerprint は証明書(DER)の SHA-256。接続文字列に入れ、エージェントがピン留めに使う。
func Fingerprint(c tls.Certificate) [32]byte { return sha256.Sum256(c.Certificate[0]) }
