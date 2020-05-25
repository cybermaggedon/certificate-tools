
package cert_tools

import (
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"io/ioutil"
	"io"
	"encoding/pem"
)

type Key struct {
	key *ecdsa.PrivateKey
}

func NewKey() (*Key, error) {

	// Generate a key.
	c := elliptic.P256()

	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Key{priv}, nil

}

func ReadKeyFromFile(file string) (*Key, error) {
	
	// Read keyfile
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	// Parse PEM in keyfile
	keyPem, _ := pem.Decode([]byte(raw))
	if keyPem == nil {
		return nil, err
	}

	// Parse key from PEM.
	key, err := x509.ParseECPrivateKey(keyPem.Bytes)
	if err != nil {
		return nil, err
	}

	return &Key{key}, nil

}

func (k *Key) ToPem() ([]byte, error) {

	// Marshal as PEM
	return x509.MarshalECPrivateKey(k.key)

}

func (k *Key) OutputPem(out io.Writer) error {
	b, err := k.ToPem()
	if err != nil {
		return err
	}
	return OutputPem(out, b, "EC PRIVATE KEY")
}

func OutputPem(out io.Writer, b []byte, header string) error {
	return pem.Encode(out, &pem.Block{Type: header, Bytes: b})
}

