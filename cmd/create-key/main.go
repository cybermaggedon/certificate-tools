package main

import (
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func main() {

	// Generate a key.
	c := elliptic.P256()

	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate private number: %s", err)
	}

	// Output to stdout as PEM.
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("failed to marshal key: %s", err)
	}

	pem.Encode(os.Stdout, &pem.Block{Type: "EC PRIVATE KEY",
		Bytes: b})

}

