package main

import (

	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

var options struct {
	KeyFile string `short:"k" long:"key" description:"CA private key, PEM format" required:"true"`
	CaFile  string `short:"c" long:"ca-certificate" description:"CA cert file, PEM format" required:"true"`
	RevFile string `short:"r" long:"revoked" description:"List of revoked certificates, form is SERIAL<space>TIME" required:"true"`
	BinaryOut bool `short:"b" long:"binary" description:"Output the CRL in binary form" required:"false"`
}


var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}


func main() {

	// Parse flags
	_, err := flags.Parse(&options)
	if err != nil {
		os.Exit(1)
	}

	// ----- CA key ------

	// Read key file
	raw, err := ioutil.ReadFile(options.KeyFile)
	if err != nil {
		log.Fatalf("failed to read key file: %s", err)
	}

	// Parse key for PEM.
	keyPem, _ := pem.Decode([]byte(raw))
	if keyPem == nil {
		log.Fatalf("failed to read key file")
	}

	// Parse for ECDSA key.
	priv, err := x509.ParseECPrivateKey(keyPem.Bytes)
	if err != nil {
		log.Fatalf("failed to read key file: %s", err)
	}

	// ----- Get CA cert -----

	// Read CA cert file
	raw, err = ioutil.ReadFile(options.CaFile)
	if err != nil {
		log.Fatalf("failed to read certificate file: %s", err)
	}

	// Read CA cert
	caPem, _ := pem.Decode([]byte(raw))
	if caPem == nil {
		log.Fatalf("failed to read certificate file")
	}

	// Parse certificate
	caCert, err := x509.ParseCertificate(caPem.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %s\n", err)
	}

	// ----- Get revoked certs -----

	// Read revoked file
	revFile, err := os.Open(options.RevFile)
	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}

	csvReader := csv.NewReader(revFile)
	csvReader.FieldsPerRecord = 2

	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
	}

	revoked := []pkix.RevokedCertificate{}

	for _, v := range records {

		serial := big.NewInt(0)

		fmt.Sscanf(v[0], "%X", serial)

		tm, _ := time.Parse(time.RFC3339, v[1])

		revoked = append(revoked,
			pkix.RevokedCertificate{
				SerialNumber:   serial,
				RevocationTime: tm,
			})

	}

	// Generate a new CRL


	t := time.Now().UTC()
	crl, err := caCert.CreateCRL(rand.Reader, priv, revoked,
		t, t.Add(100*24*time.Hour))
	
	if err != nil {
		log.Fatalf("failed to generate CRL: %s\n",err);
	}
	


	if options.BinaryOut {
		err = binary.Write(os.Stdout, binary.LittleEndian, crl)
	} else {
		err = pem.Encode(os.Stdout, &pem.Block{
			Type: "X509 CRL",
			Bytes: crl,
		})
	}
	if err != nil {
		log.Fatalf("failed to write CRL: %s\n",err);
	}
	
	os.Exit(0)
}
