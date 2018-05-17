package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"github.com/google/uuid"
	"math/big"
	"os"
	"time"
	"strings"
)

var options struct {
	Validity    int64  `short:"v" long:"validity" description:"Certificate validity period (days)" default:"90"`
	KeyFile     string `short:"k" long:"key" description:"CA private key, PEM format" required:"true"`
	CaFile      string `short:"c" long:"ca-certificate" description:"CA cert file, PEM format" required:"true"`
	CsrFile     string `short:"r" long:"certificate-request" description:"CSR file, PEM format" required:"true"`
	ServerUsage bool   `short:"S" long:"server-usage" description:"Specifies to create a server certificate"`
	ClientUsage bool   `short:"C" long:"client-usage" description:"Specifies to create a client certificate"`
	CaUsage     bool   `short:"A" long:"ca-usage" description:"Specifies to create a CA certificate"`
	CRLUsage    bool   `short:"R" long:"crl-usage" description:"Specifies to create a CRL issuer certificate"`
	
	CrlUri      string `short:"d" long:"crl-distribution" description:"Comma separated list of CRL Distribution URIs" required:"false"`
	CaUri       string `short:"i" long:"ca-issuers-distribution" description:"Comma separated list of CA Issuer Chains (p7c)" required:"false"`
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

	// ----- Get CSR -----

	// Read CSR file
	raw, err = ioutil.ReadFile(options.CsrFile)
	if err != nil {
		log.Fatalf("failed to read CSR file: %s", err)
	}

	// Parse CSR for PEM
	csrPem, _ := pem.Decode([]byte(raw))
	if csrPem == nil {
		log.Fatalf("failed to read CSR file")
	}

	// Parse PEM for certificate request.
	clientCSR, err := x509.ParseCertificateRequest(csrPem.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate request: %s\n", err)
	}
	if err = clientCSR.CheckSignature(); err != nil {
		log.Fatalf("failed to check certificate request signing: %s\n",
			err)
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

	// Work out certificate start time
	notBefore := time.Now().UTC()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n",
			err)
		os.Exit(1)
	}

	// Work out certificate expiry
	duration := time.Duration(options.Validity*24) * time.Hour
	notAfter := notBefore.Add(duration)

	// Make up a random serial number.

	uuidVal, err := uuid.NewRandom()
	if err != nil {
		log.Fatalf("failed to generate uuid: %s", err)
	}
	
	uuidBytes,err := uuidVal.MarshalBinary()

	if err != nil {
		log.Fatalf("failed to generate serial: %s", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial            := serialNumberLimit.SetBytes(uuidBytes)

	// Populate client certificate template
	template := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: serial,
		Issuer:       caCert.Subject,

	        Subject:      clientCSR.Subject,
		
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage: x509.KeyUsageDigitalSignature,
		
		ExtKeyUsage: []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,


		DNSNames:       clientCSR.DNSNames,
		IPAddresses:    clientCSR.IPAddresses,
		EmailAddresses: clientCSR.EmailAddresses,


	}

	pkix, err :=  x509.MarshalPKIXPublicKey(template.PublicKey)
	if err != nil {
		log.Fatalf("failed to get Public Key bytes: %s", err)
	}

	pkixSum := sha256.Sum256(pkix)
	template.SubjectKeyId = pkixSum[:]
	
	// Add server usage if required
	if options.ServerUsage {
		template.ExtKeyUsage = append(template.ExtKeyUsage,
			x509.ExtKeyUsageServerAuth)
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	// Add client usage if required
	if options.ClientUsage {
		template.ExtKeyUsage = append(template.ExtKeyUsage,
			x509.ExtKeyUsageClientAuth)
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	// Set CA attributes in certificate if required.
	if options.CaUsage {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// Set CRL attributes in certificate if required
	if options.CRLUsage {
		template.KeyUsage |= x509.KeyUsageCRLSign
	}

	if options.CrlUri != "" {

		template.CRLDistributionPoints = strings.Split(options.CrlUri,",")

	} else {

		template.CRLDistributionPoints = caCert.CRLDistributionPoints
	}

	if options.CaUri != "" {

		template.IssuingCertificateURL = strings.Split(options.CaUri,",")
		
	} else {

		template.IssuingCertificateURL = caCert.IssuingCertificateURL
	}


	
	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &template,
		caCert, clientCSR.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE",
		Bytes: clientCRTRaw})

}
