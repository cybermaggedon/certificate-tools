package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"github.com/google/uuid"
	"math/big"
	"net"
	"os"
	"time"
)

var options struct {
	Validity int64  `short:"v" long:"validity" description:"Certificate validity period (days)" default:"90"`
	KeyFile  string `short:"k" long:"key" description:"CA Private key, PEM format" required:"true"`

	EmailAddress       []string `short:"E" long:"email" description:"Email Address" required:"true"`
	
	Hosts              []string `short:"h" long:"hosts" description:"DNS name or IP addresse"`
	
	Country            []string `short:"C" long:"country" description:"Country"`
	Province           []string `short:"P" long:"province" description:"Province"`
	Locality           []string `short:"L" long:"locality" description:"Locality"`
	OrganizationalUnit []string `short:"U" long:"organisational-unit" description:"Organizational Unit"`
	Organization       []string `short:"O" long:"organisation" description:"Organization"`
	CommonName         string `short:"N" long:"common-name" description:"Common Name" required:"true"`

	CrlUri      []string `short:"d" long:"crl-distribution" description:"CRL Distribution URI" required:"false"`
	CaUri       []string `short:"i" long:"ca-issuers-distribution" description:"CA Issuer Chains (p7c)" required:"false"`

}

// OID of email address.
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func main() {

	// Parse flags.
	_, err := flags.Parse(&options)
	if err != nil {
		os.Exit(1)
	}

	// Read keyfile
	raw, err := ioutil.ReadFile(options.KeyFile)
	if err != nil {
		log.Fatalf("failed to read key file: %s", err)
	}

	// Parse PEM in keyfile
	keyPem, _ := pem.Decode([]byte(raw))
	if keyPem == nil {
		log.Fatalf("failed to parse PEM key")
	}

	// Parse key from PEM.
	key, err := x509.ParseECPrivateKey(keyPem.Bytes)
	if err != nil {
		log.Fatalf("failed to read key file: %s", err)
	}

	// Certificate validity period starts now.
	notBefore := time.Now().UTC()

	// Work out certificate expiry.
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

	
	// Create the certificate subject based on options.
	subject := pkix.Name{}
	if len(options.Country) > 0 {
		subject.Country = options.Country
	}
	if len(options.Province) > 0 {
		subject.Province = options.Province
	}
	if len(options.Locality) > 0 {
		subject.Locality = options.Locality
	}
	if len(options.OrganizationalUnit) > 0 {
		subject.OrganizationalUnit =
			options.OrganizationalUnit
	}
	if len(options.Organization) > 0 {
		subject.Organization =
			options.Organization
	}
	if options.CommonName != "" {
		subject.CommonName = options.CommonName
	}


	// Create populated certificate template
	template := x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA512,
		
		SerialNumber:   serial,
		Subject:        subject,


		NotBefore:      notBefore,
		NotAfter:       notAfter,

		KeyUsage:      x509.KeyUsageCertSign |
			       x509.KeyUsageDigitalSignature |
			       x509.KeyUsageCRLSign,

		IsCA:          true,

		
		ExtKeyUsage: []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,

		EmailAddresses: options.EmailAddress,
		
	}

	// Add optional hosts containing IP address and DNS names.
	if len(options.Hosts) > 0 {
		for _, h := range options.Hosts {
			if ip := net.ParseIP(h); ip != nil {
				template.IPAddresses =
					append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, h)
			}
		}
	}


	pkix, err :=  x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		log.Fatalf("failed to get Public Key bytes: %s", err)
	}

	pkixSum := sha256.Sum256(pkix)
	template.SubjectKeyId = pkixSum[:]
	

	if len(options.CrlUri) > 0 {

		template.CRLDistributionPoints = options.CrlUri
	}

	if len(options.CaUri) > 0 {

		template.IssuingCertificateURL = options.CaUri
	}


	
	// Sign the certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template,
		&template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	// Output certificate in PEM format.
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	os.Exit(0)

}
