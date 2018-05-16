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
	"strings"
	"time"
)

var options struct {
	Validity int64  `short:"v" long:"validity" description:"Certificate validity period (days)" default:"90"`
	KeyFile  string `short:"k" long:"key" description:"CA Private key, PEM format" required:"true"`

	EmailAddress       string `short:"E" long:"email" description:"Email address" required:"true"`
	Hosts              string `short:"h" long:"hosts" desription:"Comma-separated list of hosts or IP addresses" default:""`
	
	Country            string `short:"C" long:"country" description:"Country"`
	Province           string `short:"P" long:"province" description:"Province"`
	Locality           string `short:"L" long:"locality" description:"Locality"`
	OrganizationalUnit string `short:"U" long:"organisational-unit" description:"Organizational Unit"`
	Organization       string `short:"O" long:"organisation" description:"Organization"`
	CommonName         string `short:"N" long:"common-name" description:"Country" required:"true"`

	CrlUri      string `short:"d" long:"crl-distribution" description:"Comma separated list of CRL Distribution URIs" required:"false"`
	CaUri       string `short:"i" long:"ca-issuers-distribution" description:"Comma separated list of CA Issuer Chains (p7c)" required:"false"`

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
	notBefore := time.Now()

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
	if options.Country != "" {
		subject.Country = []string{options.Country}
	}
	if options.Province != "" {
		subject.Province = []string{options.Province}
	}
	if options.Locality != "" {
		subject.Locality = []string{options.Locality}
	}
	if options.OrganizationalUnit != "" {
		subject.OrganizationalUnit =
			[]string{options.OrganizationalUnit}
	}
	if options.Organization != "" {
		subject.Organization = []string{options.Organization}
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

		EmailAddresses: []string{options.EmailAddress},
		
	}

	// Add optional hosts containing IP address and DNS names.
	if options.Hosts != "" {
		hosts := strings.Split(options.Hosts, ",")
		for _, h := range hosts {
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
	

	if options.CrlUri != "" {

		uris := strings.Split(options.CrlUri,",")
		for _, u := range uris {
			template.CRLDistributionPoints = append(template.CRLDistributionPoints,u)
		}

	}

	if options.CaUri != "" {

		uris := strings.Split(options.CaUri,",")
		for _, u := range uris {
			template.IssuingCertificateURL = append(template.IssuingCertificateURL,u)
		}
		
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
