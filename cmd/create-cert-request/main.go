package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"net"
	"os"
)

var options struct {
	KeyFile string `short:"k" long:"key" description:"New cert private key, PEM format" required:"true"`
	
	Hosts              []string `short:"h" long:"hosts" description:"DNS name or IP address"`
	EmailAddress       []string `short:"E" long:"email" description:"Email address" required:"true"`
	
	Country            []string `short:"C" long:"country" description:"Country"`
	Province           []string `short:"P" long:"province" description:"Province"`
	Locality           []string `short:"L" long:"locality" description:"Locality"`
	OrganizationalUnit []string `short:"U" long:"organisational-unit" description:"Organizational Unit"`
	Organization       []string `short:"O" long:"organisation" description:"Organization"`
	
	CommonName         string `short:"N" long:"common-name" description:"Common Name" required:"true"`
}

// OID of email address.
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func main() {

	// Parse flags.
	_, err := flags.Parse(&options)
	if err != nil {
		os.Exit(1)
	}

	// Read key file
	raw, err := ioutil.ReadFile(options.KeyFile)
	if err != nil {
		log.Fatalf("failed to read key file: %s", err)
	}

	// Parse KEY PEM.
	keyPem, _ := pem.Decode([]byte(raw))
	if keyPem == nil {
		log.Fatalf("failed to read key file")
	}

	// Parse key for private key.
	priv, err := x509.ParseECPrivateKey(keyPem.Bytes)
	if err != nil {
		log.Fatalf("failed to read key file: %s", err)
	}

	// Create a certificate subject and populate based on fields.
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
		subject.Organization = options.Organization
	}
	if options.CommonName != "" {
		subject.CommonName = options.CommonName
	}

	// Start populating certificate request template.
	template := x509.CertificateRequest{
		Subject:            subject,

		EmailAddresses:     options.EmailAddress,
		
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}

	// Populate optional hosts field for DNS names and IP addresses.
	if len(options.Hosts) > 0 {
		for _, h := range options.Hosts {
			ip := net.ParseIP(h)
            if ip != nil {
				template.IPAddresses =
					append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, h)
			}
		}
	}

	// Create certificate request.
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template,
		priv)

	// Write CSR in PEM format.
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST",
		Bytes: csrBytes})

	os.Exit(0)

}
