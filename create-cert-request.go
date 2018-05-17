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
	"strings"
)

var options struct {
	KeyFile string `short:"k" long:"key" description:"New cert private key, PEM format" required:"true"`
	
	Hosts   string `short:"h" long:"hosts" desription:"Comma separated DNS name or IP address list" default:""`
	EmailAddress       string `short:"E" long:"email" description:"Comma separated Email address list" required:"true"`
	
	Country            string `short:"C" long:"country" description:"Comma separated Country list"`
	Province           string `short:"P" long:"province" description:"Comma separated Province list"`
	Locality           string `short:"L" long:"locality" description:"Comma separated Locality list"`
	OrganizationalUnit string `short:"U" long:"organisational-unit" description:"Comma separated Organizational Unit list"`
	Organization       string `short:"O" long:"organisation" description:"Comma separated Organization list"`
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
	if options.Country != "" {
		subject.Country = strings.Split(options.Country,",")
	}
	if options.Province != "" {
		subject.Province = strings.Split(options.Province,",")
	}
	if options.Locality != "" {
		subject.Locality = strings.Split(options.Locality,",")
	}
	if options.OrganizationalUnit != "" {
		subject.OrganizationalUnit = 
			strings.Split(options.OrganizationalUnit,",")
	}
	if options.Organization != "" {
		subject.Organization = strings.Split(options.Organization,",")
	}
	if options.CommonName != "" {
		subject.CommonName = options.CommonName
	}

	// Start populating certificate request template.
	template := x509.CertificateRequest{
		Subject:            subject,

		EmailAddresses:     strings.Split(options.EmailAddress,","),
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}

	// Populate optional hosts field for DNS names and IP addresses.
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

	// Create certificate request.
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template,
		priv)

	// Write CSR in PEM format.
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST",
		Bytes: csrBytes})

	os.Exit(0)

}
