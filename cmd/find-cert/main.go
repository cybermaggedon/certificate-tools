package main

import (
	//	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	//	"encoding/binary"
	//	"encoding/csv"
	"encoding/pem"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	//	"math/big"
	"os"
	"time"
	"strings"
)

var options struct {
	Email string `short:"e" long:"email" description:"E-mail to locate in a cert" default:"" required:"false"`
	Subject string`short:"s" long:"subject" description:"Subject substring to match" default:"" required:"false"`
	CertPrefix  string `short:"p" long:"prefix" description:"Prefix of Cert file, PEM format" required:"true"`
	CertDir string `short:"d" long:"directory" description:"Directory to search" required:"true"`
	Verbose []bool `short:"v" long:"verbose" description:"Verbosity" required:"false"`
	Extended bool `short:"x" long:"extended" description:"Extended Output" required:"false"` 
	ExceptLatest bool `short:"l" long:"exceptlatest" description:"Show all but latest certificate" required:"false"`
	OnlyLatest bool `short:"L" long:"onlylatest" description:"Show only latest certificate" required:"false"`
}

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

type certtab struct {
	Cert *x509.Certificate
	Issued time.Time
	Email string
	Revoke bool
}

//type Name struct {
//	Country, Organization, OrganizationalUnit []string
//	Locality, Province                        []string
//	StreetAddress, PostalCode                 []string
//	SerialNumber, CommonName                  string

//	Names      []AttributeTypeAndValue
//	ExtraNames []AttributeTypeAndValue
//}

func stringListContains(l []string, s string) bool {
	for _, le := range l {
		if strings.Contains(le,s) {
			return true
		}
	}
	return false
}

func nameContains(n pkix.Name, s string) bool {

	return 	strings.Contains(n.CommonName,s) ||
		stringListContains(n.OrganizationalUnit,s) ||
		stringListContains(n.Organization,s) ||
		stringListContains(n.Country,s) ||
		stringListContains(n.Locality,s) ||
		stringListContains(n.Province,s) ||
		stringListContains(n.PostalCode,s) ||
		stringListContains(n.StreetAddress,s)
}

func main() {

	// Parse flags
	_, err := flags.Parse(&options)
	if err != nil {
		os.Exit(1)
	}


	files,err := ioutil.ReadDir(options.CertDir)
	if err != nil {
		log.Fatal("Failed to read certificate directory: %s", err)
	}

	certMap := map[string][]certtab{}
	
	
	for _, certFile := range files {

		// Temporarily hold the filename that we are examining
		tmpName :=  certFile.Name()

		// Verify that the prefix matches
		if strings.HasPrefix(tmpName,options.CertPrefix) {
			
			// Read cert file
			raw, err := ioutil.ReadFile(options.CertDir + "/" + tmpName)
			if err != nil {
				log.Fatalf("failed to read certificate file: %s", err)
			}
			
			// Read cert
			testPem, _ := pem.Decode([]byte(raw))
			if testPem == nil {
				log.Fatalf("failed to read certificate file")
			}
			
			// Parse certificate
			testCert, err := x509.ParseCertificate(testPem.Bytes)
			if err != nil {
				log.Fatalf("failed to parse certificate: %s\n", err)
			}


			// Look through the array of email addresses in the Cert for a Match
			// then optionally look for the provided Subject substring in the Cert Subject field
			for _,email := range testCert.EmailAddresses {
				if (options.Email == "" || email == options.Email) &&
					(options.Subject == "" || nameContains(testCert.Subject,options.Subject)) {

					// Everything matched, print out file name and go on to the next file
					if len(options.Verbose) > 0 {
						fmt.Printf("%s|%d|%d|%s\n",
							tmpName,
							testCert.NotBefore.Unix(),
							testCert.NotAfter.Unix(),
							email)
					}
					certMap[email] = append(certMap[email],
						certtab{
							Cert: testCert,
							Issued: testCert.NotBefore,
							Revoke: true,
							Email: email,
						})
					break
				}
			}

			
			
		}
	}

	// -- Check to see if the user wants to keep the latest issued certificate

	
	for email,certs := range certMap {
		if options.ExceptLatest || options.OnlyLatest {
			latest := 0
			latestIssued := time.Unix(0,0)
			for i,c :=range certs {
				if len(options.Verbose) > 0 {
					fmt.Printf("? %s|%X|%s\n",
						email,c.Cert.SerialNumber,
						c.Issued.UTC().Format(time.RFC3339))
				}
				
				if c.Issued.After(latestIssued) {
					if len(options.Verbose) > 0 {
						fmt.Printf("?>%s|%X|%s\n",
							email,c.Cert.SerialNumber,
							c.Issued.UTC().Format(time.RFC3339))
					}
					
					latest = i
					latestIssued = c.Issued
				}
			}
			if len(options.Verbose) > 0 {
				fmt.Printf("?*%s|%X|%s\n",
					email,
					certs[latest].Cert.SerialNumber,
					certs[latest].Issued.UTC().Format(time.RFC3339))
			}
			
			certs[latest].Revoke = false
		}


		// -- Output the list of certificates in the form: filename,Serial,Now
		
		for _, c := range certs {

			if ( options.OnlyLatest && !c.Revoke) ||
				(options.ExceptLatest && c.Revoke) ||
				(!options.ExceptLatest && !options.OnlyLatest && c.Revoke) {
				
				if options.Extended {
					fmt.Printf("%016X,%s,%s,%s,%s,%s\n",c.Cert.SerialNumber.Bytes(),c.Email,
						c.Cert.Subject.Organization, c.Cert.Subject.OrganizationalUnit,
						c.Cert.Subject.CommonName,c.Issued.UTC().Format(time.RFC3339))
				} else {
					fmt.Printf("%016X,%s\n",c.Cert.SerialNumber.Bytes(),time.Now().UTC().Format(time.RFC3339))
				}
				
			}
		}
	}
}
