#!/bin/sh
# Description of files
#   root.pem/root.key - cert and key for the Root CA
#   ca1.pem/ca1.key     - cert and key for the Intermediate CA
#   testuser.p12/testuser.cert/testuser.key - cert and key for testuser issued by the Intermediate
#   baduser.p12/baduser.cert/baduser.key   - cert and key for baduser issued by the Intermediate
#   root.crl - Root CRL signed by the Root
#   ca1.crl - CA1 CRL revoking baduser's cert signed by the Intermediate
#   crlchain.pem - root.pem + ca1.pem + root.crl + ca1.crl
#   revoke_list - Input into create-crl that lists the one cert to revoke

mkdir test-ca
cp $0 test-ca/README
cd test-ca
chmod -x ./README

# Create the root CA
../create-key > root.key
../create-ca-cert -k root.key -v 180 -E cyberprobe@trustnetworks.com -C US -O "Trust Networks" -N "Trust Networks CA root" > root.pem

# Create the Intermediate CA1
../create-key > ca1.key
../create-cert-request -E cyberprobe+ca1@trustnetworks.com -N "Trust Networks CA1" -C US -O "Trust Networks" -k ca1.key > ca1.req
../create-cert -k root.key -c root.pem -r ca1.req -A -R > ca1.pem
rm ca1.req


# Create Client Testuser
../create-key > testuser.key
../create-cert-request -E testuser@trustnetworks.com -N "M. Test User" -C US -O "Trust Networks" -k testuser.key > testuser.req
../create-cert -k ca1.key -c ca1.pem  -r testuser.req -C > testuser.cert
rm testuser.req

echo "testuser.p12 Password is: foo"
openssl pkcs12 -export -passout pass:foo -inkey testuser.key -in testuser.cert -caname 'Trust Networks CA1'  -certfile ca1.pem -out testuser.p12

# Create Client Baduser
../create-key > baduser.key
../create-cert-request -E baduser@trustnetworks.com -N "M. Bad User" -C US -O "Trust Networks" -k baduser.key > baduser.req
../create-cert -k ca1.key -c ca1.pem  -r baduser.req -C > baduser.cert
rm baduser.req

echo "baduser.p12 Password is: foo"
openssl pkcs12 -export -passout pass:foo -inkey baduser.key -in baduser.cert -caname 'Trust Networks CA1'  -certfile ca1.pem -out baduser.p12

# Verify all of the certs
openssl verify -CAfile root.pem root.pem
openssl verify -CAfile root.pem ca1.pem 
cat root.pem ca1.pem > chain.pem
openssl verify -CAfile chain.pem testuser.cert 
openssl verify -CAfile chain.pem baduser.cert

# Create and Verify the CRL
../create-crl -k root.key -c root.pem -r /dev/null > root.crl
openssl crl -verify -CAfile root.pem -in root.crl -noout

echo $(openssl x509 -in baduser.cert -serial -noout | cut -f2 -d=),2018-05-08T19:34:05.940Z > revoke_list
../create-crl -k ca1.key -c ca1.pem -r revoke_list >  ca1.crl
openssl crl -verify -CAfile ca1.pem -in ca1.crl -noout

# Test the client certs against the CRL
cat chain.pem root.crl ca1.crl > crlchain.pem
openssl verify -crl_check -CAfile crlchain.pem testuser.cert
openssl verify -crl_check -CAfile crlchain.pem baduser.cert 
