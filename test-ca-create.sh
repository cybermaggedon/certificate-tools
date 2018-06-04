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

rm -rf test-ca
mkdir test-ca
cp $0 test-ca/README
cd test-ca
chmod -x ./README

# Create the root CA
../create-key > root.key || exit 1
../create-ca-cert -k root.key -v 180 -E cyberprobe@trustnetworks.com -C US -O "Trust Networks" -N "Trust Networks CA root" > root.pem || exit 1

# Create the Intermediate CA1
../create-key > ca1.key || exit 1
../create-cert-request -E cyberprobe+ca1@trustnetworks.com -N "Trust Networks CA1" -C US -O "Trust Networks" -k ca1.key > ca1.req || exit 1
../create-cert -k root.key -c root.pem -r ca1.req -A -R > ca1.pem || exit 1
rm ca1.req


# Create Client Testuser
../create-key > testuser.key || exit 1
../create-cert-request -E testuser@trustnetworks.com -N "M. Test User" -C US -O "Trust Networks" -k testuser.key > testuser.req || exit 1
../create-cert -k ca1.key -c ca1.pem  -r testuser.req -C > testuser.cert || exit 1
rm testuser.req

echo "testuser.p12 Password is: foo"
openssl pkcs12 -export -passout pass:foo -inkey testuser.key -in testuser.cert -caname 'Trust Networks CA1'  -certfile ca1.pem -out testuser.p12 || exit 1

# Create Client Baduser
../create-key > baduser.key || exit 1
../create-cert-request -E baduser@trustnetworks.com -N "M. Bad User" -C US -O "Trust Networks" -k baduser.key > baduser.req
../create-cert -k ca1.key -c ca1.pem  -r baduser.req -C > baduser.cert || exit 1
rm baduser.req

echo "baduser.p12 Password is: foo"
openssl pkcs12 -export -passout pass:foo -inkey baduser.key -in baduser.cert -caname 'Trust Networks CA1'  -certfile ca1.pem -out baduser.p12 || exit 1

# Verify all of the certs
openssl verify -CAfile root.pem root.pem || exit 1
openssl verify -CAfile root.pem ca1.pem  || exit 1
cat root.pem ca1.pem > chain.pem
openssl verify -CAfile chain.pem testuser.cert  || exit 1
openssl verify -CAfile chain.pem baduser.cert || exit 1

# Create and Verify the CRL
../create-crl -k root.key -c root.pem -r /dev/null > root.crl || exit 1
openssl crl -verify -CAfile root.pem -in root.crl -noout || exit 1


../find-cert -d . -p baduser.cert  > revoke_list
../create-crl -k ca1.key -c ca1.pem -r revoke_list >  ca1.crl || exit 1
openssl crl -verify -CAfile ca1.pem -in ca1.crl -noout || exit 1

# Test the client certs against the CRL
cat chain.pem root.crl ca1.crl > crlchain.pem || exit 1
openssl verify -crl_check -CAfile crlchain.pem testuser.cert || exit 1
openssl verify -crl_check -CAfile crlchain.pem baduser.cert  && exit 1

# Test create-rand
N=$(../create-rand -b 16 -c 64 | wc -c | sed -e"s/ //g")
if [ "$N" != "1024" ]; then
 echo "create-rand: failed $N != 1024"
 exit 1
else 
 echo "create-rand: OK"
fi 
exit 0
