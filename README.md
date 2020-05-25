
# Certificate tools

This is a set of X.509 certificate management tools.  Makes use of Golang
`crypto/x509`.

Simple approach, defaults are all good (Elliptic Curve P256).  All information
is command-line, no configuration files or state.

This just illustrates usage, in normal usage specific handling instructions
would be used to keep some of these files secret.  If you're doing something
in production and are not familiar with the security requirements here,
it is strongly recommended you find a production-grade CA service.

# Usage

To build...

```
  make
```

Executables are built in `go/bin`.

Example usage:

## Create CA key/cert

This just illustrates usage, in normal usage specific handling instructions
would be used to keep some of these files secret.  If you're doing something
in production and are not familiar with the security requirements here,
it is strongly recommended you find a production-grade CA service.

```
  create-key > ca.pem
  create-ca-cert \
      -v 180 -k ca.pem -E ca@example.org \
      -C GB -P Glos -L Cheltenham -U IT -O Example -N CA > ca.crt
  openssl x509 -in ca.crt -noout -text
```

## Create signing req for web site

```
  create-key > example.org.pem
  create-cert-request \
      -k example.org.pem -H example.org,www.example.org -E admin@example.org \
      -C GB -P Glos -L Cheltenham -U IT -O Example -N example.org \
      > example.org.csr
  openssl req -in example.org.csr -noout -text
```

## CA signs request

```
  create-cert \
    -v 90 -k ca.pem -c ca.crt -r example.org.csr \
    -S > example.org.crt
  openssl x509 -in example.org.crt -noout -text
```

