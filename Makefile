
VERSION=$(shell git describe | sed 's/^v//')

CERT_TOOLS = create-cert create-cert-request \
	create-ca-cert create-crl create-key\
	find-cert

GODEPS= go/.uuid go/.goflags
            
all: godeps $(CERT_TOOLS)

%: %.go  
#GOPATH Mods to enable linux build on MacOSX
#	GOPATH=$$(pwd)/go GOOS=linux GOARCH=amd64 go build $< ${CORE}
	GOPATH=$$(pwd)/go go build $< ${CORE}

go:
	mkdir go

godeps: go ${GODEPS}

go/.uuid:
	GOPATH=$$(pwd)/go go get github.com/google/uuid
	touch $@

go/.goflags:
	GOPATH=$$(pwd)/go go get github.com/jessevdk/go-flags
	touch $@

clean:
	rm -rf ${CERT_TOOLS} 
	rm -rf go
