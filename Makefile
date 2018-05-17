
VERSION=$(shell git describe | sed 's/^v//')

CERT_TOOLS = create-cert create-cert-request \
	create-ca-cert create-crl create-key\
	find-cert

GODEPS = go/.uuid go/.goflags

CERT_TOOLS_TAR = cert-tools.tar
            
all: tar test

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

tar:    $(CERT_TOOLS_TAR)

$(CERT_TOOLS): godeps

$(CERT_TOOLS_TAR): $(CERT_TOOLS)
	tar cvf $(CERT_TOOLS_TAR) $(CERT_TOOLS)

clean:
	rm -rf $(CERT_TOOLS) $(CERT_TOOLS_TAR) 
	rm -rf go
	rm -rf test-ca

test:  $(CERT_TOOLS) 
	./test-ca-create.sh
