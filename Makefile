
VERSION=$(shell git describe | sed 's/^v//')

CERT_TOOLS = create-cert create-cert-request \
	create-ca-cert create-crl create-key\
	find-cert create-rand

GODEPS = go/.uuid go/.goflags 

CERT_TOOLS_TAR = cert-tools.tar

all: godeps tar test

# %: %.go  
#GOPATH Mods to enable linux build on MacOSX
# 	GOPATH=$$(pwd)/go go build $<

${CERT_TOOLS}: %: cmd/%/main.go
	GOPATH=$$(pwd)/go go build -o $@ $<

go:
	mkdir go

godeps: go ${GODEPS}
	go version

go/.uuid:
	GOPATH=$$(pwd)/go go get github.com/google/uuid
	touch $@

go/.goflags:
	GOPATH=$$(pwd)/go go get github.com/jessevdk/go-flags
	touch $@

tar:    $(CERT_TOOLS_TAR)


$(CERT_TOOLS_TAR): $(CERT_TOOLS)
	tar cvf $(CERT_TOOLS_TAR) $(CERT_TOOLS)

clean:
	rm -rf $(CERT_TOOLS) $(CERT_TOOLS_TAR) 
	rm -rf go
	rm -rf test-ca

test:  $(CERT_TOOLS) 
	./test-ca-create.sh
