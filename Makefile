
VERSION=$(shell git describe | sed 's/^v//')

CERT_TOOLS = create-cert create-cert-request create-ca-cert create-crl \
        create-key find-cert create-rand

CERT_TOOLS_TAR = cert-tools.tar

all: tar

tar:    $(CERT_TOOLS_TAR)

$(CERT_TOOLS_TAR): FORCE
	GOPATH=$$(pwd)/go go install ./...
	(cd go/bin; tar cvf - ${CERT_TOOLS}) > ${CERT_TOOLS_TAR}

FORCE:

clean:
	rm -rf go
	rm -rf test-ca
	rm -rf $(CERT_TOOLS_TAR) 

# test:  $(CERT_TOOLS) 
test:
	./test-ca-create.sh
