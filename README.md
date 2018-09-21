
To build...

```
  GOPATH=$(pwd)/go go get -u github.com/jessevdk/go-flags
  GOPATH=$(pwd)/go go get -u github.com/google/uuid
  GOPATH=$(pwd)/go go get -u github.com/trustnetworks/certificate-tools
```

To install executable in current directory...

```
  GOPATH=$(pwd)/go GOBIN=$(pwd) \
                 go install github.com/trustnetworks/certificate-tools/...
```
