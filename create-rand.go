package main

import (

	"crypto/rand"
	"github.com/jessevdk/go-flags"
	"os"
    "log"
    "fmt"
)

var options struct {
	NumBlocks int `short:"c" long:"count" description:"Number of blocks to output" required:"false" default:"1"`
	BlockSize int `short:"b" long:"bs"    description:"Number of bytes in a block" required:"true" `
    Verbose  bool `short:"v" long:"verbose" description:"Verbose Mode" required:"false"`
}



func main() {

	// Parse flags
	_, err := flags.Parse(&options)
	if err != nil {
		os.Exit(1)
	}

    
    randBlock := make([]byte,options.BlockSize)
    for i := 0; i< options.NumBlocks; i = i+1 {

        numRandBytes, err := rand.Read(randBlock)

        if err != nil {
            log.Fatalf("failed to generate block of random bytes: %s\n",err);
        }
        if numRandBytes != options.BlockSize {
            log.Fatalf("failed to generate full block of random bytes\n");
        }

        if options.Verbose {
            for j:=0;j<numRandBytes;j+=1 {
                fmt.Fprintf(os.Stderr, "%02x ",randBlock[j])
            }
            fmt.Fprintf(os.Stderr,"\n")
        }
        
        numRandBytes, err = os.Stdout.Write(randBlock)
        if err != nil {
            log.Fatalf("failed to write CRL: %s\n",err);
        }
        if numRandBytes != options.BlockSize {
            log.Fatalf("failed to write full block of random bytes\n");
        }
    }
    
	os.Exit(0)
}
