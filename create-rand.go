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

    var one,zero int = 0,0
    
    randBlock := make([]byte,options.BlockSize)
    for i := 0; i< options.NumBlocks; i = i+1 {

        numRandBytes, err := rand.Read(randBlock)

        if err != nil {
            log.Fatalf("failed to generate block of random bytes: %s\n",err);
        }
        if numRandBytes != options.BlockSize {
            log.Fatalf("failed to generate full block of random bytes\n");
        }


        for j:=0;j<numRandBytes;j+=1 {
            if options.Verbose {
                fmt.Fprintf(os.Stderr, "%02x ",randBlock[j])
            }
            
            for p:=1 ; p < 256; p = p << 1 {
                if (byte(p) & randBlock[j])!=0 {
                    one = one + 1
                } else {
                    zero = zero + 1
                }
            }
        }
        if options.Verbose {
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

    // Quick Entropy Check

    if one==0 || zero==0 || (one/zero != 1 && zero/one != 1) { 
        fmt.Fprintf(os.Stderr,"Entropy Check Failed: %d %d %d %d\n",one,zero, one*100/zero, zero*100/one)
        fmt.Fprintf(os.Stdout,"FAILED")
        os.Exit(1)
    }
    
	os.Exit(0)
}
