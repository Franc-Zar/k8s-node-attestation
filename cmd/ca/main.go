package main

import (
	"github.com/franc-zar/k8s-node-attestation/pkg/ca"
	"os"
)

func main() {
	ca.RootCaCLI(os.Args)
}
