package main

import (
	"github.com/franc-zar/k8s-node-attestation/pkg/ca"
	"os"
)

func main() {
	ca.CLI(os.Args)
}
