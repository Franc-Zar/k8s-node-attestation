package main

import (
	"github.com/franc-zar/k8s-node-attestation/pkg/ca"
	"os"
)

func main() {
	attestationCA := &ca.Server{}
	attestationCA.Init()

	command := os.Args[1]
	flag := os.Args[2]
	switch command {
	case "--help", "-h":
		attestationCA.Help()
	case "certificate":
		swit
	case "crl":

	}
}
