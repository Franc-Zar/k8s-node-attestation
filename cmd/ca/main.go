package main

import (
	"github.com/franc-zar/k8s-node-attestation/pkg/ca"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"log"
	"os"
)

const (
	HelpCommandName          = "help"
	ResetCommand             = "reset"
	InitCommand              = "init"
	IssueCertificateCommand  = "issue-certificate"
	RevokeCertificateCommand = "revoke-certificate"
	GetCertificateCommand    = "get-certificate"
	GetCRLCommand            = "get-crl"
)

func main() {
	if len(os.Args) < 2 {
		logger.Fatal("Usage: attestation-ca <command> [flag]\nattestation-ca help for more information")
	}

	attestationCA := &ca.Server{}

	command := os.Args[1]

	switch command {
	case HelpCommandName:
		// Show help message
		attestationCA.Help()

	case ResetCommand:
		attestationCA.Reset()

	case InitCommand:
		// Ensure that the setup flag is provided
		if len(os.Args) < 3 {
			logger.Fatal("Usage: attestation-ca init --root-key-alg ECDSA | RSA")
		}
		// Setup Root CA with the specified key algorithm
		flag := os.Args[2]
		switch flag {
		case "--root-key-alg":
			if len(os.Args) < 4 {
				logger.Fatal("Usage: kubectl attestation ca setup --root-key-alg ECDSA | RSA")
			}
			keyAlg := os.Args[3]
			switch keyAlg {
			case "ECDSA":
				attestationCA.Init(ca.ECDSA)
			case "RSA":
				attestationCA.Init(ca.RSA)
			default:
				logger.Fatal("Invalid key algorithm. Use 'ECDSA' or 'RSA'")
			}
		default:
			logger.Fatal("Invalid flag for setup command.")
		}

	case IssueCertificateCommand:
		// Ensure that the certificate flag is provided
		if len(os.Args) < 3 {
			logger.Fatal("Usage: attestation-ca certificate --csr")
		}
		attestationCA.SetCA()
		flag := os.Args[2]
		switch flag {
		case "--csr":
			csr := os.Args[3]
			// Issue a certificate with CSR
			attestationCA.IssueCertificate(csr)
		default:
			logger.Fatal("Unknown flag for certificate command: %s", flag)
		}

	case RevokeCertificateCommand:
		// Ensure that the revoke certificate flags are provided
		if len(os.Args) < 3 {
			log.Fatal("Usage: attestation-ca revoke-certificate --cert, -c | --all, -a")
		}
		attestationCA.SetCA()
		flag := os.Args[2]
		switch flag {
		case "--cert", "-c":
			// Revoke a specific certificate
			_, err := attestationCA.RevokeCertificate(os.Args[3])
			if err != nil {
				return
			}
		case "--all", "-a":
			// Revoke all certificates
			_, err := attestationCA.RevokeAllCertificates()
			if err != nil {
				return
			}
		default:
			log.Fatalf("Unknown flag for revoke-certificate command: %s", flag)
		}

	case GetCertificateCommand:
		// Ensure that the get certificate flag is provided
		if len(os.Args) < 3 {
			log.Fatal("Usage: kubectl attestation ca get-certificate --common-name, -cn")
		}
		attestationCA.SetCA()
		flag := os.Args[2]
		switch flag {
		case "--common-name", "-cn":
			// Retrieve a certificate by Common Name
			//attestationCA.GetCertificateByCN(os.Args[3])
		default:
			log.Fatalf("Unknown flag for get-certificate command: %s", flag)
		}

	case GetCRLCommand:
		attestationCA.SetCA()
		// Retrieve the Certificate Revocation List (CRL)
		latestCRL := attestationCA.GetLatestCRL()
		logger.Success(latestCRL)

	default:
		logger.Fatal("Unknown command: %s", command)
	}
}
