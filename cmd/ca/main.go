package main

import (
	"encoding/base64"
	"github.com/franc-zar/k8s-node-attestation/pkg/ca"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		logger.CommandError("Usage: attestation-ca <command> [flag]\nattestation-ca help for more information")
	}

	attestationCA := ca.New()
	command := os.Args[1]

	switch command {

	case ca.HelpCommandName:
		logger.CommandSuccess(attestationCA.Help())

	case ca.ResetCommandName:
		err := attestationCA.Reset()
		if err != nil {
			logger.CommandError(err.Error())
		}
		logger.CommandSuccess("Successfully reset Attestation CA")

	case ca.InitCommandName:
		// Ensure that the setup flag is provided
		if len(os.Args) < 3 {
			logger.CommandError("Usage: attestation-ca init --root-key-alg ECDSA | RSA")
		}
		// Setup Root CA with the specified key algorithm
		flag := os.Args[2]
		switch flag {

		case "--root-key-alg":
			if len(os.Args) < 4 {
				logger.CommandError("Usage: kubectl attestation ca setup --root-key-alg ECDSA | RSA")
			}
			keyAlg := os.Args[3]
			switch keyAlg {

			case "ECDSA":
				err := attestationCA.InitCA(ca.ECDSA)
				if err != nil {
					logger.CommandError(err.Error())
				}

			case "RSA":
				err := attestationCA.InitCA(ca.RSA)
				if err != nil {
					logger.CommandError(err.Error())
				}

			default:
				logger.CommandError("Invalid key algorithm. Use 'ECDSA' or 'RSA'")
			}

		default:
			logger.CommandError("Invalid flag for setup command.")
		}

	case ca.IssueCertificateCommandName:
		if len(os.Args) < 4 {
			logger.CommandError("Usage: attestation-ca issue-certificate --csr <csr-base64>")
		}
		err := attestationCA.SetCA()
		if err != nil {
			logger.CommandError(err.Error())
		}
		flag := os.Args[2]
		encCSR := os.Args[3]
		decodedCSR, err := base64.StdEncoding.DecodeString(encCSR)
		if err != nil {
			logger.CommandError("Invalid base64 CSR")
		}
		switch flag {

		case "--csr":
			// Issue a certificate with CSR
			issuedCert, err := attestationCA.IssueCertificate(decodedCSR)
			if err != nil {
				logger.CommandError(err.Error())
			}
			logger.CommandSuccess("%s", issuedCert)

		default:
			logger.CommandError("Unknown flag for certificate command: %s", flag)
		}

	case ca.RevokeCertificateCommandName:
		// Ensure that the revoke certificate flags are provided
		if len(os.Args) < 3 {
			logger.CommandError("Usage: attestation-ca revoke-certificate --cert, -c <pem-certificate-base64> | --all, -a")
		}

		err := attestationCA.SetCA()
		if err != nil {
			logger.CommandError(err.Error())
		}

		flag := os.Args[2]
		switch flag {

		case "--cert", "-c":
			if len(os.Args) < 4 {
				logger.CommandError("Usage: attestation-ca revoke-certificate --cert, -c <pem-certificate-base64>")
			}
			flagArg := []byte(os.Args[3])

			_, err = attestationCA.RevokeCertificate(flagArg)
			if err != nil {
				logger.CommandError(err.Error())
			}

		case "--all", "-a":
			// Revoke all certificates
			_, err = attestationCA.RevokeAllCertificates()
			if err != nil {
				logger.CommandError(err.Error())
			}

		default:
			logger.CommandError("Unknown flag for revoke-certificate command: %s", flag)
		}

	case ca.GetCertificateCommandName:
		// Ensure that the get certificate flag is provided
		if len(os.Args) < 3 {
			logger.CommandError("Usage: kubectl attestation ca get-certificate --common-name, -cn")
		}
		err := attestationCA.SetCA()
		if err != nil {
			logger.CommandError(err.Error())
		}
		flag := os.Args[2]
		switch flag {
		case "--common-name", "-cn":
			if len(os.Args) < 4 {
				logger.CommandError("Usage: kubectl attestation ca get-certificate --common-name, -cn <common-name>")
			}
			commonName := os.Args[3]
			// Retrieve a certificate by Common Name
			certificate, err := attestationCA.GetCertificateByCommonName(commonName)
			if err != nil {
				logger.CommandError("Failed to get certificate by common name '%s': %v", commonName, err)
			}
			logger.CommandSuccess("%s", certificate)

		case "--root":
			certificate, err := attestationCA.GetRootCACert()
			if err != nil {
				logger.CommandError("Failed to get Root CA certificate: %v", err)
			}
			logger.CommandSuccess("%s", certificate)

		default:
			logger.CommandError("Unknown flag for get-certificate command: %s", flag)
		}

	case ca.GetCRLCommandName:
		err := attestationCA.SetCA()
		if err != nil {
			logger.CommandError(err.Error())
		}
		// Retrieve the Certificate Revocation List (CRL)
		latestCRL, err := attestationCA.GetLatestCRL()
		if err != nil {
			logger.CommandError(err.Error())
		}
		logger.CommandSuccess("%s", latestCRL)

	default:
		logger.CommandError("Unknown command: %s", command)
	}
}
