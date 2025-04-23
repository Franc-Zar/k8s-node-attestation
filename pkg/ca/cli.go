package ca

import (
	"encoding/base64"
	"encoding/json"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"strconv"
)

func CLI(args []string) {
	if len(args) < 2 {
		logger.CommandError("Usage: attestation-ca <command> [flag]\nattestation-ca help for more information")
	}

	attestationCA, err := New()
	if err != nil {
		logger.CommandError(err.Error())
		return
	}
	command := args[1]

	switch command {

	case HelpCommandName:
		logger.CommandInfo(attestationCA.Help())

	case ResetCommandName:
		err = attestationCA.Reset()
		if err != nil {
			logger.CommandError("Failed to reset Attestation CA: %v", err)
		}
		logger.CommandSuccess("Successfully reset Attestation CA")

	case InitCommandName:
		// Ensure that the setup flag is provided
		if len(args) < 3 {
			logger.CommandError("Usage: attestation-ca %s --root-key-alg ECDSA | RSA", InitCommandName)
		}
		// Setup Root CA with the specified key algorithm
		flag := args[2]
		switch flag {

		case "--root-key-alg":
			if len(args) < 4 {
				logger.CommandError("Usage: kubectl attestation-ca %s --root-key-alg ECDSA | RSA", InitCommandName)
			}
			keyAlg := args[3]
			switch keyAlg {

			case "ECDSA":
				err = attestationCA.InitCA(ECDSA)
				if err != nil {
					logger.CommandError("Failed to initialize Root CA: %v", err)
				}
				logger.CommandSuccess("Successfully initialized attestation CA")

			case "RSA":
				err = attestationCA.InitCA(RSA)
				if err != nil {
					logger.CommandError("Failed to initialize Root CA: %v", err)
				}
				logger.CommandSuccess("Successfully initialized attestation CA")

			default:
				logger.CommandError("Invalid key algorithm. Use 'ECDSA' or 'RSA'")
			}

		default:
			logger.CommandError("Invalid flag for command.")
		}

	case IssueCertificateCommandName:
		if len(args) < 4 {
			logger.CommandError("Usage: attestation-ca %s --csr <csr-base64>", IssueCertificateCommandName)
		}
		err = attestationCA.SetCA()
		if err != nil {
			logger.CommandError(err.Error())
		}
		flag := args[2]
		encCSR := args[3]
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

			output, err := json.MarshalIndent(issuedCert, "", "  ")
			if err != nil {
				logger.CommandError("Error marshalling issued certificate to JSON: %v", err)
			}

			logger.CommandSuccess("%s", output)

		default:
			logger.CommandError("Unknown flag for certificate command: %s", flag)
		}

	case RevokeCertificateCommandName:
		// Ensure that the revoke certificate flags are provided
		if len(args) < 3 {
			logger.CommandError("Usage: attestation-ca %s --cert, -c <pem-certificate-base64> | --all, -a", RevokeCertificateCommandName)
		}

		err = attestationCA.SetCA()
		if err != nil {
			logger.CommandError("Failed to revoke certificate: %v", err)
		}

		flag := args[2]
		switch flag {

		case "--cert", "-c":
			if len(args) < 4 {
				logger.CommandError("Usage: attestation-ca %s --cert, -c <pem-certificate-base64>", RevokeCertificateCommandName)
			}
			flagArg := []byte(args[3])

			_, err = attestationCA.RevokeCertificate(flagArg)
			if err != nil {
				logger.CommandError("Failed to revoke certificate: %v", err)
			}
			logger.CommandSuccess("Successfully revoked certificate")

		case "--all", "-a":
			// Revoke all certificates
			_, err = attestationCA.RevokeAllCertificates()
			if err != nil {
				logger.CommandError("Failed to revoke all certificates: %v", err)
			}
			logger.Success("Successfully revoked all certificates")
		default:
			logger.CommandError("Unknown flag for %s command: %s", RevokeCertificateCommandName, flag)
		}

	case GetCertificateCommandName:
		// Ensure that the get certificate flag is provided
		if len(args) < 3 {
			logger.CommandError("Usage: kubectl attestation-ca %s --common-name, -cn <common-name> | --all", GetCertificateCommandName)
		}
		err = attestationCA.SetCA()
		if err != nil {
			logger.CommandError("Failed to get certificate: %v", err)
		}
		flag := args[2]
		switch flag {
		case "--common-name", "-cn":
			if len(args) < 4 {
				logger.CommandError("Usage: kubectl attestation-ca %s --common-name, -cn <common-name>", GetCertificateCommandName)
			}
			commonName := args[3]
			// Retrieve a certificate by Common Name
			certificate, err := attestationCA.GetCertificateByCommonName(commonName)
			if err != nil {
				logger.CommandError("Failed to get certificate by common name '%s': %v", commonName, err)
			}

			output, err := json.MarshalIndent(certificate, "", "  ")
			if err != nil {
				logger.CommandError("Error marshalling certificate to JSON: %v", err)
			}
			logger.CommandSuccess("%s", output)

		case "--serial-number", "-sn":
			if len(args) < 4 {
				logger.CommandError("Usage: kubectl attestation-ca %s --serial-number, -sn <serial-number>", GetCertificateCommandName)
			}

			serialNumber, err := strconv.ParseInt(args[3], 10, 64)
			certificate, err := attestationCA.GetCertificateBySerialNumber(serialNumber)
			if err != nil {
				logger.CommandError("Failed to get certificate by serial number '%s': %v", serialNumber, err)
			}

			output, err := json.MarshalIndent(certificate, "", "  ")
			if err != nil {
				logger.CommandError("Error marshalling certificate to JSON: %v", err)
			}
			logger.CommandSuccess("%s", output)

		case "--root":
			certificate, err := attestationCA.GetRootCACert()
			if err != nil {
				logger.CommandError("Failed to get Root CA certificate: %v", err)
			}

			output, err := json.MarshalIndent(certificate, "", "  ")
			if err != nil {
				logger.CommandError("Error marshalling certificate to JSON: %v", err)
			}
			logger.CommandSuccess("%s", output)

		default:
			logger.CommandError("Unknown flag for %s command: %s", GetCertificateCommandName, flag)
		}

	case GetCRLCommandName:
		err = attestationCA.SetCA()
		if err != nil {
			logger.CommandError("Failed to get CRL: %v", err)
		}
		// Retrieve the Certificate Revocation List (CRL)
		latestCRL, err := attestationCA.GetLatestCRL()
		if err != nil {
			logger.CommandError("Failed to get latest CRL: %v", err)
		}
		logger.CommandSuccess("%s", latestCRL)

	default:
		logger.CommandError("Unknown command: %s", command)
	}
}
