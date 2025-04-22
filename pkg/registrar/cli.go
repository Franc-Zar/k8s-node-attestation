package registrar

import (
	"encoding/base64"
	"encoding/json"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
)

func CLI(args []string) {
	if len(args) < 2 {
		logger.CommandError("Usage: registrar-ca <command> [flag]\nregistrar-ca help for more information")
	}

	registrar, err := New()
	if err != nil {
		logger.CommandError(err.Error())
		return
	}
	command := args[1]

	switch command {
	case HelpCommandName:
		logger.CommandInfo(registrar.Help())

	case RegisterWorkerCommandName:
		if len(args) < 4 {
			logger.CommandError("Usage: registrar-ca %s --worker, -w <node-json>", RegisterWorkerCommandName)
		}
		flag := args[2]
		switch flag {
		case "--worker", "-w":
			var worker *model.WorkerNode
			err = json.Unmarshal([]byte(args[3]), worker)
			if err != nil {
				logger.CommandError("Failed to parse --worker argument: %v", err)
			}
			err = registrar.RegisterNode(worker)
			if err != nil {
				logger.CommandError("Failed to register worker: %v", err)
			}
			logger.CommandSuccess("Successfully registered worker")
		default:
			logger.CommandError("Unknown flag: %s", flag)
		}

	case GetWorkerCommandName:
		if len(args) < 4 {
			logger.CommandError("Usage: registrar-ca %s --uuid <node-uuid> | --name <name> | --all", GetWorkerCommandName)
		}
		flag := args[2]
		switch flag {
		case "--uuid":
			uuid := args[3]
			worker, err := registrar.GetWorkerByUUID(uuid)
			if err != nil {
				logger.CommandError("Failed to get worker: %v", err)
			}
			logger.CommandSuccess("%s", worker)
		case "--name":
			name := args[3]
			worker, err := registrar.GetWorkerByName(name)
			if err != nil {
				logger.CommandError("Failed to get worker: %v", err)
			}
			logger.CommandSuccess("%s", worker)

		case "--all":
			workers, err := registrar.GetAllWorkers()
			if err != nil {
				logger.CommandError("Failed to get workers: %v", err)
			}
			logger.CommandSuccess("%s", workers)
		default:
			logger.CommandError("Unknown flag: %s", flag)
		}

	case UnregisterWorkerCommandName:
		if len(args) < 4 {
			logger.CommandError("Usage: registrar-ca %s --uuid <uuid>", UnregisterWorkerCommandName)
		}
		flag := args[2]
		switch flag {
		case "--uuid", "-u":
			uuid := args[3]
			err = registrar.UnregisterNode(uuid)
			if err != nil {
				logger.CommandError("Failed to unregister worker: %v", err)
			}
			logger.CommandSuccess("Successfully unregistered worker")
		default:
			logger.CommandError("Unknown flag: %s", flag)
		}

	case GetVendorCommandName:
		if len(args) < 3 {
			logger.CommandError("Usage: registrar-ca %s --tcg-id <id> | --all", GetVendorCommandName)
		}

		flag := args[2]
		switch flag {
		case "--tcg-id":
			tcgId := args[3]
			vendor, err := registrar.GetTPMVendorByTCGId(tcgId)
			if err != nil {
				logger.CommandError("Failed to get TPM vendor: %v", err)
			}
			logger.CommandSuccess("%s", vendor)
		case "--all":
			vendors, err := registrar.GetTPMVendors()
			if err != nil {
				logger.CommandError("Failed to get TPM vendors: %v", err)
			}
			logger.CommandSuccess("%s", vendors)
		default:
			logger.CommandError("Unknown flag: %s", flag)
		}

	case GetVendorCertCommandName:
		if len(args) < 3 {
			logger.CommandError("Usage: registrar-ca %s --common-name, -cn <common-name> | --all", GetVendorCertCommandName)
		}
		flag := args[2]
		switch flag {
		case "--common-name", "-cn":
			commonName := args[3]
			certificate, err := registrar.GetTPMCaCertificate(commonName)
			if err != nil {
				logger.CommandError("Failed to get certificate: %v", err)
			}
			logger.CommandSuccess("%s", certificate)
		case "--all":
			certificates, err := registrar.GetAllTPMCaCertificates()
			if err != nil {
				logger.CommandError("Failed to get certificates: %v", err)
			}
			logger.CommandSuccess("%s", certificates)
		}

	case StoreVendorCertCommandName:
		if len(args) < 4 {
			logger.CommandError("Usage: registrar-ca %s --intermediate <pem-certificate-base64> | --root <pem-certificate-base64>", StoreVendorCertCommandName)
		}
		flag := args[2]
		switch flag {
		case "--intermediate":
			certificateBase64 := args[3]
			pemCertificate, err := base64.StdEncoding.DecodeString(certificateBase64)
			if err != nil {
				logger.CommandError("Failed to decode certificate: %v", err)
			}
			err = registrar.StoreTPMIntermediateCACertificate(pemCertificate)
			if err != nil {
				logger.CommandError("Failed to store certificate: %v", err)
			}
			logger.CommandSuccess("Successfully stored Intermediate CA certificate")

		case "--root":
			certificateBase64 := args[3]
			pemCertificate, err := base64.StdEncoding.DecodeString(certificateBase64)
			if err != nil {
				logger.CommandError("Failed to decode certificate: %v", err)
			}
			err = registrar.StoreTPMRootCACertificate(pemCertificate)
			if err != nil {
				logger.CommandError("Failed to store certificate: %v", err)
			}
			logger.CommandSuccess("Successfully stored Root CA certificate")

		default:
			logger.CommandError("Unknown flag: %s", flag)
		}

	case DeleteVendorCertCommandName:
		if len(args) < 4 {
			logger.CommandError("Usage: registrar-ca %s --common-name, -cn <common-name>", DeleteVendorCertCommandName)
		}

		flag := args[2]
		switch flag {
		case "--common-name", "-cn":
			commonName := args[3]
			err = registrar.DeleteTPMCaCertificate(commonName)
			if err != nil {
				logger.CommandError("Failed to delete certificate: %v", err)
			}
			logger.CommandSuccess("Successfully deleted CA certificate")

		default:
			logger.CommandError("Unknown flag: %s", flag)
		}

	}
}
