package registrar

import (
	"encoding/json"
	"fmt"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	"os/exec"
)

const (
	HelpCommandName             = "help"
	RegisterWorkerCommandName   = "register-worker"
	UnregisterWorkerCommandName = "unregister-worker"
	GetWorkerCommandName        = "get-worker"
	StoreVendorCertCommandName  = "store-vendor-cert"
	GetVendorCertCommandName    = "get-vendor-cert"
	GetVendorCommandName        = "get-vendor"
	DeleteVendorCertCommandName = "delete-vendor-cert"

	KubernetesRegistrarPluginCommandName = "kubectl attestation-registrar"
)

// HelpCommand runs the 'kubectl attestation-ca help' command and prints its output
func HelpCommand() (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, HelpCommandName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", HelpCommandName, err)
	}
	return string(output), nil
}

func RegisterNodeCommand(workerNode string) (bool, string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, RegisterWorkerCommandName, "--worker", workerNode)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", RegisterWorkerCommandName, err)
	}
	return true, string(output), nil
}

func UnregisterNodeCommand(uuid string) (bool, string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, UnregisterWorkerCommandName, "--uuid", uuid)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", UnregisterWorkerCommandName, err)
	}
	return true, string(output), nil
}

func GetWorkerByUuidCommand(uuid string) (*model.WorkerNode, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetWorkerCommandName, "--uuid", uuid)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running %s command: %v", GetWorkerCommandName, err)
	}
	var worker model.WorkerNode
	err = json.Unmarshal(output, &worker)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling worker: %v", err)
	}
	return &worker, nil
}

func GetWorkerByNameCommand(name string) (*model.WorkerNode, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetWorkerCommandName, "--name", name)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running %s command: %v", GetWorkerCommandName, err)
	}
	var worker model.WorkerNode
	err = json.Unmarshal(output, &worker)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling worker: %v", err)
	}
	return &worker, nil
}

func GetAllWorkersCommand() ([]model.WorkerNode, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetWorkerCommandName, "--all")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running %s command: %v", GetWorkerCommandName, err)
	}
	var workers []model.WorkerNode
	err = json.Unmarshal(output, &workers)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling workers: %v", err)
	}
	return workers, nil
}

func StoreVendorIntermediateCertCommand(intermediateCert string) (bool, string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, StoreVendorCertCommandName, "--intermediate", intermediateCert)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", StoreVendorCertCommandName, err)
	}
	return true, string(output), nil
}

func StoreVendorRootCertCommand(rootCert string) (bool, string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, StoreVendorCertCommandName, "--root", rootCert)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", StoreVendorCertCommandName, err)
	}
	return true, string(output), nil
}

func GetVendorCertByCommonNameCommand(commonName string) (*model.TPMCACertificate, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetVendorCertCommandName, "--common-name", commonName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running %s command: %v", GetVendorCertCommandName, err)
	}
	var tpmCaCert model.TPMCACertificate
	err = json.Unmarshal(output, &tpmCaCert)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling vendor ca certificate: %v", err)
	}
	return &tpmCaCert, nil
}

func GetAllVendorCertsCommand() ([]model.TPMCACertificate, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetVendorCertCommandName, "--all")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running %s command: %v", GetVendorCertCommandName, err)
	}
	var tpmCaCerts []model.TPMCACertificate
	err = json.Unmarshal(output, &tpmCaCerts)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling vendor ca certificates: %v", err)
	}
	return tpmCaCerts, nil
}

func GetVendorByTcgIdCommand(tcgId string) (*model.TPMVendor, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetVendorCommandName, "--tcg-id", tcgId)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running %s command: %v", GetVendorCommandName, err)
	}
	var tpmVendor model.TPMVendor
	err = json.Unmarshal(output, &tpmVendor)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling vendor: %v", err)
	}
	return &tpmVendor, nil
}

func GetAllVendorsCommand() ([]model.TPMVendor, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetVendorCommandName, "--all")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running %s command: %v", GetVendorCommandName, err)
	}
	var tpmVendors []model.TPMVendor
	err = json.Unmarshal(output, &tpmVendors)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling vendor: %v", err)
	}
	return tpmVendors, nil
}

func DeleteVendorCertCommand(commonName string) (bool, string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, DeleteVendorCertCommandName, "--common-name", commonName)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", DeleteVendorCertCommandName, err)
	}
	return true, string(output), nil
}
