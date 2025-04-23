package registrar

import (
	"fmt"
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

func GetWorkerByUuidCommand(uuid string) (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetWorkerCommandName, "--uuid", uuid)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetWorkerCommandName, err)
	}
	return string(output), nil
}

func GetWorkerByNameCommand(name string) (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetWorkerCommandName, "--name", name)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetWorkerCommandName, err)
	}
	return string(output), nil
}

func GetAllWorkersCommand() (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetWorkerCommandName, "--all")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetWorkerCommandName, err)
	}
	return string(output), nil
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

func GetVendorCertByCommonNameCommand(commonName string) (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetVendorCertCommandName, "--common-name", commonName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetVendorCertCommandName, err)
	}
	return string(output), nil
}

func GetAllVendorCertCommand() (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetVendorCertCommandName, "--all")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetVendorCertCommandName, err)
	}
	return string(output), nil
}

func GetVendorByTcgIdCommand(tcgId string) (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetVendorCommandName, "--tcg-id", tcgId)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetVendorCommandName, err)
	}
	return string(output), nil
}

func GetAllVendorsCommand() (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetVendorCommandName, "--all")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetVendorCommandName, err)
	}
	return string(output), nil
}

func DeleteVendorCertCommand(commonName string) (bool, string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, DeleteVendorCertCommandName, "--common-name", commonName)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", DeleteVendorCertCommandName, err)
	}
	return true, string(output), nil
}
