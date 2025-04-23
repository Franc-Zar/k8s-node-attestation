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

func RegisterNodeCommand() (bool, string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, RegisterWorkerCommandName)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", RegisterWorkerCommandName, err)
	}
	return true, string(output), nil
}

func UnregisterNodeCommand() (bool, string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, UnregisterWorkerCommandName)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", UnregisterWorkerCommandName, err)
	}
	return true, string(output), nil
}

func GetWorkerCommand() (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetWorkerCommandName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetWorkerCommandName, err)
	}
	return string(output), nil
}

func StoreVendorCertCommand() (bool, string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, StoreVendorCertCommandName)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", StoreVendorCertCommandName, err)
	}
	return true, string(output), nil
}

func GetVendorCertCommand() (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetVendorCertCommandName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetVendorCertCommandName, err)
	}
	return string(output), nil
}

func GetVendorCommand() (string, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, GetVendorCommandName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetVendorCommandName, err)
	}
	return string(output), nil
}
