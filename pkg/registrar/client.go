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
