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
func HelpCommand() ([]byte, error) {
	cmd := exec.Command(KubernetesRegistrarPluginCommandName, HelpCommandName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running %s command: %v", HelpCommandName, err)
	}
	return output, nil
}
