package ca

import (
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"os/exec"
)

// Constants for command names
const (
	HelpCommandName          = "help"
	ResetCommand             = "reset"
	InitCommand              = "init"
	IssueCertificateCommand  = "issue-certificate"
	RevokeCertificateCommand = "revoke-certificate"
	GetCertificateCommand    = "get-certificate"
	GetCRLCommand            = "get-crl"
)

// HelpCommand runs the 'kubectl attestation-ca help' command and prints its output
func HelpCommand() {
	cmd := exec.Command("kubectl", "attestation-ca", "help")
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running help command: %v", err)
	}
	logger.CommandSuccess(string(output))
}
