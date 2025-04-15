package ca

import (
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"os/exec"
)

// Constants for command names
const (
	HelpCommandName              = "help"
	ResetCommandName             = "reset"
	InitCommandName              = "init"
	IssueCertificateCommandName  = "issue-certificate"
	RevokeCertificateCommandName = "revoke-certificate"
	GetCertificateCommandName    = "get-certificate"
	GetCRLCommandName            = "get-crl"

	KubernetesCaPluginCommandName = "kubectl attestation-ca"
)

// HelpCommand runs the 'kubectl attestation-ca help' command and prints its output
func HelpCommand() {
	cmd := exec.Command(KubernetesCaPluginCommandName, HelpCommandName)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running %s command: %v", HelpCommandName, err)
	}
	logger.CommandSuccess("%s", output)
}

func ResetCommand() {
	cmd := exec.Command(KubernetesCaPluginCommandName, ResetCommandName)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running %s command: %v", ResetCommandName, err)
	}
	logger.CommandSuccess("%s", output)
}

func InitCommand(rootKeyAlg string) {
	cmd := exec.Command(KubernetesCaPluginCommandName, InitCommandName, "--root-key-alg", rootKeyAlg)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running init command: %v", err)
	}
	logger.CommandSuccess("%s", output)
}

func IssueCertificateCommand(csr string) {
	cmd := exec.Command(KubernetesCaPluginCommandName, IssueCertificateCommandName, "--csr", csr)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running %s command: %v", IssueCertificateCommandName, err)
	}
	logger.CommandSuccess("%s", output)
}

func RevokeCertificateCommand(csr string) {
	cmd := exec.Command(KubernetesCaPluginCommandName, RevokeCertificateCommandName, "--csr", csr)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running %s command: %v", RevokeCertificateCommandName, err)
	}
	logger.CommandSuccess("%s", output)
}

func RevokeAllCertificateCommand() {
	cmd := exec.Command(KubernetesCaPluginCommandName, RevokeCertificateCommandName, "--all")
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running %s command: %v", RevokeCertificateCommandName, err)
	}
	logger.CommandSuccess("%s", output)
}

func GetCertificateCommand(commonName string) {
	cmd := exec.Command(KubernetesCaPluginCommandName, GetCertificateCommandName, "--common-name", commonName)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error %s command: %v", GetCertificateCommandName, err)
	}
	logger.CommandSuccess("%s", output)
}

func GetRootCertificateCommand() {
	cmd := exec.Command(KubernetesCaPluginCommandName, GetCertificateCommandName, "--root")
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running %s command: %v", GetCertificateCommandName, err)
	}
	logger.CommandSuccess("%s", output)
}

func GetCRLCommand() {
	cmd := exec.Command(KubernetesCaPluginCommandName, GetCRLCommandName)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running %s command: %v", GetCRLCommandName, err)
	}
	logger.CommandSuccess("%s", output)
}
