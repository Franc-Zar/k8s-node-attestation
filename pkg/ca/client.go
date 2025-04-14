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
)

// HelpCommand runs the 'kubectl attestation-ca help' command and prints its output
func HelpCommand() {
	cmd := exec.Command("kubectl attestation-ca", HelpCommandName)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running help command: %v", err)
	}
	logger.CommandSuccess(string(output))
}

func ResetCommand() {
	cmd := exec.Command("kubectl attestation-ca", ResetCommandName)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running reset command: %v", err)
	}
	logger.CommandSuccess(string(output))
}

func InitCommand(rootKeyAlg string) {
	cmd := exec.Command("kubectl attestation-ca", InitCommandName, "--root-key-alg", rootKeyAlg)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running init command: %v", err)
	}
	logger.CommandSuccess(string(output))
}

func IssueCertificateCommand(csr string) {
	cmd := exec.Command("kubectl attestation-ca", IssueCertificateCommandName, "--csr", csr)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running issue-certificate command: %v", err)
	}
	logger.CommandSuccess(string(output))
}

func RevokeCertificateCommand(csr string) {
	cmd := exec.Command("kubectl attestation-ca", RevokeCertificateCommandName, "--csr", csr)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running issue-certificate command: %v", err)
	}
	logger.CommandSuccess(string(output))
}

func RevokeAllCertificateCommand() {
	cmd := exec.Command("kubectl attestation-ca", RevokeCertificateCommandName, "--all")
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running issue-certificate command: %v", err)
	}
	logger.CommandSuccess(string(output))
}

func GetCertificateCommand(commonName string) {
	cmd := exec.Command("kubectl attestation-ca", GetCertificateCommandName, "--common-name", commonName)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running issue-certificate command: %v", err)
	}
	logger.CommandSuccess(string(output))
}

func GetRootCertificateCommand() {
	cmd := exec.Command("kubectl attestation-ca", GetCertificateCommandName, "--root")
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running issue-certificate command: %v", err)
	}
	logger.CommandSuccess(string(output))
}

func GetCRLCommand() {
	cmd := exec.Command("kubectl attestation-ca", GetCRLCommandName)
	output, err := cmd.Output()
	if err != nil {
		logger.CommandError("error running issue-certificate command: %v", err)
	}
	logger.CommandSuccess(string(output))
}
