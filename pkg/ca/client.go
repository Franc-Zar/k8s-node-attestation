package ca

import (
	"encoding/json"
	"fmt"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
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
func HelpCommand() (string, error) {
	cmd := exec.Command(KubernetesCaPluginCommandName, HelpCommandName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", HelpCommandName, err)
	}
	return string(output), nil
}

func ResetCommand() (bool, string, error) {
	cmd := exec.Command(KubernetesCaPluginCommandName, ResetCommandName)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", ResetCommandName, err)
	}
	return true, string(output), nil
}

func InitCommand(rootKeyAlg string) (bool, string, error) {
	cmd := exec.Command(KubernetesCaPluginCommandName, InitCommandName, "--root-key-alg", rootKeyAlg)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running init command: %v", err)
	}
	return true, string(output), nil
}

func IssueCertificateCommand(csr string) (bool, string, error) {
	cmd := exec.Command(KubernetesCaPluginCommandName, IssueCertificateCommandName, "--csr", csr)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", IssueCertificateCommandName, err)
	}
	return true, string(output), nil
}

func RevokeCertificateCommand(csr string) (bool, string, error) {
	cmd := exec.Command(KubernetesCaPluginCommandName, RevokeCertificateCommandName, "--csr", csr)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", RevokeCertificateCommandName, err)
	}
	return true, string(output), nil
}

func RevokeAllCertificateCommand() (bool, string, error) {
	cmd := exec.Command(KubernetesCaPluginCommandName, RevokeCertificateCommandName, "--all")
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("error running %s command: %v", RevokeCertificateCommandName, err)
	}
	return true, string(output), nil
}

func GetCertificateByCommonNameCommand(commonName string) (*model.Certificate, error) {
	cmd := exec.Command(KubernetesCaPluginCommandName, GetCertificateCommandName, "--common-name", commonName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error %s command: %v", GetCertificateCommandName, err)
	}
	var certificate model.Certificate
	err = json.Unmarshal(output, &certificate)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling certificate: %v", err)
	}
	return &certificate, nil
}

func GetCertificateBySerialNumberCommand(serialNumber string) (*model.Certificate, error) {
	cmd := exec.Command(KubernetesCaPluginCommandName, GetCertificateCommandName, "--serial-number", serialNumber)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error %s command: %v", GetCertificateCommandName, err)
	}
	var certificate model.Certificate
	err = json.Unmarshal(output, &certificate)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling certificate: %v", err)
	}
	return &certificate, nil
}

func GetRootCertificateCommand() (*model.Certificate, error) {
	cmd := exec.Command(KubernetesCaPluginCommandName, GetCertificateCommandName, "--root")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running %s command: %v", GetCertificateCommandName, err)
	}

	var rootCertificate model.Certificate
	err = json.Unmarshal(output, &rootCertificate)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling certificate: %v", err)
	}
	return &rootCertificate, nil
}

func GetCRLCommand() (string, error) {
	cmd := exec.Command(KubernetesCaPluginCommandName, GetCRLCommandName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error running %s command: %v", GetCRLCommandName, err)
	}
	return string(output), nil
}
