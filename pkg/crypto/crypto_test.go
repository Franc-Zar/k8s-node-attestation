package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	"os"
	"testing"
)

// Helper to decode PEM into *x509.Certificate
func loadCertFromFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode PEM: %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	return cert
}

func TestVerifyEKCertificateChain(t *testing.T) {
	tests := []struct {
		name        string
		ekCertPath  string
		intPath     string
		rootPath    string
		tpmVendors  []model.TPMVendor
		expectError bool
	}{
		{
			name:       "valid chain",
			ekCertPath: "test-data/ekCert.pem",
			intPath:    "test-data/OptigaRsaMfrCA003.pem",
			rootPath:   "test-data/Infineon-TPM_RSA_Root_CA-C-v01_00-EN.pem",
			tpmVendors: []model.TPMVendor{{Name: "AMD", TCGIdentifier: "id:414D4400"},
				{Name: "Atmel", TCGIdentifier: "id:41544D4C"},
				{Name: "Broadcom", TCGIdentifier: "id:4252434D"},
				{Name: "Cisco", TCGIdentifier: "id:4353434F"},
				{Name: "Flyslice Technologies", TCGIdentifier: "id:464C5953"},
				{Name: "HPE", TCGIdentifier: "id:48504500"},
				{Name: "Huawei", TCGIdentifier: "id:48495349"},
				{Name: "IBM", TCGIdentifier: "id:49424D00"},
				{Name: "Infineon", TCGIdentifier: "id:49465800"},
				{Name: "Intel", TCGIdentifier: "id:494E5443"},
				{Name: "Lenovo", TCGIdentifier: "id:4C454E00"},
				{Name: "Microsoft", TCGIdentifier: "id:4D534654"},
				{Name: "National Semiconductor", TCGIdentifier: "id:4E534D20"},
				{Name: "Nationz", TCGIdentifier: "id:4E545A00"},
				{Name: "Nuvoton Technology", TCGIdentifier: "id:4E544300"},
				{Name: "Qualcomm", TCGIdentifier: "id:51434F4D"},
				{Name: "SMSC", TCGIdentifier: "id:534D5343"},
				{Name: "ST Microelectronics", TCGIdentifier: "id:53544D20"},
				{Name: "Samsung", TCGIdentifier: "id:534D534E"},
				{Name: "Sinosun", TCGIdentifier: "id:534E5300"},
				{Name: "Texas Instruments", TCGIdentifier: "id:54584E00"},
				{Name: "Winbond", TCGIdentifier: "id:57454300"},
				{Name: "Fuzhouk Rockchip", TCGIdentifier: "id:524F4343"},
				{Name: "Google", TCGIdentifier: "id:474F4F47"}},
			expectError: false,
		},
		/*		{
				name:        "invalid chain",
				ekCertPath:  "test-data/ek-invalid.pem",
				intPath:     "test-data/OptigaRsaMfrCA003.pem",
				rootPath:    "test-data/Infineon-TPM_RSA_Root_CA-C-v01_00-EN.pem",
				expectError: true,
			},*/
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ek := loadCertFromFile(t, tt.ekCertPath)
			intermediate := loadCertFromFile(t, tt.intPath)
			root := loadCertFromFile(t, tt.rootPath)

			err := VerifyEKCertificateChain(ek, intermediate, root, tt.tpmVendors)
			if (err != nil) != tt.expectError {
				t.Errorf("VerifyEKCertificateChain() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestVerifyTPMIntermediateCACertificate(t *testing.T) {
	tests := []struct {
		name        string
		intPath     string
		rootPath    string
		expectError bool
	}{
		{
			name:        "valid intermediate",
			intPath:     "test-data/OptigaRsaMfrCA003.pem",
			rootPath:    "test-data/Infineon-TPM_RSA_Root_CA-C-v01_00-EN.pem",
			expectError: false,
		},
		{
			name:        "root provided as intermediate",
			intPath:     "test-data/Infineon-TPM_RSA_Root_CA-C-v01_00-EN.pem",
			rootPath:    "test-data/OptigaRsaMfrCA003.pem",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intermediate := loadCertFromFile(t, tt.intPath)
			root := loadCertFromFile(t, tt.rootPath)

			err := VerifyTPMIntermediateCACertificate(intermediate, root)
			if (err != nil) != tt.expectError {
				t.Errorf("VerifyEKCertificateChain() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}
