package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

var vendors = []model.TPMVendor{{CommonName: "AMD", TCGIdentifier: "id:414D4400"},
	{CommonName: "Atmel", TCGIdentifier: "id:41544D4C"},
	{CommonName: "Broadcom", TCGIdentifier: "id:4252434D"},
	{CommonName: "Cisco", TCGIdentifier: "id:4353434F"},
	{CommonName: "Flyslice Technologies", TCGIdentifier: "id:464C5953"},
	{CommonName: "HPE", TCGIdentifier: "id:48504500"},
	{CommonName: "Huawei", TCGIdentifier: "id:48495349"},
	{CommonName: "IBM", TCGIdentifier: "id:49424D00"},
	{CommonName: "Infineon", TCGIdentifier: "id:49465800"},
	{CommonName: "Intel", TCGIdentifier: "id:494E5443"},
	{CommonName: "Lenovo", TCGIdentifier: "id:4C454E00"},
	{CommonName: "Microsoft", TCGIdentifier: "id:4D534654"},
	{CommonName: "National Semiconductor", TCGIdentifier: "id:4E534D20"},
	{CommonName: "Nationz", TCGIdentifier: "id:4E545A00"},
	{CommonName: "Nuvoton Technology", TCGIdentifier: "id:4E544300"},
	{CommonName: "Qualcomm", TCGIdentifier: "id:51434F4D"},
	{CommonName: "SMSC", TCGIdentifier: "id:534D5343"},
	{CommonName: "ST Microelectronics", TCGIdentifier: "id:53544D20"},
	{CommonName: "Samsung", TCGIdentifier: "id:534D534E"},
	{CommonName: "Sinosun", TCGIdentifier: "id:534E5300"},
	{CommonName: "Texas Instruments", TCGIdentifier: "id:54584E00"},
	{CommonName: "Winbond", TCGIdentifier: "id:57454300"},
	{CommonName: "Fuzhouk Rockchip", TCGIdentifier: "id:524F4343"},
	{CommonName: "Google", TCGIdentifier: "id:474F4F47"}}

type certJwt struct {
	X5C []string `json:"x5c"`
	Iat int64    `json:"iat"`
	Nbf int64    `json:"nbf"`
	Exp int64    `json:"exp"`
}

func getSamplePayload() []byte {
	now := time.Now().Unix()
	claims := certJwt{
		X5C: []string{"dummy-cert"},
		Iat: now,
		Nbf: now,
		Exp: now + 300,
	}
	data, _ := json.Marshal(claims)
	return data
}

func TestEncryptDecryptJWT_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	payload := getSamplePayload()

	jweStr, err := EncryptJWT(payload, privKey.Public())
	assert.NoError(t, err)
	assert.NotEmpty(t, jweStr)

	plain, err := DecryptJWT(jweStr, privKey)
	assert.NoError(t, err)
	assert.JSONEq(t, string(payload), string(plain))
}

func TestEncryptDecryptJWT_ECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	payload := getSamplePayload()

	jweStr, err := EncryptJWT(payload, privKey.Public())
	assert.NoError(t, err)
	assert.NotEmpty(t, jweStr)

	plain, err := DecryptJWT(jweStr, privKey)
	assert.NoError(t, err)
	assert.JSONEq(t, string(payload), string(plain))
}

func TestDecryptJWT_InvalidKey(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwe := "invalid.jwe.token"

	_, err := DecryptJWT(jwe, privKey)
	assert.Error(t, err)
}

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
			name:        "valid chain",
			ekCertPath:  "test-data/ekCert.pem",
			intPath:     "test-data/OptigaRsaMfrCA003.pem",
			rootPath:    "test-data/Infineon-TPM_RSA_Root_CA-C-v01_00-EN.pem",
			tpmVendors:  vendors,
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

func TestVerifyTPMRootCACertificate(t *testing.T) {
	tests := []struct {
		name        string
		rootPath    string
		tpmVendors  []model.TPMVendor
		expectError bool
	}{
		{
			name:        "valid root",
			rootPath:    "test-data/Infineon-TPM_RSA_Root_CA-C-v01_00-EN.pem",
			tpmVendors:  vendors,
			expectError: false,
		},
		{
			name:        "root provided as intermediate",
			rootPath:    "test-data/OptigaRsaMfrCA003.pem",
			tpmVendors:  vendors,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := loadCertFromFile(t, tt.rootPath)
			err := VerifyTPMRootCACertificate(root, tt.tpmVendors)
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
