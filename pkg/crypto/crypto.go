package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	x509ext "github.com/google/go-attestation/x509"
	"github.com/google/go-tpm/tpmutil"
	"math/big"
)

var SANoid = []int{2, 5, 29, 17} // OID for subjectAltName

// EncodePublicKeyToPEM converts an RSA or ECDSA public key to PEM format.
func EncodePublicKeyToPEM(pubKey crypto.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubPEM, nil
}

// DecodePublicKeyFromPEM decodes a PEM-encoded RSA or ECDSA public key and returns it as a crypto.PublicKey.
func DecodePublicKeyFromPEM(publicKeyPEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	switch block.Type {
	case "RSA PUBLIC KEY":
		rsaPubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 RSA public key: %v", err)
		}
		return rsaPubKey, nil
	case "PUBLIC KEY":
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %v", err)
		}

		switch key := pubKey.(type) {
		case *rsa.PublicKey:
			return key, nil
		case *ecdsa.PublicKey:
			return key, nil
		default:
			return nil, fmt.Errorf("unsupported public key type: %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
}

// LoadCertificateFromPEM loads a certificate from a PEM string
func LoadCertificateFromPEM(pemCert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemCert)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return cert, nil
}

// handleTPMSubjectAltName processes the subjectAltName extension to mark it as handled
func handleTPMSubjectAltName(cert *x509.Certificate, tpmVendors []model.TPMVendor) error {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(SANoid) {
			subjectAltName, err := x509ext.ParseSubjectAltName(ext)
			if err != nil {
				return err
			}

			// check if Certificate Vendor is a TCG valid one
			tcgVendorId := (subjectAltName.DirectoryNames[0].Names[0].Value).(string)
			var foundTPMVendor *model.TPMVendor

			for _, tpmVendor := range tpmVendors {
				if tpmVendor.TCGIdentifier == tcgVendorId {
					foundTPMVendor = &tpmVendor
				}
			}

			if foundTPMVendor == nil {
				return fmt.Errorf("TPM Vendor Not Found")
			}

			// TODO implement checks on platform model and firmware version
			//TPMModel := subjectAltName.DirectoryNames[0].Names[1]
			//TPMVersion := subjectAltName.DirectoryNames[0].Names[2]

			// Remove from UnhandledCriticalExtensions if it's the SAN extension
			for i, unhandledExt := range cert.UnhandledCriticalExtensions {
				if unhandledExt.Equal(ext.Id) {
					// Remove the SAN extension from UnhandledCriticalExtensions
					cert.UnhandledCriticalExtensions = append(cert.UnhandledCriticalExtensions[:i], cert.UnhandledCriticalExtensions[i+1:]...)
					break
				}
			}
			return nil
		}
	}
	return fmt.Errorf("SubjectAltName extension not found")
}

// VerifyEKCertificateChain verifies the provided certificate chain from PEM strings
func VerifyEKCertificateChain(ekCert, intermediateCACert, rootCACert *x509.Certificate, tpmVendors []model.TPMVendor) error {
	roots := x509.NewCertPool()
	roots.AddCert(rootCACert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCACert)

	opts := x509.VerifyOptions{
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:         roots,
		Intermediates: intermediates,
	}

	err := handleTPMSubjectAltName(ekCert, tpmVendors)
	if err != nil {
		return fmt.Errorf("EK Certificate verification failed: %v", err)
	}

	if _, err := ekCert.Verify(opts); err != nil {
		return fmt.Errorf("EK Certificate verification failed: %v", err)
	}
	return nil
}

// VerifyTPMSignature verifies a TPM signature using the provided public key (RSA or ECC).
func VerifyTPMSignature(pubKey crypto.PublicKey, message []byte, signature tpmutil.U16Bytes) error {
	hashed := sha256.Sum256(message)

	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
		if err != nil {
			return fmt.Errorf("RSA verification failed: %v", err)
		}
		return nil
	case *ecdsa.PublicKey:
		r, s := parseSignature(signature)
		if r == nil || s == nil {
			return fmt.Errorf("invalid signature format")
		}
		valid := ecdsa.Verify(pubKey, hashed[:], r, s)
		if !valid {
			return fmt.Errorf("ECDSA verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// VerifySignature verifies a signature using the provided public key (RSA or ECC).
func VerifySignature(publicKey crypto.PublicKey, message, signature []byte) error {
	hashed := sha256.Sum256(message)

	switch pubKey := publicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
		if err != nil {
			return fmt.Errorf("RSA verification failed: %v", err)
		}
		return nil
	case *ecdsa.PublicKey:
		r, s := parseSignature(signature)
		if r == nil || s == nil {
			return fmt.Errorf("invalid signature format")
		}
		valid := ecdsa.Verify(pubKey, hashed[:], r, s)
		if !valid {
			return fmt.Errorf("ECDSA verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// Helper function to parse the signature into r and s values for ECDSA
func parseSignature(sig []byte) (*big.Int, *big.Int) {
	if len(sig) < 64 {
		return nil, nil
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	return r, s
}
