package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	x509ext "github.com/google/go-attestation/x509"
	"github.com/google/go-tpm/tpmutil"
	"math/big"
	"strings"
	"time"
)

var SANoid = asn1.ObjectIdentifier{2, 5, 29, 17} // OID for subjectAltName
var EKCertificateOid = asn1.ObjectIdentifier{2, 23, 133, 8, 1}

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

// DecodePrivateKeyFromPEM decodes a PEM-encoded RSA or ECDSA private key and returns it as a crypto.PrivateKey.
func DecodePrivateKeyFromPEM(privateKeyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 RSA private key: %v", err)
		}
		return rsaKey, nil

	case "EC PRIVATE KEY":
		ecKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %v", err)
		}
		return ecKey, nil

	case "PRIVATE KEY": // Usually PKCS#8, could be RSA or EC
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %v", err)
		}

		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported private key type in PKCS#8: %T", k)
		}

	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
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

func HandleTPMEKCertificateEKU(cert *x509.Certificate) error {
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(EKCertificateOid) {
			return nil
		}
	}
	return fmt.Errorf("certificate does not contain EKU: tcg-kp-EKCertificate")
}

// HandleTPMSubjectAltName processes the subjectAltName extension to mark it as handled
func HandleTPMSubjectAltName(cert *x509.Certificate, tpmVendors []model.TPMVendor) error {
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

// VerifyTLSCertificateChain verifies the TLS certificate against the root CA certificate for mTLS
func VerifyTLSCertificateChain(cert, rootCACert *x509.Certificate) error {
	// Create a new cert pool and add the root CA certificate
	roots := x509.NewCertPool()
	roots.AddCert(rootCACert)

	// Create the VerifyOptions object, including the Root CA cert pool
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	// Verify the certificate chain against the root CA
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	// Check if the certificate includes KeyEncipherment for mTLS
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return fmt.Errorf("certificate key usage does not include KeyEncipherment")
	}

	// Check if the certificate supports ClientAuth or ServerAuth for mTLS
	validAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth || eku == x509.ExtKeyUsageServerAuth {
			validAuth = true
			break
		}
	}
	if !validAuth {
		return fmt.Errorf("certificate does not include ClientAuth or ServerAuth in extended key usage")
	}

	return nil
}

func VerifyTPMRootCACertificate(rootCert *x509.Certificate, tpmVendors []model.TPMVendor) error {
	now := time.Now()
	if now.Before(rootCert.NotBefore) || now.After(rootCert.NotAfter) {
		return fmt.Errorf("certificate is not currently valid")
	}

	if !rootCert.IsCA {
		return fmt.Errorf("certificate is not a CA")
	}

	isSubjectValidVendor := false
	for _, tpmVendor := range tpmVendors {
		isSubjectValidVendor = strings.Contains(rootCert.Subject.String(), tpmVendor.CommonName)
		if isSubjectValidVendor {
			break
		}
	}
	if !isSubjectValidVendor {
		return fmt.Errorf("certificate is not a CA for a valid TPM vendor")
	}

	if rootCert.MaxPathLenZero && rootCert.MaxPathLen != 0 {
		return fmt.Errorf("invalid path length constraints for CA")
	}

	if rootCert.KeyUsage != (x509.KeyUsageCRLSign | x509.KeyUsageCertSign) {
		return fmt.Errorf("intermediate CA verification does not support CRLSign or CertSign")
	}

	err := rootCert.CheckSignatureFrom(rootCert)
	if err != nil {
		return fmt.Errorf("certificate signature verification failed: %v", err)
	}
	return nil
}

func VerifyTPMIntermediateCACertificate(intermediateCert, rootCert *x509.Certificate) error {
	now := time.Now()
	if now.Before(rootCert.NotBefore) || now.After(rootCert.NotAfter) {
		return fmt.Errorf("certificate is not currently valid")
	}

	if !intermediateCert.IsCA {
		return fmt.Errorf("certificate is not a CA")
	}

	if intermediateCert.Subject.String() == rootCert.Subject.String() {
		return fmt.Errorf("certificate is not intermediate CA")
	}

	// Optional: verify EKU if needed (e.g., for intermediate-specific EKU)
	err := HandleTPMEKCertificateEKU(intermediateCert)
	if err != nil {
		return fmt.Errorf("certificate EK validation failed: %v", err)
	}

	// Setup roots
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	// Verify chain from intermediate to root
	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     roots,
	}

	if _, err := intermediateCert.Verify(opts); err != nil {
		return fmt.Errorf("intermediate CA verification failed: %v", err)
	}

	if intermediateCert.KeyUsage != (x509.KeyUsageCRLSign | x509.KeyUsageCertSign) {
		return fmt.Errorf("intermediate CA verification does not support CRLSign or CertSign")
	}

	return nil
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

	err := HandleTPMSubjectAltName(ekCert, tpmVendors)
	if err != nil {
		return fmt.Errorf("EK Certificate verification failed: %v", err)
	}

	if ekCert.KeyUsage != x509.KeyUsageKeyEncipherment {
		return fmt.Errorf("EK certificate key usage does not include only KeyEncipherment")
	}

	err = HandleTPMEKCertificateEKU(ekCert)
	if err != nil {
		return fmt.Errorf("EK Certificate verification failed: %v", err)
	}

	if _, err = ekCert.Verify(opts); err != nil {
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
		r, s := ParseSignature(signature)
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
		r, s := ParseSignature(signature)
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

// ParseSignature Helper function to parse the signature into r and s values for ECDSA
func ParseSignature(sig []byte) (*big.Int, *big.Int) {
	if len(sig) < 64 {
		return nil, nil
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	return r, s
}

func VerifyHMAC(message, key, providedHMAC []byte) error {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	expectedHMAC := h.Sum(nil)

	if !hmac.Equal(expectedHMAC, providedHMAC) {
		return fmt.Errorf("HMAC verification failed")
	}
	return nil
}

func ComputeHMAC(message, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}
