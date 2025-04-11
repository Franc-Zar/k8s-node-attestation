package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	cryptoUtils "github.com/franc-zar/k8s-node-attestation/pkg/crypto"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"math/big"
	"time"
)

const CommonName = "Kubernetes Attestation Root CA"
const Organization = "Kubernetes Attestation"
const DatabaseName = "kubernetes-ca.db"

// Server represents a CA without an exposed Gin server
type Server struct {
	CARootCert    *x509.Certificate
	CARootKey     *rsa.PrivateKey
	CARootCertPEM []byte
	CARootKeyPEM  []byte
	CADao         DAO
}

func generateSerialNumber() (int64, error) {
	// 128-bit serial number (16 bytes)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return 0, err
	}
	return serialNumber.Int64(), nil
}

func (s *Server) SetCA() {
	var err error
	s.CADao.Open(DatabaseName)
	s.CARootCertPEM, s.CARootKeyPEM, err = s.CADao.GetRootCA()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Warning("root CA does not exist; initializing CA")
			s.Init()
			return
		} else {
			logger.Fatal("failed to get root CA certificate and key: %v", err)
		}
	}
	s.CARootCert, err = cryptoUtils.LoadCertificateFromPEM(s.CARootCertPEM)
	if err != nil {
		logger.Fatal("failed to load root CA certificate: %v", err)
	}
	s.CARootKey, err = cryptoUtils.DecodePrivateKeyFromPEM(s.CARootKeyPEM)
	if err != nil {
		logger.Fatal("failed to load root CA certificate: %v", err)
	}
}

// Init initializes the CA and generates a self-signed certificate
func (s *Server) Init() {
	var err error

	s.CARootKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Fatal("could not generate root ca RSA key")
	}

	newSerialNumber, err := generateSerialNumber()
	if err != nil {
		logger.Fatal("error while generating root ca certificate serial number")
	}

	if newSerialNumber == 0 {
		logger.Fatal("could not generate root ca certificate serial number")
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(newSerialNumber),
		Subject: pkix.Name{
			CommonName:   CommonName,
			Organization: []string{Organization},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &s.CARootKey.PublicKey, s.CARootKey)
	if err != nil {
		logger.Fatal("could not create root ca certificate")
	}

	s.CARootCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		logger.Fatal("could not parse root ca certificate")
	}

	s.CARootCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	s.CARootKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(s.CARootKey)})
	err = s.CADao.StoreRootCA(s.CARootCertPEM, s.CARootKeyPEM)
	if err != nil {
		logger.Fatal("could not store root CA certificate")
	}
}

func (s *Server) IssueCertificate(csrPEM []byte) []byte {
	serialNumber, issuedCert, err := s.SignCSR(csrPEM)
	if err != nil {
		logger.Error("failed to issue new certificate: %v", err)
		return nil
	}
	err = s.CADao.StoreIssuedCertificate(serialNumber, issuedCert)
	if err != nil {
		logger.Error("failed to store newly issued certificate: %v", err)
		return nil
	}
	return issuedCert
}

func (s *Server) RevokeCertificate(certPEM []byte) ([]byte, error) {
	// Decode the input PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM certificate")
	}
	certToRevoke, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	certSerial := certToRevoke.SerialNumber.Int64()

	// Make sure it's an issued certificate
	_, err = s.CADao.GetIssuedCertificate(certSerial)
	if err != nil {
		return nil, fmt.Errorf("certificate not found in issued store")
	}

	// Prepare revoked certificate entry
	revokedCert := pkix.RevokedCertificate{
		SerialNumber:   certToRevoke.SerialNumber,
		RevocationTime: time.Now(),
	}

	// Convert to x509.RevocationListEntry
	revokedEntry := x509.RevocationListEntry{
		SerialNumber:   revokedCert.SerialNumber,
		RevocationTime: revokedCert.RevocationTime,
		ReasonCode:     0, // Unspecified
	}

	newSerialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}
	if newSerialNumber == 0 {
		return nil, fmt.Errorf("failed to generate serial number")
	}

	// Define CRL template (could include extensions, etc.)
	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:        s.CARootCert.SignatureAlgorithm,
		RevokedCertificateEntries: []x509.RevocationListEntry{revokedEntry},
		Number:                    big.NewInt(newSerialNumber), // Use a unique serial number for the CRL (this is a placeholder)
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 1, 0), // valid for 1 month
	}

	// Create CRL (Revocation List)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, s.CARootCert, s.CARootKey)
	if err != nil {
		return nil, err
	}

	// Encode CRL to PEM
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	})

	// Store CRL in DB
	if err = s.CADao.StoreCRL(certSerial, crlPEM); err != nil {
		return nil, err
	}

	err = s.CADao.DeleteIssuedCertificate(certSerial)
	if err != nil {
		return nil, fmt.Errorf("failed to delete issued certificate: %v", err)
	}

	return crlPEM, nil
}

func (s *Server) RevokeAllCertificates() ([]byte, error) {
	// Retrieve all issued certificates
	issuedCertsPEM, err := s.CADao.GetAllIssuedCertificates()
	if err != nil {
		return nil, fmt.Errorf("failed to get issued certificates: %v", err)
	}

	// Prepare the list of revoked certificates
	var revokedEntries []x509.RevocationListEntry
	for _, certPEM := range issuedCertsPEM {
		// Decode the input PEM certificate
		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("invalid PEM certificate")
		}
		certToRevoke, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}
		certSerial := certToRevoke.SerialNumber.Int64()
		// Prepare revoked certificate entry for each certificate
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   big.NewInt(certSerial),
			RevocationTime: time.Now(),
		}

		// Convert to x509.RevocationListEntry
		revokedEntry := x509.RevocationListEntry{
			SerialNumber:   revokedCert.SerialNumber,
			RevocationTime: revokedCert.RevocationTime,
			ReasonCode:     0, // Unspecified
		}

		revokedEntries = append(revokedEntries, revokedEntry)

		// Optionally delete the certificate from the issued store
		if err = s.CADao.DeleteIssuedCertificate(certSerial); err != nil {
			return nil, fmt.Errorf("failed to delete issued certificate: %v", err)
		}
	}

	// Generate a new serial number for the CRL
	newSerialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}
	if newSerialNumber == 0 {
		return nil, fmt.Errorf("failed to generate serial number")
	}

	// Define CRL template (could include extensions, etc.)
	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:        s.CARootCert.SignatureAlgorithm,
		RevokedCertificateEntries: revokedEntries,
		Number:                    big.NewInt(newSerialNumber), // Use a unique serial number for the CRL
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 1, 0), // valid for 1 month
	}

	// Create CRL (Revocation List)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, s.CARootCert, s.CARootKey)
	if err != nil {
		return nil, err
	}

	// Encode CRL to PEM
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	})

	// Store the CRL in the DB
	if err := s.CADao.StoreCRL(newSerialNumber, crlPEM); err != nil {
		return nil, err
	}

	return crlPEM, nil
}

// SignCSR signs a certificate signing request and returns a signed certificate in PEM format
func (s *Server) SignCSR(csrPEM []byte) (int64, []byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return 0, nil, fmt.Errorf("invalid CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return 0, nil, fmt.Errorf("could not parse CSR")
	}

	if err := csr.CheckSignature(); err != nil {
		return 0, nil, fmt.Errorf("invalid CSR signature")
	}

	newSerialNumber, err := generateSerialNumber()
	if err != nil {
		return 0, nil, fmt.Errorf("error while generating certificate serial number")
	}

	if newSerialNumber == 0 {
		return 0, nil, fmt.Errorf("could not generate certificate serial number")
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(newSerialNumber),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, s.CARootCert, csr.PublicKey, s.CARootKey)
	if err != nil {
		return 0, nil, fmt.Errorf("could not sign certificate")
	}

	return newSerialNumber, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}
