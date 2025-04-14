package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
const HelpString = `Attestation CA is a plugin that manages certificates for components involved in the attestation process of nodes within a Kubernetes cluster.

Usage:
  attestation-ca <command> [--flags]

Commands:
  help
      Show this help message

  reset
      Erase current Root CA configuration

  init
      --root-key-alg ECDSA | RSA
          Set up and initialize the Root CA (if not already done) by generating 
          a private signing key using the chosen algorithm and creating the root certificate

  issue-certificate
      --csr
          Issue a certificate using a Certificate Signing Request (CSR) base64-encoded

  revoke-certificate
      --cert, -c
          Revoke a specific certificate using its PEM-encoded content
      --all, -a
          Revoke all issued certificates

  get-certificate
      --common-name, -cn
          Retrieve a certificate by Common Name

  get-crl
      Get the Certificate Revocation List (CRL)`

// Server represents a CA without an exposed Gin server
type Server struct {
	CARootCert    *x509.Certificate
	CARootKey     crypto.PrivateKey
	CARootCertPEM []byte
	CARootKeyPEM  []byte
	CADao         DAO
}

type KeyType int

const (
	RSA KeyType = iota
	ECDSA
)

func (k KeyType) String() string {
	switch k {
	case RSA:
		return "RSA"
	case ECDSA:
		return "ECDSA"
	default:
		return "Unknown"
	}
}

func New() *Server {
	newServer := &Server{}
	newServer.CADao.Open(DatabaseName)
	defer newServer.CADao.Close()
	newServer.CADao.Init()
	return newServer
}

func (s *Server) Help() {
	logger.Info(HelpString)
}

func (s *Server) SetCA() {
	var err error
	s.CADao.Open(DatabaseName)
	defer s.CADao.Close()
	s.CARootCertPEM, s.CARootKeyPEM, err = s.CADao.GetRootCA()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Fatal("root CA is not initialized")
		} else {
			logger.Fatal("failed to get root CA certificate and key: %v", err)
		}
	}
	s.CARootCert, err = cryptoUtils.LoadCertificateFromPEM(s.CARootCertPEM)
	if err != nil {
		logger.Fatal("failed to load root CA certificate: %v", err)
	}

	// Decode the private key
	privateKey, err := cryptoUtils.DecodePrivateKeyFromPEM(s.CARootKeyPEM)
	if err != nil {
		logger.Fatal("failed to decode private key: %v", err)
	}
	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		s.CARootKey = privateKey
	default:
		logger.Fatal("unsupported private key type: %T", privateKey)
	}
}

// InitCA initializes the CA and generates a self-signed certificate
func (s *Server) InitCA(rootKeyType KeyType) {
	s.CADao.Open(DatabaseName)
	defer s.CADao.Close()
	err := s.CADao.EraseAllTables()
	if err != nil {
		logger.Fatal("failed to erase all tables: %v", err)
	}

	switch rootKeyType {
	case RSA:
		rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			logger.Fatal("could not generate root CA RSA key:", err)
		}
		s.CARootKey = rsaKey

	case ECDSA:
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			logger.Fatal("could not generate root CA ECDSA key:", err)
		}
		s.CARootKey = ecKey
	default:
		logger.Fatal("unsupported root key type")
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

	signer, ok := s.CARootKey.(crypto.Signer)
	if !ok {
		logger.Fatal("root key does not implement crypto.Signer")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		logger.Fatal("could not create root CA certificate: %v", err)
	}

	s.CARootCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		logger.Fatal("could not parse root ca certificate")
	}

	s.CARootCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	switch key := s.CARootKey.(type) {
	case *rsa.PrivateKey:
		s.CARootKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			logger.Fatal("could not marshal ECDSA key: %v", err)
		}
		s.CARootKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: b,
		})
	default:
		logger.Fatal("unsupported key type: %T", key)
	}

	err = s.CADao.StoreRootCA(s.CARootCertPEM, s.CARootKeyPEM)
	if err != nil {
		logger.Fatal("could not store root CA certificate")
	}
	logger.Success("Correctly setup Root CA")
}

func (s *Server) IssueCertificate(csrPEM []byte) []byte {
	s.CADao.Open(DatabaseName)
	defer s.CADao.Close()
	serialNumber, commonName, issuedCert, err := s.signCSR(csrPEM)
	if err != nil {
		logger.Error("failed to issue new certificate: %v", err)
		return nil
	}
	err = s.CADao.StoreIssuedCertificate(serialNumber, commonName, issuedCert)
	if err != nil {
		logger.Error("failed to store newly issued certificate: %v", err)
		return nil
	}
	logger.Success("Correctly issued new certificate")
	return issuedCert
}

func (s *Server) GetLatestCRL() []byte {
	crl, err := s.CADao.GetLatestCRL()
	if err != nil {
		logger.Fatal("failed to get latest crl: %v", err)
	}
	logger.Success("successfully retrieved latest crl")
	return crl
}

func (s *Server) RevokeCertificate(certPEM []byte) ([]byte, error) {
	s.CADao.Open(DatabaseName)
	defer s.CADao.Close()
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

	// Prepare new revoked certificate entry
	newRevokedEntry := x509.RevocationListEntry{
		SerialNumber:   certToRevoke.SerialNumber,
		RevocationTime: time.Now(),
		ReasonCode:     0,
	}

	// Load the latest CRL if available
	var allRevoked []x509.RevocationListEntry
	prevCRLPEM, err := s.CADao.GetLatestCRL()
	if err == nil {
		block, _ := pem.Decode(prevCRLPEM)
		if block != nil && block.Type == "X509 CRL" {
			parsedCRL, err := x509.ParseRevocationList(block.Bytes)
			if err == nil {
				allRevoked = parsedCRL.RevokedCertificateEntries
			}
		}
	}

	// Append the new revocation entry
	allRevoked = append(allRevoked, newRevokedEntry)

	// Generate a new CRL serial number
	newSerialNumber, err := generateSerialNumber()
	if err != nil || newSerialNumber == 0 {
		return nil, fmt.Errorf("failed to generate serial number")
	}

	// Create a new CRL
	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:        s.CARootCert.SignatureAlgorithm,
		RevokedCertificateEntries: allRevoked,
		Number:                    big.NewInt(newSerialNumber),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 1, 0),
	}

	// Ensure the key is a crypto.Signer
	signer, ok := s.CARootKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA root key does not implement crypto.Signer")
	}

	// Create CRL (Revocation List)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, s.CARootCert, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %v", err)
	}

	// Encode CRL to PEM
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	})

	// Store new CRL
	if err = s.CADao.StoreCRL(certSerial, crlPEM); err != nil {
		return nil, fmt.Errorf("failed to store CRL: %v", err)
	}

	// Remove the certificate from the issued store
	if err = s.CADao.DeleteIssuedCertificate(certSerial); err != nil {
		return nil, fmt.Errorf("failed to delete issued certificate: %v", err)
	}

	logger.Success("Revoked certificate")
	return crlPEM, nil
}

func (s *Server) RevokeAllCertificates() ([]byte, error) {
	s.CADao.Open(DatabaseName)
	defer s.CADao.Close()
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
		certToRevoke, errCert := x509.ParseCertificate(block.Bytes)
		if errCert != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", errCert)
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
		if errCert = s.CADao.DeleteIssuedCertificate(certSerial); errCert != nil {
			return nil, fmt.Errorf("failed to delete issued certificate: %v", errCert)
		}
	}

	// Load the latest CRL if available
	var allRevoked []x509.RevocationListEntry
	prevCRLPEM, err := s.CADao.GetLatestCRL()
	if err == nil {
		block, _ := pem.Decode(prevCRLPEM)
		if block != nil && block.Type == "X509 CRL" {
			parsedCRL, err := x509.ParseRevocationList(block.Bytes)
			if err == nil {
				allRevoked = parsedCRL.RevokedCertificateEntries
			}
		}
	}

	// Append the new revocation entry
	allRevoked = append(allRevoked, revokedEntries...)

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
		RevokedCertificateEntries: allRevoked,
		Number:                    big.NewInt(newSerialNumber), // Use a unique serial number for the CRL
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 1, 0), // valid for 1 month
	}

	// Ensure the key is a crypto.Signer
	signer, ok := s.CARootKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA root key does not implement crypto.Signer")
	}

	// Create CRL (Revocation List)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, s.CARootCert, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %v", err)
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

	logger.Success("Revoked all certificates")
	return crlPEM, nil
}

func (s *Server) Reset() {
	s.CADao.Open(DatabaseName)
	defer s.CADao.Close()
	err := s.CADao.EraseAllTables()
	if err != nil {
		logger.Fatal("failed to erase all tables: %v", err)
	}
	logger.Success("Correctly reset Root CA")
}

func (s *Server) GetCertificateByCommonName(commonName string) ([]byte, error) {
	s.CADao.Open(DatabaseName)
	defer s.CADao.Close()
	certPEM, err := s.CADao.GetIssuedCertificateByCommonName(commonName)
	if err != nil {
		logger.Error("Failed to get certificate with CN: '%s': %v", commonName, err)
		return nil, fmt.Errorf("failed to get certificate with CN: '%s': %v", commonName, err)
	}
	return certPEM, nil
}

// Private
// -------------------------------------------------------------------------------------------------------------------

func generateSerialNumber() (int64, error) {
	// 128-bit serial number (16 bytes)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return 0, err
	}
	return serialNumber.Int64(), nil
}

// signCSR signs a certificate signing request and returns a signed certificate in PEM format
func (s *Server) signCSR(csrPEM []byte) (int64, string, []byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return 0, "", nil, fmt.Errorf("invalid CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return 0, "", nil, fmt.Errorf("could not parse CSR")
	}

	commonName := csr.Subject.CommonName

	if err := csr.CheckSignature(); err != nil {
		return 0, "", nil, fmt.Errorf("invalid CSR signature")
	}

	newSerialNumber, err := generateSerialNumber()
	if err != nil {
		return 0, "", nil, fmt.Errorf("error while generating certificate serial number")
	}

	if newSerialNumber == 0 {
		return 0, "", nil, fmt.Errorf("could not generate certificate serial number")
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(newSerialNumber),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment, // keyEncipherement
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, s.CARootCert, csr.PublicKey, s.CARootKey)
	if err != nil {
		return 0, "", nil, fmt.Errorf("could not sign certificate")
	}

	return newSerialNumber, commonName, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}
