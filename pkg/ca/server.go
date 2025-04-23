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
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	"math"
	"math/big"
	"time"
)

const CommonName = "Kubernetes Attestation Root CA"
const Organization = "Kubernetes Attestation"
const DatabaseName = "attestation-ca.db"
const HelpString = `Attestation CA is a plugin that manages certificates for components involved in the attestation process of nodes within a Kubernetes cluster.

Usage:
  attestation-ca <command> --flags [arguments]

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
      --csr <csr-base64>
          Issue a certificate using a Certificate Signing Request (CSR) base64-encoded

  revoke-certificate
      --cert, -c <pem-certificate-base64>
          Revoke a specific certificate by providing its pem certificate base64-encoded
      --all, -a 
          Revoke all issued certificates

  get-certificate
      --common-name, -cn <common-name>
          Retrieve a certificate by Common Name
      --serial-number, -sn <serial-number>
          Retrieve a certificate by Serial Number
      --root
		  Retrieve Root CA certificate

  get-crl
      Get the Certificate Revocation List (CRL)`

// Server represents a CA without an exposed Gin server
type Server struct {
	caRootCert   *x509.Certificate
	caRootKey    crypto.PrivateKey
	caRootKeyPEM []byte
	caDao        DAO
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

func New() (*Server, error) {
	newServer := &Server{}
	err := newServer.caDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Root CA database")
	}
	err = newServer.caDao.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Root CA database")
	}
	err = newServer.caDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Root CA database")
	}
	return newServer, nil
}

func (s *Server) Help() string {
	return HelpString
}

func (s *Server) SetCA() error {
	err := s.caDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Root CA database")
	}

	var rootCaCertificate *model.Certificate
	rootCaCertificate, s.caRootKeyPEM, err = s.caDao.GetRootCA()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("root CA is not initialized")
		} else {
			return fmt.Errorf("failed to get root CA certificate and key: %v", err)
		}
	}
	s.caRootCert, err = cryptoUtils.LoadCertificateFromPEM([]byte(rootCaCertificate.PEMCertificate))
	if err != nil {
		return fmt.Errorf("failed to load root CA certificate: %v", err)
	}

	// Decode the private key
	privateKey, err := cryptoUtils.DecodePrivateKeyFromPEM(s.caRootKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %v", err)
	}
	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		s.caRootKey = privateKey
	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	err = s.caDao.Close()
	if err != nil {
		return fmt.Errorf("failed to close Root CA database")
	}
	return nil
}

// InitCA initializes the CA and generates a self-signed certificate
func (s *Server) InitCA(rootKeyType KeyType) error {
	err := s.caDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Root CA database")
	}
	err = s.caDao.EraseAllTables()
	if err != nil {
		return fmt.Errorf("failed to erase all tables: %v", err)
	}

	switch rootKeyType {
	case RSA:
		rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return fmt.Errorf("could not generate root CA RSA key: %v", err)
		}
		s.caRootKey = rsaKey

	case ECDSA:
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("could not generate root CA ECDSA key: %v", err)
		}
		s.caRootKey = ecKey
	default:
		return fmt.Errorf("unsupported root key type")
	}

	newSerialNumber, err := generateSerialNumber()
	if err != nil {
		return fmt.Errorf("error while generating root ca certificate serial number")
	}

	if newSerialNumber == 0 {
		return fmt.Errorf("could not generate root ca certificate serial number")
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

	signer, ok := s.caRootKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("root key does not implement crypto.Signer")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return fmt.Errorf("could not create root CA certificate: %v", err)
	}

	s.caRootCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("could not parse root ca certificate")
	}

	caRootCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	switch key := s.caRootKey.(type) {
	case *rsa.PrivateKey:
		s.caRootKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return fmt.Errorf("could not marshal ECDSA key: %v", err)
		}
		s.caRootKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: b,
		})
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}

	rootCaCert := &model.Certificate{
		Id:             newSerialNumber,
		CommonName:     s.caRootCert.Subject.CommonName,
		PEMCertificate: string(caRootCertPEM),
	}

	err = s.caDao.StoreRootCA(rootCaCert, s.caRootKeyPEM)
	if err != nil {
		return fmt.Errorf("could not store root CA certificate: %v", err)
	}

	err = s.caDao.Close()
	if err != nil {
		return fmt.Errorf("failed to close Root CA database: %v", err)
	}

	return nil
}

func (s *Server) IssueCertificate(csrPEM []byte) (*model.Certificate, error) {
	err := s.caDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Root CA database: %v", err)
	}
	issuedCertificate, err := s.signCSR(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to issue new certificate: %v", err)

	}
	err = s.caDao.StoreIssuedCertificate(issuedCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to store newly issued certificate: %v", err)

	}

	err = s.caDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Root CA database: %v", err)
	}
	return issuedCertificate, nil
}

func (s *Server) GetLatestCRL() ([]byte, error) {
	err := s.caDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Root CA database: %v", err)
	}
	crl, err := s.caDao.GetLatestCRL()
	if err != nil {
		return nil, fmt.Errorf("failed to get latest crl: %v", err)
	}
	err = s.caDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Root CA database: %v", err)
	}
	return crl, nil
}

func (s *Server) RevokeCertificate(certPEM []byte) ([]byte, error) {
	err := s.caDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Root CA database: %v", err)
	}
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
	_, err = s.caDao.GetIssuedCertificateBySerialNumber(certSerial)
	if err != nil {
		return nil, fmt.Errorf("certificate not found in issued store: %v", err)
	}

	// Prepare new revoked certificate entry
	newRevokedEntry := x509.RevocationListEntry{
		SerialNumber:   certToRevoke.SerialNumber,
		RevocationTime: time.Now(),
		ReasonCode:     0,
	}

	// Load the latest CRL if available
	var allRevoked []x509.RevocationListEntry
	prevCRLPEM, err := s.caDao.GetLatestCRL()
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
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Create a new CRL
	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:        s.caRootCert.SignatureAlgorithm,
		RevokedCertificateEntries: allRevoked,
		Number:                    big.NewInt(newSerialNumber),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 1, 0),
	}

	// Ensure the key is a crypto.Signer
	signer, ok := s.caRootKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA root key does not implement crypto.Signer")
	}

	// Create CRL (Revocation List)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, s.caRootCert, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %v", err)
	}

	// Encode CRL to PEM
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	})

	// Store new CRL
	if err = s.caDao.StoreCRL(certSerial, crlPEM); err != nil {
		return nil, fmt.Errorf("failed to store CRL: %v", err)
	}

	// Remove the certificate from the issued store
	if err = s.caDao.DeleteIssuedCertificate(certSerial); err != nil {
		return nil, fmt.Errorf("failed to delete issued certificate: %v", err)
	}

	err = s.caDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Root CA database: %v", err)
	}

	return crlPEM, nil
}

func (s *Server) RevokeAllCertificates() ([]byte, error) {
	err := s.caDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Root CA database: %v", err)
	}
	issuedCerts, err := s.caDao.GetAllIssuedCertificates()
	if err != nil {
		return nil, fmt.Errorf("failed to get issued certificates: %v", err)
	}

	// Prepare the list of revoked certificates
	var revokedEntries []x509.RevocationListEntry
	for _, cert := range issuedCerts {
		// Decode the input PEM certificate
		block, _ := pem.Decode([]byte(cert.PEMCertificate))
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
		if errCert = s.caDao.DeleteIssuedCertificate(certSerial); errCert != nil {
			return nil, fmt.Errorf("failed to delete issued certificate: %v", errCert)
		}
	}

	// Load the latest CRL if available
	var allRevoked []x509.RevocationListEntry
	prevCRLPEM, err := s.caDao.GetLatestCRL()
	if err == nil {
		block, _ := pem.Decode(prevCRLPEM)
		if block != nil && block.Type == "X509 CRL" {
			parsedCRL, errCert := x509.ParseRevocationList(block.Bytes)
			if errCert == nil {
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
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Define CRL template (could include extensions, etc.)
	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:        s.caRootCert.SignatureAlgorithm,
		RevokedCertificateEntries: allRevoked,
		Number:                    big.NewInt(newSerialNumber), // Use a unique serial number for the CRL
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 1, 0), // valid for 1 month
	}

	// Ensure the key is a crypto.Signer
	signer, ok := s.caRootKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA root key does not implement crypto.Signer: %v", err)
	}

	// Create CRL (Revocation List)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, s.caRootCert, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %v", err)
	}

	// Encode CRL to PEM
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	})

	// Store the CRL in the DB
	if err = s.caDao.StoreCRL(newSerialNumber, crlPEM); err != nil {
		return nil, fmt.Errorf("failed to store CRL: %v", err)
	}

	err = s.caDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Root CA database: %v", err)
	}

	return crlPEM, nil
}

func (s *Server) Reset() error {
	err := s.caDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Root CA database: %v", err)
	}
	err = s.caDao.EraseAllTables()
	if err != nil {
		return fmt.Errorf("failed to erase all tables: %v", err)
	}
	err = s.caDao.Close()
	if err != nil {
		return fmt.Errorf("failed to close Root CA database: %v", err)
	}
	return nil
}

func (s *Server) GetCertificateByCommonName(commonName string) (*model.Certificate, error) {
	err := s.caDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Root CA database: %v", err)
	}

	cert, err := s.caDao.GetIssuedCertificateByCommonName(commonName)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate with CN: '%s': %v", commonName, err)
	}

	err = s.caDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Root CA database: %v", err)
	}
	return cert, nil
}

func (s *Server) GetCertificateBySerialNumber(serialNumber int64) (*model.Certificate, error) {
	err := s.caDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Root CA database: %v", err)
	}

	cert, err := s.caDao.GetIssuedCertificateBySerialNumber(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate with CN: '%d': %v", serialNumber, err)
	}

	err = s.caDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Root CA database: %v", err)
	}
	return cert, nil
}

func (s *Server) GetRootCACert() (*model.Certificate, error) {
	err := s.caDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Root CA database: %v", err)
	}

	caCert, err := s.caDao.GetRootCACert()
	if err != nil {
		return nil, fmt.Errorf("failed to get root CA certificate: %v", err)
	}

	err = s.caDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Root CA database: %v", err)
	}
	return caCert, nil
}

// Private
// -------------------------------------------------------------------------------------------------------------------

func generateSerialNumber() (int64, error) {
	// Max value for int64
	maxValue := big.NewInt(math.MaxInt64)

	for {
		serialNumber, err := rand.Int(rand.Reader, maxValue)
		if err != nil {
			return 0, err
		}
		// Avoid zero value
		if serialNumber.Sign() > 0 {
			return serialNumber.Int64(), nil
		}
	}
}

// signCSR signs a certificate signing request and returns a signed certificate in PEM format
func (s *Server) signCSR(csrPEM []byte) (*model.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse CSR: %v", err)
	}

	commonName := csr.Subject.CommonName

	if err = csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %v", err)
	}

	newSerialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("error while generating certificate serial number: %v", err)
	}

	if newSerialNumber == 0 {
		return nil, fmt.Errorf("could not generate certificate serial number")
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(newSerialNumber),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment, // keyEncipherement
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, s.caRootCert, csr.PublicKey, s.caRootKey)
	if err != nil {
		return nil, fmt.Errorf("could not sign certificate: %v", err)
	}

	certificate := &model.Certificate{
		Id:             newSerialNumber,
		CommonName:     commonName,
		PEMCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
	}

	return certificate, nil
}
