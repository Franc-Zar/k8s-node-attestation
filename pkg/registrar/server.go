package registrar

import (
	"fmt"
	cryptoUtils "github.com/franc-zar/k8s-node-attestation/pkg/crypto"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
)

const DatabaseName = "attestation-registrar.db"

type Server struct {
	registrarDao DAO
}

func (s *Server) Init() error {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Registrar database: %w", err)
	}

	err = s.registrarDao.Init()
	if err != nil {
		return fmt.Errorf("failed to initialize Registrar database: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return fmt.Errorf("failed to close Registrar database: %w", err)
	}

	return nil
}

func (s *Server) RegisterNode(node *model.WorkerNode) error {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Registrar database: %w", err)
	}

	err = s.registrarDao.AddWorker(node)
	if err != nil {
		return fmt.Errorf("failed to register worker node: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return fmt.Errorf("failed to close Registrar database: %w", err)
	}

	return nil
}

func (s *Server) UnregisterNode(nodeUUID string) error {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Registrar database: %w", err)
	}

	err = s.registrarDao.DeleteWorker(nodeUUID)
	if err != nil {
		return fmt.Errorf("failed to unregister worker node: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return nil
}

func (s *Server) StoreTPMIntermediateCACertificate(tpmCaCertificate *model.TPMCACertificate) error {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Registrar database: %w", err)
	}

	cert, err := cryptoUtils.LoadCertificateFromPEM([]byte(tpmCaCertificate.PEMCertificate))
	if err != nil {
		return fmt.Errorf("failed to load certificate from PEM: %w", err)
	}

	rootCaCertificate, err := s.registrarDao.GetTPMCaCertificate(cert.Issuer.CommonName)
	if err != nil {
		return fmt.Errorf("failed to get root CA certificate: %w", err)
	}

	rootCert, err := cryptoUtils.LoadCertificateFromPEM([]byte(rootCaCertificate.PEMCertificate))
	if err != nil {
		return fmt.Errorf("failed to load root certificate from PEM: %w", err)
	}

	err = cryptoUtils.VerifyTPMIntermediateCACertificate(cert, rootCert)
	if err != nil {
		return fmt.Errorf("failed to verify intermediate certificate: %w", err)
	}

	err = s.registrarDao.AddTPMCaCertificate(tpmCaCertificate)
	if err != nil {
		return fmt.Errorf("failed to add TPM Vendor CA certificate: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return fmt.Errorf("failed to close Registrar database: %w", err)
	}

	return nil
}

func (s *Server) StoreTPMRootCACertificate(tpmRootCACertificate *model.TPMCACertificate) error {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Registrar database: %w", err)
	}
	return nil
}
