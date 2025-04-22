package registrar

import (
	"fmt"
	cryptoUtils "github.com/franc-zar/k8s-node-attestation/pkg/crypto"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
)

const DatabaseName = "attestation-registrar.db"
const HelpString = `Attestation Registrar is a plugin that manages certificates and node registration for the attestation process in a Kubernetes cluster.

Usage:
  attestation-registrar <command> --flags [arguments]

Commands:
  help
      Show this help message

  register-node
      --worker, -w <node-json>
          Register a worker node in the database

  unregister-node
      --uuid <node-uuid>
          Remove a worker node from the database using its UUID

  get-worker
      --uuid <uuid>
          Retrieve a worker node by UUID
      --name <name>
          Retrieve a worker node by name
      --all
          List all registered worker nodes

  get-vendor
      --tcg-id <id>
          Retrieve a TPM vendor by TCG identifier
	  --all      
          List all TPM vendors

  store-vendor-cert
      --intermediate <pem-certificate-base64>
          Store and verify a TPM Intermediate CA certificate

      --root <pem-certificate-base64>
          Store a TPM Root CA certificate after verification

  get-vendor-cert
      --common-name, -cn <common-name>
          Retrieve a TPM CA certificate by Common Name
      --all    
          List all TPM CA certificates

  delete-vendor-cert
      --cn <common-name>
          Delete a TPM CA certificate by Common Name`

type Server struct {
	registrarDao DAO
}

func New() (*Server, error) {
	newServer := &Server{}
	err := newServer.registrarDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Registrar database: %w", err)
	}

	err = newServer.registrarDao.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Registrar database: %w", err)
	}

	err = newServer.registrarDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return newServer, nil
}

func (s *Server) GetWorkerByUUID(UUID string) (*model.WorkerNode, error) {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Registrar database: %w", err)
	}

	workerNode, err := s.registrarDao.GetWorkerByUUID(UUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get worker by UUID %s: %w", UUID, err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return workerNode, nil
}

func (s *Server) Help() string {
	return HelpString
}

func (s *Server) GetAllWorkers() ([]model.WorkerNode, error) {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Registrar database: %w", err)
	}

	workers, err := s.registrarDao.GetAllWorkers()
	if err != nil {
		return nil, fmt.Errorf("failed to get all workers: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return workers, nil
}

func (s *Server) GetWorkerByName(name string) (*model.WorkerNode, error) {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Registrar database: %w", err)
	}

	workerNode, err := s.registrarDao.GetWorkerByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get worker by name %s: %w", name, err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return workerNode, nil
}

func (s *Server) GetAllTPMCaCertificates() ([]model.TPMCACertificate, error) {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Registrar database: %w", err)
	}

	tpmCaCertificates, err := s.registrarDao.GetAllTPMCaCertificates()
	if err != nil {
		return nil, fmt.Errorf("failed to get all TPM certificates: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return tpmCaCertificates, nil
}

func (s *Server) DeleteTPMCaCertificate(commonName string) error {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Registrar database: %w", err)
	}

	err = s.registrarDao.DeleteTPMCaCertificate(commonName)
	if err != nil {
		return fmt.Errorf("failed to delete TPM certificate: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return nil
}

func (s *Server) GetTPMVendors() ([]model.TPMVendor, error) {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Registrar database: %w", err)
	}

	tpmVendors, err := s.registrarDao.GetAllTPMVendors()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TPM Vendors: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return tpmVendors, nil
}

func (s *Server) GetTPMVendorByTCGId(tcgIdentifier string) (*model.TPMVendor, error) {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Registrar database: %w", err)
	}

	tpmVendor, err := s.registrarDao.GetTPMVendorByTCGId(tcgIdentifier)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TPM Vendors: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return tpmVendor, nil
}

func (s *Server) GetTPMCaCertificate(commonName string) (*model.TPMCACertificate, error) {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Registrar database: %w", err)
	}

	certificate, err := s.registrarDao.GetTPMCaCertificate(commonName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TPM CA Certificate: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return certificate, nil
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

func (s *Server) StoreTPMIntermediateCACertificate(tpmCaCertificatePEM []byte) error {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Registrar database: %w", err)
	}

	cert, err := cryptoUtils.LoadCertificateFromPEM(tpmCaCertificatePEM)
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

	certificate := &model.TPMCACertificate{
		Id:             rootCert.SerialNumber.Int64(),
		CommonName:     rootCert.Subject.CommonName,
		PEMCertificate: string(tpmCaCertificatePEM),
	}

	err = s.registrarDao.AddTPMCaCertificate(certificate)
	if err != nil {
		return fmt.Errorf("failed to add TPM Vendor CA certificate: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return nil
}

func (s *Server) StoreTPMRootCACertificate(tpmRootCACertificatePEM []byte) error {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Registrar database: %w", err)
	}

	rootCert, err := cryptoUtils.LoadCertificateFromPEM(tpmRootCACertificatePEM)
	if err != nil {
		return fmt.Errorf("failed to load root certificate from PEM: %w", err)
	}

	tpmVendors, err := s.registrarDao.GetAllTPMVendors()
	if err != nil {
		return fmt.Errorf("failed to get all TPM Vendors: %w", err)
	}

	err = cryptoUtils.VerifyTPMRootCACertificate(rootCert, tpmVendors)
	if err != nil {
		return fmt.Errorf("failed to verify root CA certificate: %w", err)
	}

	certificate := &model.TPMCACertificate{
		Id:             rootCert.SerialNumber.Int64(),
		CommonName:     rootCert.Subject.CommonName,
		PEMCertificate: string(tpmRootCACertificatePEM),
	}

	err = s.registrarDao.AddTPMCaCertificate(certificate)
	if err != nil {
		return fmt.Errorf("failed to add TPM Vendor CA certificate: %w", err)
	}

	err = s.registrarDao.Close()
	if err != nil {
		return fmt.Errorf("failed to close Registrar database: %w", err)
	}
	return nil
}
