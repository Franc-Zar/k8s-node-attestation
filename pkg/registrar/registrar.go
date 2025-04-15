package registrar

import (
	"fmt"
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
