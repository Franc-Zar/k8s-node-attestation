package registrar

import (
	"fmt"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
)

const DatabaseName = "kubernetes-ca.db"

type Server struct {
	registrarDao DAO
}

func (s *Server) Init() error {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return fmt.Errorf("failed to open Registrar database: %w", err)
	}

	defer func(registrarDao *DAO) {
		err := registrarDao.Close()
		if err != nil {
			return
		}
	}(&s.registrarDao)

	err = s.registrarDao.Init()
	if err != nil {
		return fmt.Errorf("failed to initialize Registrar database: %w", err)
	}
	return nil
}

func (s *Server) RegisterNode(node *model.WorkerNode) error {
	err := s.registrarDao.Open(DatabaseName)
	if err != nil {
		return err
	}
	defer s.registrarDao.Close()
	err := s.registrarDao.AddWorker(node)
	if err != nil {
		return fmt.Errorf("failed to register worker node: %w", err)
	}
}

func (s *Server) UnregisterNode(node *model.WorkerNode) {
	s.registrarDao.Open(DatabaseName)
	defer s.registrarDao.Close()
}
