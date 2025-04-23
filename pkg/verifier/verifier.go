package verifier

import (
	"crypto/x509"
	"github.com/franc-zar/k8s-node-attestation/pkg/attestation"
	"github.com/franc-zar/k8s-node-attestation/pkg/cluster"
)

type Server struct {
	interactor cluster.Interactor
	tlsCert    *x509.Certificate
}

func New(tlsCert *x509.Certificate) *Server {
	newServer := &Server{}
	newServer.Init(tlsCert)
	return newServer
}

func (s *Server) Init(tlsCert *x509.Certificate) {
	s.interactor.ConfigureKubernetesClient()
	s.tlsCert = tlsCert
}

func (s *Server) EnrolWorker() {

}

func (s *Server) AttestWorker() {

}
