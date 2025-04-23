package agent

import (
	"crypto/x509"
	"encoding/base64"
	"github.com/franc-zar/k8s-node-attestation/pkg/attestation"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"net/http"
	"strconv"
)

const (
	GetWorkerRegistrationCredentialsUrl = "/agent/worker/registration/credentials"
	WorkerRegistrationChallengeUrl      = "/agent/worker/registration/challenge"
	AcknowledgeRegistrationUrl          = "/agent/worker/registration/acknowledge"
	WorkerAttestationUrl                = "/agent/worker/attest"
)

type Server struct {
	host           string
	port           int
	tpm            *attestation.TPM
	router         *gin.Engine
	tlsCertificate *x509.Certificate
	workerId       string
}

func New(tpm *attestation.TPM, tlsCertificate *x509.Certificate) *Server {
	newServer := &Server{}
	newServer.tpm = tpm
	newServer.tlsCertificate = tlsCertificate
	return newServer
}

func (s *Server) getWorkerRegistrationCredentials(c *gin.Context) {
	s.workerId = uuid.New().String()

	ekCert, err := s.tpm.GetEKCertificate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Agent failed to fetch EK certificate",
			"status":  model.Error,
		})
	}

	aikNameData, aikPublicArea, err := s.tpm.CreateWorkerAIK()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Agent failed to create AIK",
			"status":  model.Error,
		})
	}

	encodedEkCert := base64.StdEncoding.EncodeToString(ekCert)

	c.JSON(http.StatusOK, gin.H{"uuid": s.workerId, "ekCert": encodedEkCert, "aikNameData": aikNameData, "aikPublicArea": aikPublicArea})
}

func (s *Server) challengeWorker(c *gin.Context) {

}

func (s *Server) acknowledgeRegistration(c *gin.Context) {

}

func (s *Server) workerAttestation(c *gin.Context) {

}

func (s *Server) Start() {
	s.router = gin.Default()

	s.router.GET(GetWorkerRegistrationCredentialsUrl, s.getWorkerRegistrationCredentials) // GET worker identifying data (newly generated UUID, AIK, EK)
	s.router.POST(WorkerRegistrationChallengeUrl, s.challengeWorker)                      // POST challenge worker for Registration
	s.router.POST(AcknowledgeRegistrationUrl, s.acknowledgeRegistration)

	s.router.POST(WorkerAttestationUrl, s.workerAttestation) // POST attestation against one Pod running upon Worker of this agent

	// Start the server
	err := s.router.Run(":" + strconv.Itoa(s.agentPort))
	if err != nil {
		logger.Fatal("failed to start registrar: %v", err)
	}
}
