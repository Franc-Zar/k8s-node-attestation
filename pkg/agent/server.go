package agent

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/franc-zar/k8s-node-attestation/pkg/attestation"
	cryptoUtils "github.com/franc-zar/k8s-node-attestation/pkg/crypto"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/veraison/cmw"
	"io"
	"net/http"
	"os"
	"strconv"
)

const (
	GetWorkerRegistrationCredentialsUrl = "/agent/worker/registration/credentials"
	WorkerRegistrationChallengeUrl      = "/agent/worker/registration/challenge"
	AcknowledgeRegistrationUrl          = "/agent/worker/registration/acknowledge"
	WorkerAttestationUrl                = "/agent/worker/attest"
)

type Server struct {
	Host                  string
	Port                  int
	imaMeasurementLogPath string
	rootCaCert            *x509.Certificate
	tpm                   *attestation.TPM
	router                *gin.Engine
	tlsCertificate        *x509.Certificate
	workerId              string
}

func New(tpm *attestation.TPM, tlsCertificate *x509.Certificate, rootCaCert *x509.Certificate) *Server {
	newServer := &Server{}
	newServer.tpm = tpm
	newServer.tlsCertificate = tlsCertificate
	newServer.rootCaCert = rootCaCert
	return newServer
}

func (s *Server) getWorkerRegistrationCredentials(c *gin.Context) {
	s.workerId = uuid.New().String()

	ekCert, err := s.tpm.GetEKCertificate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to fetch EK certificate",
			Status:  model.Error,
		})
	}

	aikNameData, aikPublicArea, err := s.tpm.CreateAIK()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to create AIK",
			Status:  model.Error,
		})
	}

	encodedEkCert := base64.StdEncoding.EncodeToString(ekCert)
	encodedAikNameData := base64.StdEncoding.EncodeToString(aikNameData)
	encodedAikPublicArea := base64.StdEncoding.EncodeToString(aikPublicArea)
	c.JSON(http.StatusOK, model.WorkerCredentialsResponse{UUID: s.workerId, EKCert: encodedEkCert, AIKNameData: encodedAikNameData, AIKPublicArea: encodedAikPublicArea})
}

func (s *Server) challengeWorker(c *gin.Context) {
	var workerChallenge model.WorkerChallenge
	// Bind the JSON request body to the struct
	if err := c.BindJSON(&workerChallenge); err != nil {
		c.JSON(http.StatusBadRequest, model.SimpleResponse{
			Message: "Invalid request payload",
			Status:  model.Error,
		})
		return
	}
	aikCredential, err := base64.StdEncoding.DecodeString(workerChallenge.AIKCredential)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.SimpleResponse{
			Message: "failed to decode aik credential from base64",
			Status:  model.Error,
		})
	}

	aikEncryptedSecret, err := base64.StdEncoding.DecodeString(workerChallenge.AIKEncryptedSecret)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.SimpleResponse{
			Message: "failed to decode aik encrypted secret from base64",
			Status:  model.Error,
		})
		return
	}

	ephemeralKey, err := s.tpm.ActivateAIKCredential(aikCredential, aikEncryptedSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.SimpleResponse{
			Message: "Agent failed to perform Credential Activation",
			Status:  model.Error,
		})
		return
	}

	salt, err := cryptoUtils.GenerateRandSequence(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to generate salt",
			Status:  model.Error,
		})
	}

	quoteNonce, err := cryptoUtils.ComputeHKDF(ephemeralKey, salt, cryptoUtils.NonceDerivationInfo, 8)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to compute quote nonce",
			Status:  model.Error,
		})
	}

	bootQuoteJSON, err := s.tpm.QuoteBootPCRs(quoteNonce)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Error while computing Boot Aggregate quote",
			Status:  model.Error,
		})
		return
	}

	// Compute HMAC on the worker UUID using the ephemeral key
	challengeHmac := cryptoUtils.ComputeHMAC([]byte(s.workerId), ephemeralKey)
	encodedChallengeHmac := base64.StdEncoding.EncodeToString(challengeHmac)
	encodedBootQuote := base64.StdEncoding.EncodeToString(bootQuoteJSON)
	encodedSalt := base64.StdEncoding.EncodeToString(salt)

	// Respond with success, including the HMAC of the UUID
	c.JSON(http.StatusOK, model.WorkerChallengeResponse{
		Message:   "Worker registration challenge decrypted and verified successfully",
		Status:    model.Success,
		HMAC:      encodedChallengeHmac,
		Salt:      encodedSalt,
		BootQuote: encodedBootQuote,
	})
	return
}

func (s *Server) acknowledgeRegistration(c *gin.Context) {

}

func (s *Server) workerAttestation(c *gin.Context) {
	var workerAttestationRequest model.WorkerAttestationRequest
	if err := c.BindJSON(&workerAttestationRequest); err != nil {
		c.JSON(http.StatusBadRequest, model.SimpleResponse{
			Message: "Invalid request payload",
			Status:  model.Error,
		})
		return
	}

	if s.workerId != workerAttestationRequest.NodeUUID {
		c.JSON(http.StatusUnauthorized, model.SimpleResponse{
			Message: "Received UUID mismatch with target worker UUID",
			Status:  model.Error,
		})
	}

	quoteNonce, err := base64.StdEncoding.DecodeString(workerAttestationRequest.Nonce)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.SimpleResponse{
			Message: "Agent failed to decode quote nonce",
			Status:  model.Error,
		})
		return
	}

	quotePcrs := []int{10}
	workerQuote, err := s.tpm.QuoteGeneralPurposePCRs(quoteNonce, quotePcrs)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.SimpleResponse{
			Message: "Agent failed to generate quote PCRs",
			Status:  model.Error,
		})
		return
	}

	encodedQuote := base64.StdEncoding.EncodeToString(workerQuote)

	measurementLog, err := s.getWorkerMeasurementLog()
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.SimpleResponse{
			Message: "Agent failed to fetch measurement log",
			Status:  model.Error,
		})
		return
	}

	evidence := cmw.NewCollection()

}

func (s *Server) getWorkerMeasurementLog() (string, error) {
	// Open the file
	imaMeasurementLog, err := os.Open(s.imaMeasurementLogPath)
	if err != nil {
		return "", fmt.Errorf("failed to open IMA measurement log: %v", err)
	}

	fileContent, err := io.ReadAll(imaMeasurementLog)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	err = imaMeasurementLog.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close IMA measurement log: %v", err)
	}
	base64Encoded := base64.StdEncoding.EncodeToString(fileContent)
	return base64Encoded, nil
}

func (s *Server) Start() {
	s.router = gin.Default()

	s.router.GET(GetWorkerRegistrationCredentialsUrl, s.getWorkerRegistrationCredentials) // GET worker identifying data (newly generated UUID, AIK, EK)
	s.router.POST(WorkerRegistrationChallengeUrl, s.challengeWorker)                      // POST challenge worker for Registration
	s.router.POST(AcknowledgeRegistrationUrl, s.acknowledgeRegistration)

	s.router.POST(WorkerAttestationUrl, s.workerAttestation) // POST attestation against one Pod running upon Worker of this agent

	// Start the server
	err := s.router.Run(":" + strconv.Itoa(s.Port))
	if err != nil {
		logger.Fatal("failed to start agent: %v", err)
	}
}
