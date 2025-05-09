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
	"github.com/veraison/cmw"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
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
	tpm                   *attestation.TPM
	router                *gin.Engine
	tlsCertificate        *x509.Certificate
	rootCaCert            *x509.Certificate
	workerUID             string
}

func New(tpm *attestation.TPM, tlsCertificate *x509.Certificate, rootCaCert *x509.Certificate, workerUID string) *Server {
	newServer := &Server{}
	newServer.tpm = tpm
	newServer.tlsCertificate = tlsCertificate
	newServer.rootCaCert = rootCaCert
	newServer.workerUID = workerUID
	return newServer
}

func (s *Server) getWorkerRegistrationCredentials(c *gin.Context) {
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

	currentTime := time.Now()

	c.JSON(http.StatusOK, model.CredentialResponse{
		CNF: model.AIKCnf{
			KID: s.workerUID,
			X5C: []string{encodedEkCert},
			AIK: model.AIKInfo{
				Name:       encodedAikNameData,
				PublicArea: encodedAikPublicArea,
			},
		},
		Iat: currentTime.Unix(),
		Nbf: currentTime.Unix(),
		Exp: currentTime.Add(3 * time.Minute).Unix(),
	})
}

func (s *Server) acknowledgeWorkerRegistration(c *gin.Context) {

}

func (s *Server) challengeWorker(c *gin.Context) {
	var aikActivationChallenge model.CredentialActivationRequest
	// Bind the JSON request body to the struct
	if err := c.BindJSON(&aikActivationChallenge); err != nil {
		c.JSON(http.StatusBadRequest, model.SimpleResponse{
			Message: "Invalid request payload",
			Status:  model.Error,
		})
		return
	}

	if s.workerUID != aikActivationChallenge.CNF.KID {
		c.JSON(http.StatusUnauthorized, model.SimpleResponse{
			Message: "KID does not match AIK owning Worker identifier",
			Status:  model.Error,
		})
	}

	aikCredential, err := base64.StdEncoding.DecodeString(aikActivationChallenge.CNF.Challenge.CredentialBlob)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.SimpleResponse{
			Message: "Agent failed to decode AIK credential from base64",
			Status:  model.Error,
		})
	}

	aikEncryptedSecret, err := base64.StdEncoding.DecodeString(aikActivationChallenge.CNF.Challenge.Secret)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.SimpleResponse{
			Message: "Agent failed to decode AIK encrypted secret from base64",
			Status:  model.Error,
		})
		return
	}

	ephemeralKey, err := s.tpm.ActivateAIKCredential(aikCredential, aikEncryptedSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.SimpleResponse{
			Message: "Agent failed to perform AIK Credential Activation",
			Status:  model.Error,
		})
		return
	}

	salt, err := base64.StdEncoding.DecodeString(aikActivationChallenge.CNF.Challenge.Salt)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.SimpleResponse{
			Message: "Agent failed to decode challenge salt from base64",
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

	bootQuoteClaim, err := attestation.NewClaim(attestation.EatJsonClaimMediaType, bootQuoteJSON, cmw.Evidence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to create claim from boot quote",
			Status:  model.Error,
		})
	}

	credentialActivationEvidence, err := attestation.NewEvidence(attestation.CmwCollectionTypeCredentialActivationEvidence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to create evidence for credential activation",
			Status:  model.Error,
		})
	}

	err = credentialActivationEvidence.AddClaim(attestation.BootQuoteClaimKey, bootQuoteClaim)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to add boot quote to credential activation evidence ",
			Status:  model.Error,
		})
	}

	evidenceJSON, err := credentialActivationEvidence.ToJSON()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to marshal evidence to JSON",
			Status:  model.Error,
		})
	}

	// Compute HMAC on the worker UUID using the ephemeral key
	challengeHmac := cryptoUtils.ComputeHMAC([]byte(s.workerUID), ephemeralKey)
	encodedChallengeHmac := base64.StdEncoding.EncodeToString(challengeHmac)

	currentTime := time.Now()
	// Respond with success, including the HMAC of the UUID
	c.JSON(http.StatusOK, model.CredentialActivationResponse{
		CNF: model.ChallengeSolutionCnf{
			KID:  s.workerUID,
			HMAC: encodedChallengeHmac,
		},
		CMW: evidenceJSON,
		Iat: currentTime.Unix(),
		Nbf: currentTime.Unix(),
		Exp: currentTime.Add(3 * time.Minute).Unix(),
	})
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

	if s.workerUID != workerAttestationRequest.CNF.KID {
		c.JSON(http.StatusUnauthorized, model.SimpleResponse{
			Message: "Received UID mismatch with target worker UID",
			Status:  model.Error,
		})
	}

	quoteNonce, err := base64.StdEncoding.DecodeString(workerAttestationRequest.CNF.Nonce)
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

	measurementLog, err := s.getWorkerMeasurementLog()
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.SimpleResponse{
			Message: "Agent failed to fetch measurement log",
			Status:  model.Error,
		})
		return
	}

	attestationEvidence, err := attestation.NewEvidence(attestation.CmwCollectionTypeAttestationEvidence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to generate attestation evidence",
			Status:  model.Error,
		})
	}

	quoteClaim, err := attestation.NewClaim(attestation.EatJsonClaimMediaType, workerQuote, cmw.Evidence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to generate quote claim",
			Status:  model.Error,
		})
	}

	measurementLogClaim, err := attestation.NewClaim(attestation.EatJsonClaimMediaType, measurementLog, cmw.Evidence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to generate measurement log claim",
			Status:  model.Error,
		})
	}

	err = attestationEvidence.AddClaim(attestation.IMAPcrQuoteClaimKey, quoteClaim)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to add quote claim to attestation evidence",
			Status:  model.Error,
		})
	}

	err = attestationEvidence.AddClaim(attestation.IMAMeasurementLogClaimKey, measurementLogClaim)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to add measurement log claim to attestation evidence",
			Status:  model.Error,
		})
	}

	evidenceJSON, err := attestationEvidence.ToJSON()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.SimpleResponse{
			Message: "Agent failed to marshal attestation evidence to JSON",
			Status:  model.Error,
		})
	}

	currentTime := time.Now()
	c.JSON(http.StatusOK, model.WorkerAttestationResponse{
		CNF: model.AttestationResponseCnf{
			KID: s.workerUID,
		},
		CMW: evidenceJSON,
		Iat: currentTime.Unix(),
		Nbf: currentTime.Unix(),
		Exp: currentTime.Add(3 * time.Minute).Unix(),
	})
}

func (s *Server) getWorkerMeasurementLog() ([]byte, error) {
	// Open the file
	imaMeasurementLog, err := os.Open(s.imaMeasurementLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open IMA measurement log: %v", err)
	}

	measurementLogContent, err := io.ReadAll(imaMeasurementLog)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	err = imaMeasurementLog.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close IMA measurement log: %v", err)
	}
	return measurementLogContent, nil
}

func (s *Server) Start() {
	s.router = gin.Default()

	s.router.GET(GetWorkerRegistrationCredentialsUrl, s.getWorkerRegistrationCredentials) // GET worker identifying data (newly generated UUID, AIK, EK)
	s.router.POST(WorkerRegistrationChallengeUrl, s.challengeWorker)                      // POST challenge worker for Registration
	s.router.POST(WorkerAttestationUrl, s.workerAttestation)                              // POST attestation against the Worker
	s.router.POST(AcknowledgeRegistrationUrl, s.acknowledgeWorkerRegistration)

	// Start the server
	err := s.router.Run(":" + strconv.Itoa(s.Port))
	if err != nil {
		logger.Fatal("failed to start agent: %v", err)
	}
}
