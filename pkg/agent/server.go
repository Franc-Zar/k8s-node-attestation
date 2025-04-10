package agent

import (
	"crypto/x509"
	"github.com/franc-zar/k8s-node-attestation/pkg/attestation"
	"github.com/gin-gonic/gin"
)

const (
	GetWorkerRegistrationCredentialsUrl = "/agent/worker/registration/credentials"
	WorkerRegistrationChallengeUrl      = "/agent/worker/registration/challenge"
	AcknowledgeRegistrationUrl          = "/agent/worker/registration/acknowledge"
	AttestationUrl                      = "/agent/worker/attest"
)

type Server struct {
	tpm            *attestation.TPM
	router         *gin.Engine
	tlsCertificate *x509.Certificate
}
