package model

import "encoding/json"

const Success = "success"
const Error = "error"

type SimpleResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type WorkerAttestationRequest struct {
	CNF AttestationRequestCnf `json:"cnf"`
	Iat int64                 `json:"iat"` // Issued at timestamp
	Nbf int64                 `json:"nbf"` // Not before timestamp
	Exp int64                 `json:"exp"` // Expiration timestamp
}

type WorkerAttestationResponse struct {
	CNF AttestationResponseCnf `json:"cnf"`
	CMW json.RawMessage        `json:"cmw"` // RATS CMW including as claims quote over ima pcr and ima measurement log content
	Iat int64                  `json:"iat"` // Issued at timestamp
	Nbf int64                  `json:"nbf"` // Not before timestamp
	Exp int64                  `json:"exp"` // Expiration timestamp
}

// AttestationRequestCnf is the CNF associated to an attestation request
type AttestationRequestCnf struct {
	KID   string `json:"kid"` // UUID of the worker
	Nonce string `json:"nonce"`
}

type AttestationResponseCnf struct {
	KID string `json:"kid"` // The AIK key identifier
}

// AIKInfo represents the AIK information (Name and Public Area) for the worker.
type AIKInfo struct {
	Name       string `json:"name"`       // base64-encoded AIK Name Data
	PublicArea string `json:"publicArea"` // base64-encoded AIK Public Area
}

// AIKCnf represents the CNF (confirmation) structure that includes the worker's key information.
type AIKCnf struct {
	KID string   `json:"kid"` // UUID of the worker
	X5C []string `json:"x5c"` // EK certificate chain (usually just one cert)
	AIK AIKInfo  `json:"aik"` // AIK information (Name and Public Area)
}

type CredentialResponse struct {
	CNF AIKCnf `json:"cnf"`
	Iat int64  `json:"iat"` // Issued at timestamp
	Nbf int64  `json:"nbf"` // Not before timestamp
	Exp int64  `json:"exp"` // Expiration timestamp
}

type CredentialActivationChallenge struct {
	CredentialBlob string `json:"credentialBlob"`
	Secret         string `json:"secret"`
	Salt           string `json:"salt"`
}

type CredentialActivationCnf struct {
	KID       string                        `json:"kid"` // UUID of the worker
	Challenge CredentialActivationChallenge `json:"challenge"`
}

type CredentialActivationRequest struct {
	CNF CredentialActivationCnf `json:"cnf"`
	Iat int64                   `json:"iat"` // Issued at timestamp
	Nbf int64                   `json:"nbf"` // Not before timestamp
	Exp int64                   `json:"exp"` // Expiration timestamp
}

type ChallengeSolutionCnf struct {
	KID  string `json:"kid"`  // UUID of the worker
	HMAC string `json:"hmac"` // HMAC computed using the activate credential challenge secret
}

// CredentialActivationResponse represents the response structure for credential activation challenge.
type CredentialActivationResponse struct {
	CNF ChallengeSolutionCnf `json:"cnf"` // CNF data containing worker's key information
	CMW json.RawMessage      `json:"cmw"` // RATS CMW including the quote computed using the newly activated aik
	CSR string               `json:"csr"` // base64 encoded pem certificate of the CSR for the TLS certificate needed by the Agent to establish mTLS with Verifier
	Iat int64                `json:"iat"` // Issued at timestamp
	Nbf int64                `json:"nbf"` // Not before timestamp
	Exp int64                `json:"exp"` // Expiration timestamp
}

type AcknowledgeWorkerRegistration struct {
	X5C []string `json:"x5c"` // EK certificate chain (usually just one cert)
	Iat int64    `json:"iat"` // Issued at timestamp
	Nbf int64    `json:"nbf"` // Not before timestamp
	Exp int64    `json:"exp"` // Expiration timestamp
}
