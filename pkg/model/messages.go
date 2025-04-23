package model

const Success = "success"
const Error = "error"

type WorkerCredentialsResponse struct {
	UUID          string `json:"UUID"`
	EKCert        string `json:"EKCert"`
	AIKNameData   string `json:"AIKNameData"`
	AIKPublicArea string `json:"AIKPublicArea"`
}

type SimpleResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type WorkerChallenge struct {
	AIKCredential      string `json:"AIKCredential"`
	AIKEncryptedSecret string `json:"AIKEncryptedSecret"`
}

type WorkerChallengeResponse struct {
	Message   string `json:"message"`
	Status    string `json:"status"`
	HMAC      string `json:"hmac"`
	Salt      string `json:"salt"`
	BootQuote string `json:"bootQuote"`
}
