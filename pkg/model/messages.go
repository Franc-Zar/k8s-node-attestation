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
