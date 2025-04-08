package model

type WorkerNode struct {
	UUID string `json:"UUID"`
	Name string `json:"name"`
	AIK  string `json:"AIK"`
}

type AgentConfig struct {
	TPMPath                 string `json:"TPMPath"`
	IMAMountPath            string `json:"IMAMountPath"`
	IMAMeasurementLogPath   string `json:"IMAMeasurementLogPath"`
	ImageName               string `json:"imageName"`
	AgentPort               int32  `json:"agentPort"`
	AgentNodePortAllocation int32  `json:"agentNodePortAllocation"`
}

type TPMCACertificate struct {
	CertificateId  string `json:"certificateId,omitempty"`
	CommonName     string `json:"commonName"`
	PEMCertificate string `json:"PEMCertificate"`
}

type TPMVendor struct {
	VendorId      string `json:"vendorId,omitempty"`
	Name          string `json:"vendorName"`
	TCGIdentifier string `json:"TCGIdentifier"`
}
