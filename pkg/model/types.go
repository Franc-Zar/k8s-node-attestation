package model

type WorkerNode struct {
	UUID string `json:"UUID"`
	Name string `json:"name"`
	AIK  string `json:"AIK"`
}

type IMAEntry struct {
	FilePath string `json:"filePath"`
	FileHash string `json:"fileHash"`
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
	Id             string `json:"Id,omitempty"`
	CommonName     string `json:"commonName"`
	PEMCertificate string `json:"PEMCertificate"`
}

type TPMVendor struct {
	Id            string `json:"Id,omitempty"`
	CommonName    string `json:"commonName"`
	TCGIdentifier string `json:"TCGIdentifier"`
}

type Certificate struct {
	Id             string `json:"id,omitempty"`
	CommonName     string `json:"commonName"`
	PEMCertificate string `json:"PEMCertificate"`
}
