package attestation

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	cryptoUtils "github.com/franc-zar/k8s-node-attestation/pkg/crypto"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"io"
	"slices"
	"time"
)

var bootReservedPCRs = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

const (
	SimulatorPath = "simulator"
)

type KeyType int

const (
	RSA KeyType = iota
	ECC
)

func (k KeyType) String() string {
	switch k {
	case RSA:
		return "RSA"
	case ECC:
		return "ECC"
	default:
		return "Unknown"
	}
}

type TPM struct {
	rwc     io.ReadWriteCloser
	TPMPath string
	KeyType KeyType

	aikHandle tpmutil.Handle
	ekHandle  tpmutil.Handle
}

func New(tpmPath string, keyType KeyType) *TPM {
	newTpm := &TPM{}
	newTpm.Init(tpmPath, keyType)
	return newTpm
}

func (tpm *TPM) Init(tpmPath string, keyType KeyType) {
	tpm.TPMPath = tpmPath
	tpm.KeyType = keyType
}

func (tpm *TPM) Open() {
	var err error
	if tpm.TPMPath == "" {
		logger.Fatal("Unable to open TPM: no device path provided")
	}

	if tpm.TPMPath == SimulatorPath {
		tpm.rwc, err = simulator.GetWithFixedSeedInsecure(1073741825)
		if err != nil {
			logger.Fatal("Unable to open TPM simulator: %v", err)
		}
	} else {
		tpm.rwc, err = tpmutil.OpenTPM(tpm.TPMPath)
		if err != nil {
			logger.Fatal("unable to open TPM: %v", err)
		}
	}
}

func (tpm *TPM) Close() {
	err := tpm.rwc.Close()
	if err != nil {
		logger.Fatal("Unable to close TPM: %v", err)
	}
}

func (tpm *TPM) getEK() *client.Key {
	var EK *client.Key
	var err error
	switch tpm.KeyType {
	case RSA:
		EK, err = client.EndorsementKeyRSA(tpm.rwc)
	case ECC:
		EK, err = client.EndorsementKeyECC(tpm.rwc)
	default:
		logger.Fatal("unsupported key type: %s", tpm.KeyType.String())
	}
	if err != nil {
		logger.Fatal("unable to get EK: %v", err)
	}
	return EK
}

func (tpm *TPM) getAIK() *client.Key {
	var AIK *client.Key
	var err error
	switch tpm.KeyType {
	case RSA:
		AIK, err = client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), tpm.aikHandle)
	case ECC:
		AIK, err = client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateECC(), tpm.aikHandle)
	default:
		logger.Fatal("unsupported key type: %s", tpm.KeyType.String())
	}
	if err != nil {
		logger.Fatal("Unable to get AIK: %v", err)
	}
	return AIK
}

func (tpm *TPM) GetEKCertificate() ([]byte, error) {
	EK := tpm.getEK()
	tpm.ekHandle = EK.Handle()
	defer EK.Close()

	var pemEKCert []byte
	EKCert := EK.Cert()
	if EKCert != nil {
		pemEKCert = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: EKCert.Raw,
		})
		return pemEKCert, nil
	}
	return nil, fmt.Errorf("unable to get EK certificate")
}

// GetEKandCertificate is used to get TPM EK public key and certificate.
// It returns both the EK and the certificate to be compliant with simulator TPMs not provided with a certificate
func (tpm *TPM) GetEKandCertificate() ([]byte, []byte, error) {
	EK := tpm.getEK()
	tpm.ekHandle = EK.Handle()
	defer EK.Close()

	var pemEKCert []byte
	EKCert := EK.Cert()
	if EKCert != nil {
		pemEKCert = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: EKCert.Raw,
		})
	}

	if pemEKCert == nil {
		pemEKCert = []byte("EK Certificate not provided")
	}

	pemPublicEK, err := cryptoUtils.EncodePublicKeyToPEM(EK.PublicKey())
	if err != nil {
		return nil, nil, fmt.Errorf("unable to encode public key to pem: %v", err)
	}
	return pemPublicEK, pemEKCert, nil
}

// CreateAIK Function to create a new AIK (Attestation Identity Key) for the Agent
func (tpm *TPM) CreateAIK() ([]byte, []byte, error) {
	AIK := tpm.getAIK()
	tpm.aikHandle = AIK.Handle()
	defer AIK.Close()

	AIKNameData, err := AIK.Name().Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode AIK Name data")
	}

	AIKPublicArea, err := AIK.PublicArea().Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode AIK public area")
	}

	return AIKNameData, AIKPublicArea, nil
}

// Custom function that checks if PCRstoQuote contains any element from bootReservedPCRs
// and returns the boolean and the list of matching PCRs
func containsAndReturnPCRs(pcrsToQuote []int) (bool, []int) {
	var foundPCRs []int
	for _, pcr := range pcrsToQuote {
		if slices.Contains(bootReservedPCRs, pcr) {
			foundPCRs = append(foundPCRs, pcr)
		}
	}
	if len(foundPCRs) == 0 {
		return false, nil // No matching PCRs found
	}
	return true, foundPCRs
}

func (tpm *TPM) QuoteGeneralPurposePCRs(nonce []byte, pcrSet []int) ([]byte, error) {
	pcrSetContainsBootReserved, foundPCR := containsAndReturnPCRs(pcrSet)
	if pcrSetContainsBootReserved {
		return nil, fmt.Errorf("cannot compute Quote on provided PCR set %v: boot reserved PCRs where included: %v", foundPCR, bootReservedPCRs)
	}

	generalPurposePcrSet := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
		PCRs: pcrSet,
	}

	AIK := tpm.getAIK()
	defer AIK.Close()

	quote, err := AIK.Quote(generalPurposePcrSet, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create quote over PCRs %v: %v", pcrSet, err)
	}
	quoteJSON, err := json.Marshal(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to parse quote result as json: %v", err)
	}
	return quoteJSON, nil
}

func (tpm *TPM) QuoteBootPCRs(nonce []byte) ([]byte, error) {
	bootPCRs := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
		PCRs: bootReservedPCRs,
	}

	AIK := tpm.getAIK()
	defer AIK.Close()

	quote, err := AIK.Quote(bootPCRs, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create quote over PCRs 0-9: %v", err)
	}
	quoteJSON, err := json.Marshal(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to parse quote result as json: %v", err)
	}
	return quoteJSON, nil
}

func (tpm *TPM) ActivateAIKCredential(aikCredential, aikEncryptedSecret []byte) ([]byte, error) {
	session, _, err := tpm2legacy.StartAuthSession(
		tpm.rwc,
		tpm2legacy.HandleNull,
		tpm2legacy.HandleNull,
		make([]byte, 16),
		nil,
		tpm2legacy.SessionPolicy,
		tpm2legacy.AlgNull,
		tpm2legacy.AlgSHA256,
	)
	if err != nil {
		return nil, fmt.Errorf("creating auth session failed: %v", err)
	}
	// Set PolicySecret on the endorsement handle, enabling EK use
	auth := tpm2legacy.AuthCommand{Session: tpm2legacy.HandlePasswordSession, Attributes: tpm2legacy.AttrContinueSession}
	if _, _, err = tpm2legacy.PolicySecret(tpm.rwc, tpm2legacy.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		return nil, fmt.Errorf("policy secret failed: %v", err)
	}

	// Create authorization commands, linking session and password auth
	auths := []tpm2legacy.AuthCommand{
		{Session: tpm2legacy.HandlePasswordSession, Attributes: tpm2legacy.AttrContinueSession},
		{Session: session, Attributes: tpm2legacy.AttrContinueSession},
	}

	// Attempt to activate the credential
	challengeSecret, err := tpm2legacy.ActivateCredentialUsingAuth(tpm.rwc, auths, tpm.aikHandle, tpm.ekHandle, aikCredential[2:], aikEncryptedSecret[2:])
	if err != nil {
		return nil, fmt.Errorf("AIK activate_credential failed: %v", err)
	}
	return challengeSecret, nil
}

func (tpm *TPM) SignEvidenceWithAIK(issuer string, evidence *Evidence) (string, error) {
	if tpm.aikHandle.HandleValue() == 0 {
		return "", fmt.Errorf("AIK is not already created")
	}

	AIK := tpm.getAIK()
	defer AIK.Close()

	// Step 1: Marshal the CMW claims
	cmwJSON, err := evidence.ToJSON()
	if err != nil {
		return "", fmt.Errorf("failed to marshal CMW: %w", err)
	}

	// Step 2: Parse CMW to map
	var cmwMap map[string]any
	if err = json.Unmarshal(cmwJSON, &cmwMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal CMW JSON: %w", err)
	}

	currentTime := time.Now()
	// Step 3: Create the JWT claims
	claims := jwt.MapClaims{
		"exp": currentTime.Add(3 * time.Minute).Unix(),
		"iat": currentTime.Unix(),
		"nbf": currentTime.Unix(),
		"cmw": cmwMap,
	}

	// Step 4: Create the JWT token (algorithm depends on key type)
	var token *jwt.Token
	var signingMethod jwt.SigningMethod

	switch tpm.KeyType {
	case ECC:
		signingMethod = jwt.SigningMethodES256
	case RSA:
		signingMethod = jwt.SigningMethodRS256
	default:
		return "", fmt.Errorf("unsupported key type: %s", tpm.KeyType.String())
	}

	token = jwt.NewWithClaims(signingMethod, claims)

	signingString, err := token.SigningString()
	if err != nil {
		return "", fmt.Errorf("failed to create JWT signing string: %w", err)
	}

	sigBytes, err := AIK.SignData([]byte(signingString))
	if err != nil {
		return "", fmt.Errorf("failed to sign with AIK: %v", err)
	}

	sigEncoded := base64.RawURLEncoding.EncodeToString(sigBytes)
	signedEvidenceJWT := signingString + "." + sigEncoded
	return signedEvidenceJWT, nil
}

func (tpm *TPM) SignWithAIK(message []byte) ([]byte, error) {
	if tpm.aikHandle.HandleValue() == 0 {
		return nil, fmt.Errorf("AIK is not already created")
	}

	AIK, err := client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), tpm.aikHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AIK from TPM: %v", err)
	}
	defer AIK.Close()

	aikSigned, err := AIK.SignData(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with AIK: %v", err)
	}
	return aikSigned, nil
}
