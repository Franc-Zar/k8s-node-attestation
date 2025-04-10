package attestation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	cryptoUtils "github.com/franc-zar/k8s-node-attestation/pkg/crypto"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"io"
	"slices"
	"sync"
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
	rwc       io.ReadWriteCloser
	tpmPath   string
	aikHandle tpmutil.Handle
	ekHandle  tpmutil.Handle
	mtx       sync.Mutex
}

func (tpm *TPM) Init(tpmPath string) {
	tpm.tpmPath = tpmPath
}

func (tpm *TPM) Open() {
	var err error
	if tpm.tpmPath == "" {
		logger.Fatal("Unable to open TPM: no device path provided")
	}

	if tpm.tpmPath == SimulatorPath {
		tpm.rwc, err = simulator.GetWithFixedSeedInsecure(1073741825)
		if err != nil {
			logger.Fatal("Unable to open TPM simulator: %v", err)
		}
	} else {
		tpm.rwc, err = tpmutil.OpenTPM(tpm.tpmPath)
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

func (tpm *TPM) GetEKCertificate(keyType KeyType) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	var EK *client.Key
	var err error

	switch keyType {
	case RSA:
		EK, err = client.EndorsementKeyRSA(tpm.rwc)
	case ECC:
		EK, err = client.EndorsementKeyECC(tpm.rwc)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType.String())
	}
	if err != nil {
		return nil, fmt.Errorf("unable to get EK: %v", err)
	}

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

// getWorkerEKandCertificate is used to get TPM EK public key and certificate.
// It returns both the EK and the certificate to be compliant with simulator TPMs not provided with a certificate
func (tpm *TPM) GetEKandCertificate(keyType KeyType) ([]byte, []byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()
	var EK *client.Key
	var err error

	switch keyType {
	case RSA:
		EK, err = client.EndorsementKeyRSA(tpm.rwc)
	case ECC:
		EK, err = client.EndorsementKeyECC(tpm.rwc)
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType.String())
	}
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get EK: %v", err)
	}

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

// Function to create a new AIK (Attestation Identity Key) for the Agent
func (tpm *TPM) CreateAIK(keyType KeyType) ([]byte, []byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	var AIK *client.Key
	var err error

	switch keyType {
	case RSA:
		AIK, err = client.AttestationKeyRSA(tpm.rwc)
	case ECC:
		AIK, err = client.AttestationKeyECC(tpm.rwc)
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType.String())
	}

	if err != nil {
		return nil, nil, fmt.Errorf("unable to create %s AIK: %v", keyType, err)
	}
	defer AIK.Close()

	tpm.aikHandle = AIK.Handle()

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

func (tpm *TPM) QuoteGeneralPurposePCRs(keyType KeyType, nonce []byte, pcrSet []int) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	pcrSetContainsBootReserved, foundPCR := containsAndReturnPCRs(pcrSet)
	if pcrSetContainsBootReserved {
		return nil, fmt.Errorf("cannot compute Quote on provided PCR set %v: boot reserved PCRs where included: %v", foundPCR, bootReservedPCRs)
	}

	generalPurposePcrSet := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
		PCRs: pcrSet,
	}

	var AIK *client.Key
	var err error
	switch keyType {
	case RSA:
		AIK, err = client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), tpm.aikHandle)
	case ECC:
		AIK, err = client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateECC(), tpm.aikHandle)
	}
	if err != nil {
		return nil, fmt.Errorf("error while retrieving AIK: %v", err)
	}
	if AIK == nil {
		return nil, fmt.Errorf("cannot quote general purpose PCRs: no AIK found")
	}
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

func (tpm *TPM) QuoteBootPCRs(keyType KeyType, nonce []byte) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	bootPCRs := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
		PCRs: bootReservedPCRs,
	}

	var AIK *client.Key
	var err error
	switch keyType {
	case RSA:
		AIK, err = client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), tpm.aikHandle)
	case ECC:
		AIK, err = client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateECC(), tpm.aikHandle)
	}
	if err != nil {
		return nil, fmt.Errorf("error while retrieving AIK: %v", err)
	}
	if AIK == nil {
		return nil, fmt.Errorf("cannot quote general purpose PCRs: no AIK found")
	}
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
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

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

func (tpm *TPM) SignWithAIK(message []byte) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	if tpm.aikHandle.HandleValue() == 0 {
		return nil, fmt.Errorf("AIK is not already created")
	}

	AIK, err := client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), tpm.aikHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AIK from TPM")
	}

	defer AIK.Close()

	aikSigned, err := AIK.SignData(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with AIK: %v", err)
	}
	return aikSigned, nil
}

func Hash(message []byte) ([]byte, error) {
	// Compute SHA256 hash
	hash := sha256.New()
	_, err := hash.Write(message)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash: %v", err)
	}
	// Get the final hash as a hex-encoded string
	digest := hash.Sum(nil)
	return digest, nil
}

// Generate a cryptographically secure random symmetric key of the specified size in bytes
func GenerateEphemeralKey(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("key size must be greater than 0")
	}

	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}
	return key, nil
}
