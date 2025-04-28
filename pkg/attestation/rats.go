package attestation

import (
	"fmt"
	"github.com/veraison/cmw"
)

const CmwCollectionTypeAttestationEvidence = "tag:attestation.com,2025:attestation-evidence"
const CmwCollectionTypeCredentialActivationEvidence = "tag:attestation.com,2025:credential-activation-evidence"

const (
	EatJWTMediaType       = "application/eat+jwt"
	EatCWTMediaType       = "application/eat+cwt"
	EatJsonClaimMediaType = "application/eat-ucs+json"
	EatCborClaimMediaType = "application/eat-ucs+cbor"
)

type Evidence struct {
	claims *cmw.CMW
}

func NewEvidence(cmwCollectionType string) (*Evidence, error) {
	var err error
	newEvidence := &Evidence{}
	newEvidence.claims, err = cmw.NewCollection(cmwCollectionType)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize attestation evidence: %w", err)
	}
	return newEvidence, nil
}

func NewClaim(mediaType any, value []byte, indicators ...cmw.Indicator) (*cmw.CMW, error) {
	claim, err := cmw.NewMonad(mediaType, value, indicators...)
	if err != nil {
		return nil, fmt.Errorf("failed to create claim: %w", err)
	}
	return claim, nil
}

func (e *Evidence) AddClaim(key any, claim *cmw.CMW) error {
	err := e.claims.AddCollectionItem(key, claim)
	if err != nil {
		return fmt.Errorf("failed to add claim to attestation evidence: %w", err)
	}
	return nil
}

func (e *Evidence) GetClaim(key any) (*cmw.CMW, error) {
	claim, err := e.claims.GetCollectionItem(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get claim from attestation evidence: %w", err)
	}
	return claim, nil
}

func (e *Evidence) MarshalEvidenceJSON() ([]byte, error) {
	evidenceJSON, err := e.claims.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims of attestation evidence: %w", err)
	}
	return evidenceJSON, nil
}

func (e *Evidence) UnmarshalEvidenceJSON(jsonClaims []byte) error {
	err := e.claims.UnmarshalJSON(jsonClaims)
	if err != nil {
		return fmt.Errorf("failed to unmarshal claims into attestation evidence: %w", err)
	}
	return nil
}
