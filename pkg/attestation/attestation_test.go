package attestation

import (
	"github.com/stretchr/testify/assert"
	"github.com/veraison/cmw"
	"testing"
)

func TestNewEvidence(t *testing.T) {
	// Test case where we provide a valid collection type
	evidence, err := NewEvidence(CmwCollectionTypeAttestationEvidence)
	assert.NoError(t, err, "Expected no error when creating new evidence")
	assert.NotNil(t, evidence, "Expected new evidence to be non-nil")
}

func TestNewClaim(t *testing.T) {
	// Test case where we provide valid data for creating a claim
	mediaType := EatJsonClaimMediaType
	value := []byte("some value for the claim")
	claim, err := NewClaim(mediaType, value)
	assert.NoError(t, err, "Expected no error when creating new claim")
	assert.NotNil(t, claim, "Expected new claim to be non-nil")
	monadType, err := claim.GetMonadType()
	assert.NoError(t, err, "Expected no error when getting monad type")
	assert.Equal(t, mediaType, monadType, "Expected the claim to have correct media type")
}

func TestAddClaim(t *testing.T) {
	// Test adding a valid claim to evidence
	evidence, err := NewEvidence(CmwCollectionTypeAttestationEvidence)
	assert.NoError(t, err, "Expected no error when creating new evidence")
	claim, err := NewClaim(EatJsonClaimMediaType, []byte("test claim"), cmw.Evidence)
	assert.NoError(t, err, "Expected no error when creating new claim")

	err = evidence.AddClaim("testClaimKey", claim)
	assert.NoError(t, err, "Expected no error when adding claim to evidence")
}

func TestGetClaim(t *testing.T) {
	// Test retrieving a claim from evidence
	evidence, err := NewEvidence(CmwCollectionTypeAttestationEvidence)
	assert.NoError(t, err, "Expected no error when creating new evidence")

	claim1, err := NewClaim(EatJsonClaimMediaType, []byte("test claim1"))
	assert.NoError(t, err, "Expected no error when creating new claim1")

	claim2, err := NewClaim(EatJsonClaimMediaType, []byte("test claim2"))
	assert.NoError(t, err, "Expected no error when creating new claim2")

	err = evidence.AddClaim("testClaimKey1", claim1)
	assert.NoError(t, err, "Expected no error when adding claim2 to evidence")

	err = evidence.AddClaim("testClaimKey2", claim2)
	assert.NoError(t, err, "Expected no error when adding claim2 to evidence")

	retrievedClaim, err := evidence.GetClaim("testClaimKey2")
	assert.NoError(t, err, "Expected no error when getting claim from evidence")
	assert.NotNil(t, retrievedClaim, "Expected retrieved claim to be non-nil")
	assert.Equal(t, claim2, retrievedClaim, "Expected retrieved claim to match claim")
}

func TestMarshalEvidenceJSON(t *testing.T) {
	// Test marshaling the evidence to JSON
	evidence, err := NewEvidence(CmwCollectionTypeAttestationEvidence)
	assert.NoError(t, err, "Expected no error when creating new evidence")

	claim, err := NewClaim(EatJsonClaimMediaType, []byte("test claim"))
	assert.NoError(t, err, "Expected no error when creating new claim")

	err = evidence.AddClaim("testClaimKey", claim)
	assert.NoError(t, err, "Expected no error when adding claim to evidence")

	jsonData, err := evidence.ToJSON()
	assert.NoError(t, err, "Expected no error when marshaling evidence to JSON")
	assert.NotNil(t, jsonData, "Expected marshaled JSON data to be non-nil")
}

func TestFromJSON(t *testing.T) {
	// Test unmarshalling the evidence from JSON
	evidence, err := NewEvidence(CmwCollectionTypeAttestationEvidence)
	assert.NoError(t, err, "Expected no error when creating new evidence")

	claim, err := NewClaim(EatJsonClaimMediaType, []byte("test claim"), cmw.Evidence)
	assert.NoError(t, err, "Expected no error when creating new claim")

	err = evidence.AddClaim("testClaimKey", claim)
	assert.NoError(t, err, "Expected no error when adding claim to evidence")

	jsonData, err := evidence.ToJSON()
	assert.NoError(t, err, "Expected no error when marshaling evidence to JSON")

	// Create a new evidence object and unmarshal the JSON
	retrievedEvidence, err := NewEvidence(CmwCollectionTypeAttestationEvidence)
	assert.NoError(t, err, "Expected no error when creating new evidence")
	err = retrievedEvidence.FromJSON(jsonData)
	assert.NoError(t, err, "Expected no error when unmarshalling JSON into evidence")
	collectionType, err := retrievedEvidence.claims.GetCollectionType()
	assert.NoError(t, err, "Expected no error when getting collection type")
	assert.Equal(t, retrievedEvidence.claims.GetKind(), evidence.claims.GetKind(), "Expected kind to match evidence")
	assert.Equal(t, collectionType, CmwCollectionTypeAttestationEvidence, "Expected collection type to match evidence")
	assert.Equal(t, retrievedEvidence.claims.GetKind(), evidence.claims.GetKind(), "Expected evidence to match evidence")

	retrievedClaim, err := retrievedEvidence.GetClaim("testClaimKey")
	assert.NoError(t, err, "Expected no error when getting claim from evidence")
	assert.Equal(t, retrievedClaim.GetKind(), claim.GetKind(), "Expected retrieved claim kind to match claim")

	retrievedClaimValue, err := retrievedClaim.GetMonadValue()
	assert.NoError(t, err, "Expected no error when getting claim value from evidence")
	claimValue, err := claim.GetMonadValue()
	assert.NoError(t, err, "Expected no error when getting claim value from evidence")
	assert.Equal(t, retrievedClaimValue, claimValue, "Expected retrieved claim kind to match claim")

	retrievedClaimType, err := retrievedClaim.GetMonadType()
	assert.NoError(t, err, "Expected no error when getting claim type value from evidence")
	claimType, err := claim.GetMonadType()
	assert.NoError(t, err, "Expected no error when getting claim type from evidence")
	assert.Equal(t, retrievedClaimType, claimType, "Expected retrieved claim type to match claim")

}
