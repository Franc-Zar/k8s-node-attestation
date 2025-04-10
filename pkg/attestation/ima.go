package attestation

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const IMABufTemplateEntryFields = 6
const ColonByte = byte(58)
const NullByte = byte(0)

// extractSHADigest extracts the algorithm (e.g., "sha256") and the actual hex digest from a string with the format "sha<algo>:<hex_digest>"
func extractShaDigest(input string) (string, string, error) {
	// Define a regular expression to match the prefix "sha<number>:" followed by the hex digest
	re := regexp.MustCompile(`^sha[0-9]+:`)

	// Check if the input matches the expected format
	if matches := re.FindStringSubmatch(input); matches != nil {
		fileHashElements := strings.Split(input, ":")

		return fileHashElements[0], fileHashElements[1], nil
	}
	return "", "", fmt.Errorf("input does not have a valid sha<algo>:<hex_digest> format")
}

// Helper function to compute the new hash by concatenating previous hash and template hash
func extendEntry(previousHash []byte, templateHash string) ([]byte, error) {
	hash := sha256.New()
	templateHashBytes, err := hex.DecodeString(templateHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode template hash field: %v", err)
	}
	dataToHash := append(previousHash, templateHashBytes...)
	hash.Write(dataToHash)
	return hash.Sum(nil), nil
}

// IMAVerification checks the integrity of the IMA measurement logger against the received Quote and returns the entries related to the pod being attested for statical analysis of executed software and the AttestationResult
func MeasurementLogValidation(measurementLog, pcr10Digest string) error {
	decodedLog, err := base64.StdEncoding.DecodeString(measurementLog)
	if err != nil {
		return fmt.Errorf("failed to decode IMA measurement logger: %v", err)
	}

	logLines := strings.Split(string(decodedLog), "\n")
	if len(logLines) > 0 && logLines[len(logLines)-1] == "" {
		logLines = logLines[:len(logLines)-1] // Remove the last empty line --> each entry adds a \n so last line will add an empty line
	}

	// initial PCR configuration
	previousHash := make([]byte, 32)

	// Iterate through each line and extract relevant fields
	for idx, imaLine := range logLines {
		// Split the line by whitespace
		IMAFields := strings.Fields(imaLine)
		if len(IMAFields) < IMABufTemplateEntryFields {
			return fmt.Errorf("IMA measurement log integrity check failed: entry %d not compliant with template: %s", idx, imaLine)
		}

		templateHashField := IMAFields[1]
		fileHashField := IMAFields[3]
		filePathField := IMAFields[4]
		bufField := IMAFields[5]

		hashAlgo, fileHash, err := extractShaDigest(fileHashField)
		if err != nil {
			return fmt.Errorf("IMA measurement log integrity check failed: entry: %d file hash is invalid: %s", idx, imaLine)
		}

		extendValue, err := validateEntry(templateHashField, hashAlgo, fileHash, filePathField, bufField)
		if err != nil {
			return fmt.Errorf("IMA measurement log integrity check failed: entry: %d is invalid: %s", idx, imaLine)
		}

		extendedHash, err := extendEntry(previousHash, extendValue)
		if err != nil {
			return fmt.Errorf("error computing hash at index %d: %v\n", idx, err)
		}

		if hex.EncodeToString(extendedHash) == pcr10Digest {
			return nil
		}
		previousHash = extendedHash
	}
	return fmt.Errorf("IMA measurement log is invalid: re-computed aggregate does not match stored PCR 10 digest")
}

func checkPodUidMatch(path, podUid string) bool {
	var regexPattern string
	// Replace dashes in podUid with underscores
	adjustedPodUid := strings.ReplaceAll(podUid, "-", "_")
	// Regex pattern to match the pod UID in the path
	regexPattern = fmt.Sprintf(`kubepods[^\/]*-pod%s\.slice`, regexp.QuoteMeta(adjustedPodUid))

	// Compile the regex
	r, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}
	// Check if the path contains the pod UID
	return r.MatchString(path)
}

func computeEntryTemplateHash(packedFileHash, packedFilePath, packedBuf []byte) (string, string) {
	packedTemplateEntry := append(packedFileHash, packedFilePath...)
	packedTemplateEntry = append(packedTemplateEntry, packedBuf...)
	sha1Hash := sha1.Sum(packedTemplateEntry)
	sha256Hash := sha256.Sum256(packedTemplateEntry)

	return hex.EncodeToString(sha1Hash[:]), hex.EncodeToString(sha256Hash[:])
}

func packHashField(hashAlg string, fileHash []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Pack total length (algorithm + 2 extra bytes + hash length)
	totalLen := uint32(len(hashAlg) + 2 + len(fileHash))
	if err := binary.Write(buf, binary.LittleEndian, totalLen); err != nil {
		return nil, fmt.Errorf("failed to pack total length: %v", err)
	}

	// Pack algorithm
	if _, err := buf.Write([]byte(hashAlg)); err != nil {
		return nil, fmt.Errorf("failed to pack algorithm: %v", err)
	}

	// Pack COLON_BYTE (1 byte)
	if err := buf.WriteByte(ColonByte); err != nil {
		return nil, fmt.Errorf("failed to pack COLON_BYTE: %v", err)
	}

	// Pack NULL_BYTE (1 byte)
	if err := buf.WriteByte(NullByte); err != nil {
		return nil, fmt.Errorf("failed to pack NULL_BYTE: %v", err)
	}

	// Pack fileHash (len(fileHash) bytes)
	if _, err := buf.Write(fileHash); err != nil {
		return nil, fmt.Errorf("failed to pack fileHash: %v", err)
	}

	return buf.Bytes(), nil
}

func packPathField(path []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Pack length (4 bytes)
	length := uint32(len(path) + 1) // length + 1 for NULL_BYTE
	if err := binary.Write(buf, binary.LittleEndian, length); err != nil {
		return nil, fmt.Errorf("failed to pack length: %v", err)
	}

	// Pack path (len(path) bytes)
	if _, err := buf.Write(path); err != nil {
		return nil, fmt.Errorf("failed to pack path: %v", err)
	}

	// Pack NULL_BYTE (1 byte)
	if err := binary.Write(buf, binary.LittleEndian, NullByte); err != nil {
		return nil, fmt.Errorf("failed to pack NULL_BYTE: %v", err)
	}
	return buf.Bytes(), nil
}

func validateEntry(templateHashField, hashAlg, fileHash, filePathField, bufField string) (string, error) {
	decodedFileHash, err := hex.DecodeString(fileHash)
	if err != nil {
		return "", fmt.Errorf("failed to decode 'file hash' field")
	}

	packedFileHash, err := packHashField(hashAlg, decodedFileHash)
	if err != nil {
		return "", fmt.Errorf("failed to pack 'file hash' field")
	}

	packedFilePath, err := packPathField([]byte(filePathField))
	if err != nil {
		return "", fmt.Errorf("failed to pack 'file path' field")
	}

	packedBufField, err := packPathField([]byte(bufField))
	if err != nil {
		return "", fmt.Errorf("failed to pack 'buf' field")
	}

	recomputedTemplateHashSha1, recomputedTemplateHashSha256 := computeEntryTemplateHash(packedFileHash, packedFilePath, packedBufField)
	if recomputedTemplateHashSha1 != templateHashField {
		return "", fmt.Errorf("re-computed template hash does not match stored entry template hash")
	}
	return recomputedTemplateHashSha256, nil
}
