package agentfacts

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
)

type credentialSetHashCredential struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	Capabilities []string  `json:"capabilities"`
	ValidFrom    time.Time `json:"validFrom"`
	ValidUntil   time.Time `json:"validUntil"`
	Signature    string    `json:"signature"`
}

type marshaledCredentialSetHashCredential struct {
	credential credentialSetHashCredential
	encoded    []byte
}

// CredentialSetHash128 returns the AgentAddr120 credential-set commitment for credentials.
func CredentialSetHash128(credentials []CapabilityCredential) ([16]byte, error) {
	if len(credentials) == 0 {
		return agentaddr.Hash128([]byte{}), nil
	}

	marshaledCredentials := make([]marshaledCredentialSetHashCredential, 0, len(credentials))
	for _, credential := range credentials {
		capabilities := append([]string(nil), credential.Capabilities...)
		sort.Strings(capabilities)
		canonicalCredential := credentialSetHashCredential{
			ID:           credential.ID,
			Type:         credential.Type,
			Issuer:       credential.Issuer,
			Subject:      credential.Subject,
			Capabilities: capabilities,
			ValidFrom:    credential.ValidFrom,
			ValidUntil:   credential.ValidUntil,
			Signature:    credential.Signature,
		}
		encoded, err := json.Marshal(canonicalCredential)
		if err != nil {
			return [16]byte{}, err
		}
		marshaledCredentials = append(marshaledCredentials, marshaledCredentialSetHashCredential{
			credential: canonicalCredential,
			encoded:    encoded,
		})
	}

	sort.Slice(marshaledCredentials, func(i, j int) bool {
		return bytes.Compare(marshaledCredentials[i].encoded, marshaledCredentials[j].encoded) < 0
	})

	canonicalCredentials := make([]credentialSetHashCredential, 0, len(marshaledCredentials))
	for _, marshaledCredential := range marshaledCredentials {
		canonicalCredentials = append(canonicalCredentials, marshaledCredential.credential)
	}
	canonicalBytes, err := json.Marshal(canonicalCredentials)
	if err != nil {
		return [16]byte{}, err
	}

	return agentaddr.Hash128(canonicalBytes), nil
}
