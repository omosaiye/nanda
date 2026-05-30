package agentaddr

import (
	"errors"
	"strings"
	"unicode"
)

var ErrEmptyAgentID = errors.New("agent id is empty")

// NormalizeAgentID returns the canonical form used before hashing an AgentID.
func NormalizeAgentID(agentID string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(agentID))
	if normalized == "" {
		return "", ErrEmptyAgentID
	}

	for _, r := range normalized {
		if unicode.IsSpace(r) {
			return "", errors.New("agent id contains whitespace")
		}
	}

	return normalized, nil
}

func AgentIDHash(agentID string) ([16]byte, error) {
	normalized, err := NormalizeAgentID(agentID)
	if err != nil {
		return [16]byte{}, err
	}

	return Hash128([]byte(normalized)), nil
}
