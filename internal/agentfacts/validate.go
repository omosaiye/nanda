package agentfacts

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
)

var (
	ErrInvalidSchemaVersion      = errors.New("agent facts schemaVersion is unsupported")
	ErrAgentIDMismatch           = errors.New("agent facts id does not match requested agent id")
	ErrEmptyController           = errors.New("agent facts controller is empty")
	ErrNotYetValid               = errors.New("agent facts validFrom is in the future")
	ErrExpired                   = errors.New("agent facts validUntil is not in the future")
	ErrMissingRequiredCapability = errors.New("agent facts missing required capability")
	ErrNoEndpoints               = errors.New("agent facts must include at least one endpoint")
	ErrEmptyEndpointID           = errors.New("agent facts endpoint id is empty")
	ErrUnsupportedEndpointType   = errors.New("agent facts endpoint type is unsupported")
	ErrUnsupportedProtocol       = errors.New("agent facts endpoint protocol must be https")
	ErrInvalidEndpointURL        = errors.New("agent facts endpoint url is invalid")
	ErrZeroEndpointTTL           = errors.New("agent facts endpoint ttlSeconds must be greater than zero")
)

func Validate(facts AgentFacts, requestedAgentID string, requiredCapability string, now time.Time) error {
	if facts.SchemaVersion != SchemaVersionV0 {
		return ErrInvalidSchemaVersion
	}

	factsID, err := agentaddr.NormalizeAgentID(facts.ID)
	if err != nil {
		return fmt.Errorf("agent facts id: %w", err)
	}
	requestedID, err := agentaddr.NormalizeAgentID(requestedAgentID)
	if err != nil {
		return fmt.Errorf("requested agent id: %w", err)
	}
	if factsID != requestedID {
		return ErrAgentIDMismatch
	}

	if strings.TrimSpace(facts.Controller) == "" {
		return ErrEmptyController
	}
	if facts.ValidFrom.After(now) {
		return ErrNotYetValid
	}
	if !facts.ValidUntil.After(now) {
		return ErrExpired
	}
	if requiredCapability != "" && !hasCapability(facts.Capabilities, requiredCapability) {
		return ErrMissingRequiredCapability
	}
	if len(facts.Endpoints) == 0 {
		return ErrNoEndpoints
	}
	for i, endpoint := range facts.Endpoints {
		if err := validateEndpoint(endpoint); err != nil {
			return fmt.Errorf("endpoint %d: %w", i, err)
		}
	}

	return nil
}

func hasCapability(capabilities []string, requiredCapability string) bool {
	for _, capability := range capabilities {
		if capability == requiredCapability {
			return true
		}
	}
	return false
}

func validateEndpoint(endpoint Endpoint) error {
	if strings.TrimSpace(endpoint.ID) == "" {
		return ErrEmptyEndpointID
	}
	if !isSupportedEndpointType(endpoint.Type) {
		return ErrUnsupportedEndpointType
	}
	if endpoint.Protocol != "https" {
		return ErrUnsupportedProtocol
	}
	parsed, err := url.ParseRequestURI(endpoint.URL)
	if err != nil {
		return ErrInvalidEndpointURL
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return ErrInvalidEndpointURL
	}
	if endpoint.TTLSeconds == 0 {
		return ErrZeroEndpointTTL
	}

	return nil
}

func isSupportedEndpointType(endpointType string) bool {
	switch endpointType {
	case EndpointTypeStatic, EndpointTypeRotating, EndpointTypeAdaptiveResolver:
		return true
	default:
		return false
	}
}
