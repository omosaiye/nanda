package agentfacts

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
)

var ErrValidation = errors.New("agent facts validation failed")

const (
	SchemaVersionV0 = "nanda.agentfacts.v0"

	EndpointTypeStatic           = "static"
	EndpointTypeRotating         = "rotating"
	EndpointTypeAdaptiveResolver = "adaptiveResolver"
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

type ValidationError struct {
	Field string
	Err   error
}

func (e ValidationError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%v: %v", ErrValidation, e.Err)
	}
	return fmt.Sprintf("%v: %s: %v", ErrValidation, e.Field, e.Err)
}

func (e ValidationError) Unwrap() error {
	return e.Err
}

func (e ValidationError) Is(target error) bool {
	return target == ErrValidation
}

type AgentFacts struct {
	SchemaVersion string     `json:"schemaVersion"`
	ID            string     `json:"id"`
	Controller    string     `json:"controller"`
	ValidFrom     time.Time  `json:"validFrom"`
	ValidUntil    time.Time  `json:"validUntil"`
	Capabilities  []string   `json:"capabilities"`
	Endpoints     []Endpoint `json:"endpoints"`
}

type Endpoint struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	URL        string `json:"url"`
	Protocol   string `json:"protocol"`
	TTLSeconds uint16 `json:"ttlSeconds"`
}

func Validate(facts AgentFacts, requestedAgentID string, requiredCapability string, now time.Time) error {
	if facts.SchemaVersion != SchemaVersionV0 {
		return ValidationError{Field: "schemaVersion", Err: ErrInvalidSchemaVersion}
	}
	normalizedRequestedAgentID, err := agentaddr.NormalizeAgentID(requestedAgentID)
	if err != nil {
		return ValidationError{Field: "id", Err: err}
	}
	normalizedFactsAgentID, err := agentaddr.NormalizeAgentID(facts.ID)
	if err != nil {
		return ValidationError{Field: "id", Err: err}
	}
	if normalizedFactsAgentID != normalizedRequestedAgentID {
		return ValidationError{Field: "id", Err: ErrAgentIDMismatch}
	}
	if strings.TrimSpace(facts.Controller) == "" {
		return ValidationError{Field: "controller", Err: ErrEmptyController}
	}
	if facts.ValidFrom.After(now) {
		return ValidationError{Field: "validFrom", Err: ErrNotYetValid}
	}
	if !facts.ValidUntil.After(now) {
		return ValidationError{Field: "validUntil", Err: ErrExpired}
	}
	if requiredCapability != "" && !slices.Contains(facts.Capabilities, requiredCapability) {
		return ValidationError{Field: "capabilities", Err: ErrMissingRequiredCapability}
	}
	if len(facts.Endpoints) == 0 {
		return ValidationError{Field: "endpoints", Err: ErrNoEndpoints}
	}

	for i, endpoint := range facts.Endpoints {
		if err := validateEndpoint(endpoint); err != nil {
			return ValidationError{Field: fmt.Sprintf("endpoints[%d]", i), Err: err}
		}
	}

	return nil
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
