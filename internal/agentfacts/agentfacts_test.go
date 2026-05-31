package agentfacts

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestValidateValidFactsPasses(t *testing.T) {
	facts := validFacts()

	if err := Validate(facts, " Agent.Example ", "chat", testNow()); err != nil {
		t.Fatalf("Validate valid facts: %v", err)
	}
}

func TestAgentFactsJSONShapeUsesFlatEndpoints(t *testing.T) {
	facts := validFacts()

	factsBytes, err := json.Marshal(facts)
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}

	var decoded struct {
		SchemaVersion string     `json:"schemaVersion"`
		ID            string     `json:"id"`
		Controller    string     `json:"controller"`
		ValidFrom     time.Time  `json:"validFrom"`
		ValidUntil    time.Time  `json:"validUntil"`
		Capabilities  []string   `json:"capabilities"`
		Endpoints     []Endpoint `json:"endpoints"`
		AgentID       string     `json:"agentId"`
	}
	if err := json.Unmarshal(factsBytes, &decoded); err != nil {
		t.Fatalf("unmarshal facts: %v", err)
	}
	if decoded.SchemaVersion != SchemaVersionV0 {
		t.Fatalf("schemaVersion = %q, want %q", decoded.SchemaVersion, SchemaVersionV0)
	}
	if decoded.ID != "agent.example" {
		t.Fatalf("id = %q, want agent.example", decoded.ID)
	}
	if decoded.AgentID != "" {
		t.Fatalf("agentId = %q, want empty", decoded.AgentID)
	}
	if len(decoded.Endpoints) != 1 {
		t.Fatalf("endpoints len = %d, want 1", len(decoded.Endpoints))
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(factsBytes, &raw); err != nil {
		t.Fatalf("unmarshal raw facts: %v", err)
	}
	for _, disallowed := range []string{"static", "rotating", "adaptiveResolver"} {
		if _, ok := raw[disallowed]; ok {
			t.Fatalf("top-level %q key is not part of AgentFacts v0", disallowed)
		}
	}
}

func TestValidateWrongSchemaVersionFails(t *testing.T) {
	facts := validFacts()
	facts.SchemaVersion = "nanda.agentfacts.v1"

	err := Validate(facts, "agent.example", "chat", testNow())
	if !errors.Is(err, ErrInvalidSchemaVersion) {
		t.Fatalf("Validate wrong schema error = %v, want %v", err, ErrInvalidSchemaVersion)
	}
}

func TestValidateAgentIDMismatchFails(t *testing.T) {
	facts := validFacts()

	err := Validate(facts, "other.example", "chat", testNow())
	if !errors.Is(err, ErrAgentIDMismatch) {
		t.Fatalf("Validate id mismatch error = %v, want %v", err, ErrAgentIDMismatch)
	}
}

func TestValidateEmptyControllerFails(t *testing.T) {
	tests := []struct {
		name       string
		controller string
	}{
		{name: "empty", controller: ""},
		{name: "whitespace", controller: " \t\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facts := validFacts()
			facts.Controller = tt.controller

			err := Validate(facts, "agent.example", "chat", testNow())
			if !errors.Is(err, ErrEmptyController) {
				t.Fatalf("Validate empty controller error = %v, want %v", err, ErrEmptyController)
			}
		})
	}
}

func TestValidateNotYetValidFactsFails(t *testing.T) {
	facts := validFacts()
	facts.ValidFrom = testNow().Add(time.Second)

	err := Validate(facts, "agent.example", "chat", testNow())
	if !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("Validate not yet valid facts error = %v, want %v", err, ErrNotYetValid)
	}
}

func TestValidateExpiredFactsFails(t *testing.T) {
	facts := validFacts()
	facts.ValidUntil = testNow()

	err := Validate(facts, "agent.example", "chat", testNow())
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Validate expired facts error = %v, want %v", err, ErrExpired)
	}
}

func TestValidateMissingRequiredCapabilityFails(t *testing.T) {
	facts := validFacts()

	err := Validate(facts, "agent.example", "payments", testNow())
	if !errors.Is(err, ErrMissingRequiredCapability) {
		t.Fatalf("Validate missing capability error = %v, want %v", err, ErrMissingRequiredCapability)
	}
}

func TestValidateNoEndpointsFails(t *testing.T) {
	facts := validFacts()
	facts.Endpoints = nil

	err := Validate(facts, "agent.example", "chat", testNow())
	if !errors.Is(err, ErrNoEndpoints) {
		t.Fatalf("Validate no endpoints error = %v, want %v", err, ErrNoEndpoints)
	}
}

func TestValidateEmptyEndpointIDFails(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{name: "empty", id: ""},
		{name: "whitespace", id: " \t\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facts := validFacts()
			facts.Endpoints[0].ID = tt.id

			err := Validate(facts, "agent.example", "chat", testNow())
			if !errors.Is(err, ErrEmptyEndpointID) {
				t.Fatalf("Validate empty endpoint id error = %v, want %v", err, ErrEmptyEndpointID)
			}
		})
	}
}

func TestValidateUnsupportedEndpointTypeFails(t *testing.T) {
	facts := validFacts()
	facts.Endpoints[0].Type = "future"

	err := Validate(facts, "agent.example", "chat", testNow())
	if !errors.Is(err, ErrUnsupportedEndpointType) {
		t.Fatalf("Validate unsupported endpoint type error = %v, want %v", err, ErrUnsupportedEndpointType)
	}
}

func TestValidateHTTPEndpointFails(t *testing.T) {
	facts := validFacts()
	facts.Endpoints[0].Protocol = "http"
	facts.Endpoints[0].URL = "http://agent.example/endpoint"

	err := Validate(facts, "agent.example", "chat", testNow())
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("Validate HTTP endpoint error = %v, want %v", err, ErrUnsupportedProtocol)
	}
}

func TestValidateInvalidEndpointURLFails(t *testing.T) {
	facts := validFacts()
	facts.Endpoints[0].URL = "://agent.example/endpoint"

	err := Validate(facts, "agent.example", "chat", testNow())
	if !errors.Is(err, ErrInvalidEndpointURL) {
		t.Fatalf("Validate invalid endpoint url error = %v, want %v", err, ErrInvalidEndpointURL)
	}
}

func TestValidateZeroEndpointTTLFails(t *testing.T) {
	facts := validFacts()
	facts.Endpoints[0].TTLSeconds = 0

	err := Validate(facts, "agent.example", "chat", testNow())
	if !errors.Is(err, ErrZeroEndpointTTL) {
		t.Fatalf("Validate zero endpoint ttl error = %v, want %v", err, ErrZeroEndpointTTL)
	}
}

func validFacts() AgentFacts {
	now := testNow()
	return AgentFacts{
		SchemaVersion: SchemaVersionV0,
		ID:            "agent.example",
		Controller:    "did:example:controller",
		ValidFrom:     now.Add(-time.Minute),
		ValidUntil:    now.Add(time.Hour),
		Capabilities:  []string{"chat", "status"},
		Endpoints: []Endpoint{
			{
				ID:         "primary",
				Type:       EndpointTypeStatic,
				URL:        "https://agent.example/endpoint",
				Protocol:   "https",
				TTLSeconds: 60,
			},
		},
	}
}

func testNow() time.Time {
	return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
}
