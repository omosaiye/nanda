package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	EventAgentRegistered = "agent.registered"
	EventResolveAllowed  = "resolve.allowed"
	EventResolveDenied   = "resolve.denied"
	EventTrustDenied     = "trust.denied"

	DecisionAllowed = "allowed"
	DecisionDenied  = "denied"
)

var (
	ErrInvalidEventInput = errors.New("invalid audit event input")
	ErrHashChainInvalid  = errors.New("audit hash chain invalid")
)

type Event struct {
	EventID      string          `json:"eventId"`
	EventType    string          `json:"eventType"`
	AgentID      string          `json:"agentId,omitempty"`
	AgentHash    string          `json:"agentHash,omitempty"`
	ActorHash    string          `json:"actorHash,omitempty"`
	Decision     string          `json:"decision"`
	Reason       string          `json:"reason,omitempty"`
	EventJSON    json.RawMessage `json:"eventJSON"`
	PreviousHash string          `json:"previousHash,omitempty"`
	EventHash    string          `json:"eventHash"`
	CreatedAt    time.Time       `json:"createdAt"`
}

type EventInput struct {
	EventType string          `json:"eventType"`
	AgentID   string          `json:"agentId,omitempty"`
	AgentHash string          `json:"agentHash,omitempty"`
	ActorHash string          `json:"actorHash,omitempty"`
	Decision  string          `json:"decision"`
	Reason    string          `json:"reason,omitempty"`
	EventJSON json.RawMessage `json:"eventJSON"`
}

type Store interface {
	Append(ctx context.Context, input EventInput) (Event, error)
	List(ctx context.Context) ([]Event, error)
	ListByAgent(ctx context.Context, agentID string) ([]Event, error)
	VerifyHashChain(ctx context.Context) error
}

func NewEvent(previousHash string, input EventInput, createdAt time.Time) (Event, error) {
	if err := validateInput(input); err != nil {
		return Event{}, err
	}
	eventJSON, err := CanonicalJSON(input.EventJSON)
	if err != nil {
		return Event{}, err
	}
	eventID, err := newEventID()
	if err != nil {
		return Event{}, err
	}

	event := Event{
		EventID:      eventID,
		EventType:    input.EventType,
		AgentID:      input.AgentID,
		AgentHash:    input.AgentHash,
		ActorHash:    input.ActorHash,
		Decision:     input.Decision,
		Reason:       input.Reason,
		EventJSON:    eventJSON,
		PreviousHash: previousHash,
		CreatedAt:    createdAt.UTC(),
	}
	event.EventHash, err = HashEvent(previousHash, event)
	if err != nil {
		return Event{}, err
	}

	return event, nil
}

func HashEvent(previousHash string, event Event) (string, error) {
	payload, err := canonicalPayload(event)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(previousHash), payload...))
	return hex.EncodeToString(sum[:]), nil
}

func CanonicalJSON(data json.RawMessage) (json.RawMessage, error) {
	if len(data) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("%w: eventJSON must be valid JSON: %v", ErrInvalidEventInput, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return nil, fmt.Errorf("%w: eventJSON must contain one JSON value", ErrInvalidEventInput)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: eventJSON must be valid JSON: %v", ErrInvalidEventInput, err)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("canonicalize audit event JSON: %w", err)
	}
	return json.RawMessage(canonical), nil
}

func Payload(data any) (json.RawMessage, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(payload)
}

func validateInput(input EventInput) error {
	switch input.EventType {
	case EventAgentRegistered, EventResolveAllowed, EventResolveDenied, EventTrustDenied:
	default:
		return fmt.Errorf("%w: unsupported event type %q", ErrInvalidEventInput, input.EventType)
	}
	switch input.Decision {
	case DecisionAllowed, DecisionDenied:
	default:
		return fmt.Errorf("%w: unsupported decision %q", ErrInvalidEventInput, input.Decision)
	}
	if input.EventJSON != nil && !json.Valid(input.EventJSON) {
		return fmt.Errorf("%w: eventJSON must be valid JSON", ErrInvalidEventInput)
	}
	return nil
}

type eventHashPayload struct {
	EventID   string          `json:"eventId"`
	EventType string          `json:"eventType"`
	AgentID   string          `json:"agentId,omitempty"`
	AgentHash string          `json:"agentHash,omitempty"`
	ActorHash string          `json:"actorHash,omitempty"`
	Decision  string          `json:"decision"`
	Reason    string          `json:"reason,omitempty"`
	EventJSON json.RawMessage `json:"eventJSON"`
	CreatedAt time.Time       `json:"createdAt"`
}

func canonicalPayload(event Event) ([]byte, error) {
	eventJSON, err := CanonicalJSON(event.EventJSON)
	if err != nil {
		return nil, err
	}
	return json.Marshal(eventHashPayload{
		EventID:   event.EventID,
		EventType: event.EventType,
		AgentID:   event.AgentID,
		AgentHash: event.AgentHash,
		ActorHash: event.ActorHash,
		Decision:  event.Decision,
		Reason:    event.Reason,
		EventJSON: eventJSON,
		CreatedAt: event.CreatedAt.UTC(),
	})
}

func newEventID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate audit event id: %w", err)
	}
	return hex.EncodeToString(bytes[:]), nil
}
