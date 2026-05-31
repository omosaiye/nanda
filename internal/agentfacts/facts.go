package agentfacts

import "time"

const SchemaVersionV0 = "nanda.agentfacts.v0"

type AgentFacts struct {
	SchemaVersion string     `json:"schemaVersion"`
	ID            string     `json:"id"`
	Controller    string     `json:"controller"`
	ValidFrom     time.Time  `json:"validFrom"`
	ValidUntil    time.Time  `json:"validUntil"`
	Capabilities  []string   `json:"capabilities"`
	Endpoints     []Endpoint `json:"endpoints"`
}
