package index

import (
	"context"
	"errors"
	"time"

	"github.com/solai/nanda/internal/agentaddr"
)

var (
	ErrNotFound         = errors.New("agent address record not found")
	ErrStaleSequence    = errors.New("agent address record sequence is stale")
	ErrSequenceConflict = errors.New("agent address record sequence conflicts with current record")
)

type IndexedRecord struct {
	AgentHash  [16]byte
	AgentID    string
	Record     agentaddr.AgentAddr120
	Sequence   uint32
	TTLSeconds uint16
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type LeanIndexStore interface {
	Put(ctx context.Context, agentID string, record agentaddr.AgentAddr120) error
	Get(ctx context.Context, agentHash [16]byte) (IndexedRecord, error)
	History(ctx context.Context, agentHash [16]byte) ([]IndexedRecord, error)
}
