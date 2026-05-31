package facts

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("agent facts not found")

type FactsPointer struct {
	Scheme string
	Path   string
}

func (p FactsPointer) String() string {
	if p.Scheme == "" {
		return p.Path
	}
	return p.Scheme + ":" + p.Path
}

type FactsStore interface {
	Put(ctx context.Context, facts []byte) (FactsPointer, error)
	Get(ctx context.Context, pointer FactsPointer) ([]byte, error)
}
