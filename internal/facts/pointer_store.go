package facts

import "context"

type PointerStore interface {
	PutFactsPointer(ctx context.Context, pointer FactsPointer) error
	ResolveFactsPointer(ctx context.Context, factsPtrHash128 [16]byte) (FactsPointer, error)
}
