package facts

import "github.com/solai/nanda/internal/agentaddr"

func PointerHash128(pointer FactsPointer) [16]byte {
	return agentaddr.Hash128([]byte(pointer.String()))
}
