package facts

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

type PostgresPointerStore struct {
	db *sql.DB
}

func NewPostgresPointerStore(db *sql.DB) (*PostgresPointerStore, error) {
	if db == nil {
		return nil, errors.New("postgres facts pointer store requires a database")
	}
	return &PostgresPointerStore{db: db}, nil
}

func (s *PostgresPointerStore) PutFactsPointer(ctx context.Context, pointer FactsPointer) error {
	factsHash := PointerHash128(pointer)
	if pointer.Scheme == "" {
		return errors.New("facts pointer scheme is empty")
	}
	if pointer.Path == "" {
		return errors.New("facts pointer path is empty")
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO facts_pointers (
			facts_hash,
			pointer_scheme,
			pointer_path
		)
		VALUES ($1, $2, $3)
		ON CONFLICT (facts_hash) DO UPDATE SET
			pointer_scheme = EXCLUDED.pointer_scheme,
			pointer_path = EXCLUDED.pointer_path
	`, hex.EncodeToString(factsHash[:]), pointer.Scheme, pointer.Path); err != nil {
		return fmt.Errorf("upsert facts pointer: %w", err)
	}
	return nil
}

func (s *PostgresPointerStore) ResolveFactsPointer(ctx context.Context, factsPtrHash128 [16]byte) (FactsPointer, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT pointer_scheme, pointer_path
		FROM facts_pointers
		WHERE facts_hash = $1
	`, hex.EncodeToString(factsPtrHash128[:]))

	var pointer FactsPointer
	if err := row.Scan(&pointer.Scheme, &pointer.Path); errors.Is(err, sql.ErrNoRows) {
		return FactsPointer{}, ErrNotFound
	} else if err != nil {
		return FactsPointer{}, fmt.Errorf("resolve facts pointer: %w", err)
	}
	return pointer, nil
}
