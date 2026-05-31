package index

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/solai/nanda/internal/agentaddr"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, errors.New("postgres index store requires a database")
	}

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Put(ctx context.Context, agentID string, record agentaddr.AgentAddr120) error {
	payload := record.Payload()
	agentHash, err := agentaddr.AgentIDHash(agentID)
	if err != nil {
		return err
	}
	if agentHash != payload.AgentIDHash {
		return errors.New("agent id hash does not match record payload")
	}
	if _, err := agentaddr.Decode(record.Encode()); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres index transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	current, err := getCurrentForUpdate(ctx, tx, agentHash)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("get current agent address record for update: %w", err)
	}
	if err == nil {
		switch {
		case payload.Sequence < current.Sequence:
			return ErrStaleSequence
		case payload.Sequence == current.Sequence:
			if bytes.Equal(record.Encode(), current.Record.Encode()) {
				return tx.Commit()
			}
			return ErrSequenceConflict
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO agent_addr_history (
			agent_hash,
			agent_id,
			record_bytes,
			sequence,
			ttl_seconds,
			created_at,
			updated_at
		)
		SELECT
			agent_hash,
			agent_id,
			record_bytes,
			sequence,
			ttl_seconds,
			created_at,
			updated_at
		FROM agent_addr_records
		WHERE agent_hash = $1
	`, agentHash[:]); err != nil {
		return fmt.Errorf("archive current agent address record: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO agent_addr_records (
			agent_hash,
			agent_id,
			record_bytes,
			sequence,
			ttl_seconds
		)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (agent_hash) DO UPDATE SET
			agent_id = EXCLUDED.agent_id,
			record_bytes = EXCLUDED.record_bytes,
			sequence = EXCLUDED.sequence,
			ttl_seconds = EXCLUDED.ttl_seconds,
			updated_at = now()
	`, agentHash[:], agentID, record.Encode(), payload.Sequence, payload.TTLSeconds); err != nil {
		return fmt.Errorf("upsert current agent address record: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres index transaction: %w", err)
	}

	return nil
}

func getCurrentForUpdate(ctx context.Context, tx *sql.Tx, agentHash [16]byte) (IndexedRecord, error) {
	row := tx.QueryRowContext(ctx, `
		SELECT
			agent_hash,
			agent_id,
			record_bytes,
			sequence,
			ttl_seconds,
			created_at,
			updated_at
		FROM agent_addr_records
		WHERE agent_hash = $1
		FOR UPDATE
	`, agentHash[:])

	record, err := scanIndexedRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return IndexedRecord{}, ErrNotFound
	}
	if err != nil {
		return IndexedRecord{}, err
	}
	return record, nil
}

func (s *PostgresStore) Get(ctx context.Context, agentHash [16]byte) (IndexedRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT
			agent_hash,
			agent_id,
			record_bytes,
			sequence,
			ttl_seconds,
			created_at,
			updated_at
		FROM agent_addr_records
		WHERE agent_hash = $1
	`, agentHash[:])

	record, err := scanIndexedRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return IndexedRecord{}, ErrNotFound
	}
	if err != nil {
		return IndexedRecord{}, fmt.Errorf("get current agent address record: %w", err)
	}

	return record, nil
}

func (s *PostgresStore) History(ctx context.Context, agentHash [16]byte) ([]IndexedRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			agent_hash,
			agent_id,
			record_bytes,
			sequence,
			ttl_seconds,
			created_at,
			updated_at
		FROM agent_addr_history
		WHERE agent_hash = $1
		ORDER BY archived_at ASC, id ASC
	`, agentHash[:])
	if err != nil {
		return nil, fmt.Errorf("query agent address history: %w", err)
	}
	defer rows.Close()

	var records []IndexedRecord
	for rows.Next() {
		record, err := scanIndexedRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent address history: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read agent address history: %w", err)
	}

	return records, nil
}

type indexedRecordScanner interface {
	Scan(dest ...any) error
}

func scanIndexedRecord(scanner indexedRecordScanner) (IndexedRecord, error) {
	var record IndexedRecord
	var agentHash []byte
	var recordBytes []byte

	if err := scanner.Scan(
		&agentHash,
		&record.AgentID,
		&recordBytes,
		&record.Sequence,
		&record.TTLSeconds,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return IndexedRecord{}, err
	}
	if len(agentHash) != 16 {
		return IndexedRecord{}, fmt.Errorf("stored agent hash length = %d, want 16", len(agentHash))
	}
	copy(record.AgentHash[:], agentHash)

	decoded, err := agentaddr.Decode(recordBytes)
	if err != nil {
		return IndexedRecord{}, err
	}
	record.Record = decoded

	return record, nil
}
