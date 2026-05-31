package revocation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, errors.New("postgres revocation store requires a database")
	}
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) SetStatus(ctx context.Context, issuer string, credentialID string, status string, reason string) error {
	if err := validateKey(issuer, credentialID); err != nil {
		return err
	}
	if err := validateStatus(status); err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO credential_revocations (
			issuer,
			credential_id,
			status,
			reason,
			updated_at
		)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (issuer, credential_id) DO UPDATE SET
			status = EXCLUDED.status,
			reason = EXCLUDED.reason,
			updated_at = now()
	`, issuer, credentialID, status, nullString(reason)); err != nil {
		return fmt.Errorf("upsert credential revocation: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetStatus(ctx context.Context, issuer string, credentialID string) (Record, error) {
	if err := validateKey(issuer, credentialID); err != nil {
		return Record{}, err
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT issuer, credential_id, status, reason, updated_at
		FROM credential_revocations
		WHERE issuer = $1 AND credential_id = $2
	`, issuer, credentialID)

	record, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("get credential revocation: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) IsRevoked(ctx context.Context, issuer string, credentialID string) (bool, error) {
	record, err := s.GetStatus(ctx, issuer, credentialID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return record.Status == StatusRevoked, nil
}

type recordScanner interface {
	Scan(dest ...any) error
}

func scanRecord(scanner recordScanner) (Record, error) {
	var record Record
	var reason sql.NullString
	if err := scanner.Scan(
		&record.Issuer,
		&record.CredentialID,
		&record.Status,
		&reason,
		&record.UpdatedAt,
	); err != nil {
		return Record{}, err
	}
	record.Reason = reason.String
	return record, nil
}

func nullString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}
