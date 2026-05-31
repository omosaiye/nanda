package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, errors.New("postgres audit store requires a database")
	}
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Append(ctx context.Context, input EventInput) (Event, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Event{}, fmt.Errorf("begin postgres audit transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `LOCK TABLE audit_events IN EXCLUSIVE MODE`); err != nil {
		return Event{}, fmt.Errorf("lock postgres audit events: %w", err)
	}

	previousHash := ""
	if err := tx.QueryRowContext(ctx, `
		SELECT event_hash
		FROM audit_events
		ORDER BY id DESC
		LIMIT 1
	`).Scan(&previousHash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Event{}, fmt.Errorf("get previous audit event hash: %w", err)
	}

	event, err := NewEvent(previousHash, input, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return Event{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
			event_id,
			event_type,
			agent_id,
			agent_hash,
			actor_hash,
			decision,
			reason,
			event_json,
			previous_hash,
			event_hash,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11)
	`, event.EventID, event.EventType, nullString(event.AgentID), nullString(event.AgentHash), nullString(event.ActorHash), event.Decision, nullString(event.Reason), []byte(event.EventJSON), nullString(event.PreviousHash), event.EventHash, event.CreatedAt); err != nil {
		return Event{}, fmt.Errorf("insert audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Event{}, fmt.Errorf("commit postgres audit transaction: %w", err)
	}

	return event, nil
}

func (s *PostgresStore) List(ctx context.Context) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, event_type, agent_id, agent_hash, actor_hash, decision, reason, event_json, previous_hash, event_hash, created_at
		FROM audit_events
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

func (s *PostgresStore) ListByAgent(ctx context.Context, agentID string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, event_type, agent_id, agent_hash, actor_hash, decision, reason, event_json, previous_hash, event_hash, created_at
		FROM audit_events
		WHERE agent_id = $1
		ORDER BY id ASC
	`, agentID)
	if err != nil {
		return nil, fmt.Errorf("query audit events by agent: %w", err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

func (s *PostgresStore) Query(ctx context.Context, query Query) (ListResult, error) {
	query, err := NormalizeQuery(query)
	if err != nil {
		return ListResult{}, err
	}

	var args []any
	var filters []string
	addFilter := func(column string, value string) {
		args = append(args, value)
		filters = append(filters, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if query.AgentID != "" {
		addFilter("agent_id", query.AgentID)
	}
	if query.EventType != "" {
		addFilter("event_type", query.EventType)
	}
	if query.Decision != "" {
		addFilter("decision", query.Decision)
	}

	where := ""
	if len(filters) > 0 {
		where = "WHERE " + strings.Join(filters, " AND ")
	}
	args = append(args, query.Limit)
	limitParam := len(args)
	args = append(args, query.Offset)
	offsetParam := len(args)

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT event_id, event_type, agent_id, agent_hash, actor_hash, decision, reason, event_json, previous_hash, event_hash, created_at
		FROM audit_events
		%s
		ORDER BY id ASC
		LIMIT $%d OFFSET $%d
	`, where, limitParam, offsetParam), args...)
	if err != nil {
		return ListResult{}, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	events, err := scanEvents(rows)
	if err != nil {
		return ListResult{}, err
	}
	return ListResult{
		Items:  events,
		Limit:  query.Limit,
		Offset: query.Offset,
		Count:  len(events),
	}, nil
}

func (s *PostgresStore) VerifyHashChain(ctx context.Context) error {
	events, err := s.List(ctx)
	if err != nil {
		return err
	}
	return verifyEvents(events)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	var events []Event
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit events: %w", err)
	}
	return events, nil
}

type eventScanner interface {
	Scan(dest ...any) error
}

func scanEvent(scanner eventScanner) (Event, error) {
	var event Event
	var agentID sql.NullString
	var agentHash sql.NullString
	var actorHash sql.NullString
	var reason sql.NullString
	var previousHash sql.NullString
	var eventJSON []byte
	if err := scanner.Scan(
		&event.EventID,
		&event.EventType,
		&agentID,
		&agentHash,
		&actorHash,
		&event.Decision,
		&reason,
		&eventJSON,
		&previousHash,
		&event.EventHash,
		&event.CreatedAt,
	); err != nil {
		return Event{}, fmt.Errorf("scan audit event: %w", err)
	}
	event.AgentID = agentID.String
	event.AgentHash = agentHash.String
	event.ActorHash = actorHash.String
	event.Reason = reason.String
	event.PreviousHash = previousHash.String
	canonicalEventJSON, err := CanonicalJSON(eventJSON)
	if err != nil {
		return Event{}, err
	}
	event.EventJSON = append([]byte(nil), canonicalEventJSON...)
	return event, nil
}

func nullString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}
