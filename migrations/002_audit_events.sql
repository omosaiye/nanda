CREATE TABLE IF NOT EXISTS audit_events (
	id bigserial PRIMARY KEY,
	event_id text UNIQUE NOT NULL,
	event_type text NOT NULL,
	agent_id text,
	agent_hash text,
	actor_hash text,
	decision text,
	reason text,
	event_json jsonb NOT NULL,
	previous_hash text,
	event_hash text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_events_agent_id_idx
	ON audit_events (agent_id, id);
