CREATE TABLE IF NOT EXISTS agent_addr_records (
	agent_hash bytea PRIMARY KEY CHECK (octet_length(agent_hash) = 16),
	agent_id text NOT NULL,
	record_bytes bytea NOT NULL CHECK (octet_length(record_bytes) = 120),
	sequence bigint NOT NULL CHECK (sequence >= 0),
	ttl_seconds integer NOT NULL CHECK (ttl_seconds > 0),
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_addr_history (
	id bigserial PRIMARY KEY,
	agent_hash bytea NOT NULL CHECK (octet_length(agent_hash) = 16),
	agent_id text NOT NULL,
	record_bytes bytea NOT NULL CHECK (octet_length(record_bytes) = 120),
	sequence bigint NOT NULL CHECK (sequence >= 0),
	ttl_seconds integer NOT NULL CHECK (ttl_seconds > 0),
	created_at timestamptz NOT NULL,
	updated_at timestamptz NOT NULL,
	archived_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS agent_addr_history_agent_hash_idx
	ON agent_addr_history (agent_hash, archived_at, id);
