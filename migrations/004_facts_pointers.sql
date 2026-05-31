CREATE TABLE IF NOT EXISTS facts_pointers (
	facts_hash text PRIMARY KEY,
	pointer_scheme text NOT NULL,
	pointer_path text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now()
);
