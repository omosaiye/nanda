CREATE TABLE IF NOT EXISTS credential_revocations (
	issuer text NOT NULL,
	credential_id text NOT NULL,
	status text NOT NULL CHECK (status IN ('active', 'revoked')),
	reason text,
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (issuer, credential_id)
);
