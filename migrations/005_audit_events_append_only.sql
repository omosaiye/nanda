CREATE OR REPLACE FUNCTION prevent_audit_events_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_events_mutation();
