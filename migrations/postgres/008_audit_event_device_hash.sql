ALTER TABLE audit_events
  ADD COLUMN IF NOT EXISTS device_id_hash TEXT;
