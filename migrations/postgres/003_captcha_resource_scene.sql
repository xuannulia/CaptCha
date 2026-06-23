ALTER TABLE captcha_resources
  ADD COLUMN IF NOT EXISTS scene TEXT NOT NULL DEFAULT '';

DROP INDEX IF EXISTS idx_captcha_resources_lookup;

CREATE INDEX IF NOT EXISTS idx_captcha_resources_lookup
  ON captcha_resources (client_id, scene, captcha_type, resource_type, status);
