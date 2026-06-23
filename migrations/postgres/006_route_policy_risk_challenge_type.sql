ALTER TABLE route_policies
  ADD COLUMN IF NOT EXISTS risk_challenge_type TEXT NOT NULL DEFAULT '';
