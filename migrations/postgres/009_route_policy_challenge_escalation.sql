ALTER TABLE route_policies
  ADD COLUMN IF NOT EXISTS challenge_escalation TEXT NOT NULL DEFAULT '';
