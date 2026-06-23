ALTER TABLE route_policies
  ADD COLUMN IF NOT EXISTS rate_strategy TEXT NOT NULL DEFAULT 'fixed_window';
