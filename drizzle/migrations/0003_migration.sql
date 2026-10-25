CREATE TABLE IF NOT EXISTS public.access_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key_hash text NOT NULL UNIQUE CHECK (length(key_hash) = 64),
  claimed_device_hash text CHECK (claimed_device_hash IS NULL OR length(claimed_device_hash) = 64),
  claimed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL PRIVILEGES ON TABLE public.access_keys FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.access_keys TO service_role;
ALTER TABLE public.access_keys ENABLE ROW LEVEL SECURITY;