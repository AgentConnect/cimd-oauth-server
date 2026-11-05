CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS admission_policies (
  namespace text NOT NULL, resource text NOT NULL, enabled boolean NOT NULL DEFAULT false,
  generation bigint NOT NULL DEFAULT 1, scopes text[] NOT NULL, ttl integer NOT NULL CHECK(ttl BETWEEN 1 AND 3600),
  max_new_clients_hour integer NOT NULL CHECK(max_new_clients_hour > 0), max_requests_client_minute integer NOT NULL CHECK(max_requests_client_minute > 0),
  max_requests_minute integer NOT NULL CHECK(max_requests_minute > 0), custody_condition text NOT NULL CHECK(length(custody_condition) > 0),
  PRIMARY KEY(namespace,resource)
);
CREATE TABLE IF NOT EXISTS request_limits (
  namespace text PRIMARY KEY, global_minute integer NOT NULL CHECK(global_minute>0),
  origin_minute integer NOT NULL CHECK(origin_minute>0), client_minute integer NOT NULL CHECK(client_minute>0),
  source_minute integer NOT NULL CHECK(source_minute>0)
);
CREATE TABLE IF NOT EXISTS clients (
  namespace text NOT NULL, client_id text NOT NULL, subject uuid NOT NULL UNIQUE,
  enabled boolean NOT NULL DEFAULT true, generation bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(namespace,client_id)
);
CREATE TABLE IF NOT EXISTS client_blocks (
  namespace text NOT NULL, client_id text NOT NULL, blocked boolean NOT NULL, generation bigint NOT NULL DEFAULT 1,
  PRIMARY KEY(namespace,client_id)
);
CREATE TABLE IF NOT EXISTS metadata_snapshots (
  namespace text NOT NULL, client_id text NOT NULL, digest text NOT NULL, jwks_digest text NOT NULL, thumbprint text NOT NULL,
  expires_at timestamptz NOT NULL, PRIMARY KEY(namespace,client_id,digest,thumbprint)
);
CREATE TABLE IF NOT EXISTS assertion_replays (
  namespace text NOT NULL, client_id text NOT NULL, jti_digest text NOT NULL, expires_at timestamptz NOT NULL,
  PRIMARY KEY(namespace,client_id,jti_digest)
);
CREATE INDEX IF NOT EXISTS assertion_replays_expiry ON assertion_replays(expires_at);
CREATE TABLE IF NOT EXISTS machine_grants (
  id uuid PRIMARY KEY, namespace text NOT NULL, grant_key text NOT NULL, client_id text NOT NULL, resource text NOT NULL, scopes text[] NOT NULL,
  enabled boolean NOT NULL DEFAULT true, generation bigint NOT NULL DEFAULT 1, policy_generation bigint NOT NULL,
  UNIQUE(namespace,grant_key), FOREIGN KEY(namespace,client_id) REFERENCES clients(namespace,client_id)
);
CREATE TABLE IF NOT EXISTS access_tokens (
  digest text PRIMARY KEY, namespace text NOT NULL, client_id text NOT NULL, grant_id uuid NOT NULL REFERENCES machine_grants(id),
  resource text NOT NULL, scopes text[] NOT NULL, issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
  revoked_at timestamptz, client_generation bigint NOT NULL, grant_generation bigint NOT NULL, policy_generation bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS access_tokens_expiry ON access_tokens(expires_at);
CREATE TABLE IF NOT EXISTS resource_servers (
  namespace text NOT NULL, id text NOT NULL, secret_digest text NOT NULL, resources text[] NOT NULL, enabled boolean NOT NULL DEFAULT true,
  PRIMARY KEY(namespace,id)
);
CREATE TABLE IF NOT EXISTS rate_buckets (
  namespace text NOT NULL, bucket text NOT NULL, window_start bigint NOT NULL, expires_at timestamptz NOT NULL, count integer NOT NULL,
  PRIMARY KEY(namespace,bucket,window_start)
);
CREATE TABLE IF NOT EXISTS audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, namespace text NOT NULL, client_ref text NOT NULL,
  category text NOT NULL, policy_generation bigint, occurred_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO schema_migrations(version) VALUES(1) ON CONFLICT DO NOTHING;
