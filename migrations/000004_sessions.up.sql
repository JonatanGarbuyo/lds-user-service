CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind text NOT NULL,
    secret_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_activity_at timestamptz NOT NULL DEFAULT now(),
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT sessions_kind_check CHECK (kind IN ('web', 'bearer')),
    CONSTRAINT sessions_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT sessions_secret_hash_length CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT sessions_idle_expiry_after_activity CHECK (idle_expires_at > last_activity_at),
    CONSTRAINT sessions_absolute_expiry_after_creation CHECK (absolute_expires_at > created_at),
    CONSTRAINT sessions_idle_within_absolute CHECK (idle_expires_at <= absolute_expires_at)
);

CREATE INDEX sessions_user_created_at
    ON sessions (user_id, created_at DESC);

CREATE INDEX sessions_user_active
    ON sessions (user_id)
    WHERE revoked_at IS NULL;
