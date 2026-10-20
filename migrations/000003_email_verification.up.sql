CREATE TABLE email_verification_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash text NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    invalidated_at timestamptz,
    CONSTRAINT email_verification_code_hash_not_blank CHECK (code_hash <> ''),
    CONSTRAINT email_verification_attempts_non_negative CHECK (attempts >= 0),
    CONSTRAINT email_verification_expiry_after_creation CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX email_verification_one_active_per_user
    ON email_verification_challenges (user_id)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

CREATE INDEX email_verification_user_created_at
    ON email_verification_challenges (user_id, created_at DESC);
