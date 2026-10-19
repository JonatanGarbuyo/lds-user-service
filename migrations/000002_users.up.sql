CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL,
    password_hash text NOT NULL,
    email_verified boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_email_not_blank CHECK (email <> ''),
    CONSTRAINT users_email_lowercase CHECK (email = lower(email)),
    CONSTRAINT users_password_hash_not_blank CHECK (password_hash <> ''),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'suspended', 'deletion_requested'))
);
