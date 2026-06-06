CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_credentials (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    password_algo TEXT NOT NULL,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO users (id, first_name, last_name, email, username)
VALUES (
    '11111111-2222-3333-4444-555555555555',
    'Test',
    'User',
    'testuser@example.com',
    'testuser'
)
ON CONFLICT (username) DO NOTHING;

INSERT INTO user_credentials (user_id, password_hash, password_algo)
VALUES (
    '11111111-2222-3333-4444-555555555555',
    '$argon2id$v=19$m=65536,t=3,p=2$and0c2VlZHN0YXRpY3NhbHQ$tJ1IZjpbKmSb1z+LnhKeo7I6bQXXht+r5czuAZCg3y0',
    'argon2id'
)
ON CONFLICT (user_id) DO NOTHING;
