CREATE TABLE oauth_authorization_codes (
    code_hash           varchar(43) PRIMARY KEY,
    client_id           varchar(64) NOT NULL,
    redirect_uri        text NOT NULL,
    user_id             uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_challenge      varchar(43) NOT NULL,
    session_expires_at  timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL
);
