CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    nickname        varchar(64) UNIQUE,
    password_hash   varchar NOT NULL DEFAULT '',
    role            varchar(16) NOT NULL DEFAULT 'USER',
    activation_key  uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    activated_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
