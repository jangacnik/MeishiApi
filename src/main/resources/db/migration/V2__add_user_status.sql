ALTER TABLE users ADD COLUMN status varchar(16) NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE users ADD COLUMN failed_login_attempts int NOT NULL DEFAULT 0;
