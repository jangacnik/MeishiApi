-- Fails loudly if two nicknames collide case-insensitively. Pre-flight (run before deploy):
-- SELECT lower(nickname), count(*), array_agg(id) FROM users GROUP BY 1 HAVING count(*) > 1;
CREATE UNIQUE INDEX users_nickname_lower_key ON users (lower(nickname));

ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('USER', 'ADMIN')) NOT VALID;
ALTER TABLE users ADD CONSTRAINT users_status_check CHECK (status IN ('ACTIVE', 'FROZEN')) NOT VALID;
ALTER TABLE users VALIDATE CONSTRAINT users_role_check;
ALTER TABLE users VALIDATE CONSTRAINT users_status_check;

-- Rollback:
-- ALTER TABLE users DROP CONSTRAINT users_status_check;
-- ALTER TABLE users DROP CONSTRAINT users_role_check;
-- DROP INDEX users_nickname_lower_key;
-- DELETE FROM flyway_schema_history WHERE version = '7';
