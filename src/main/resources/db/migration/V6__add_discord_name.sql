ALTER TABLE users ADD COLUMN discord_name varchar(32);

-- Rollback:
-- ALTER TABLE users DROP COLUMN discord_name;
-- DELETE FROM flyway_schema_history WHERE version = '6';
