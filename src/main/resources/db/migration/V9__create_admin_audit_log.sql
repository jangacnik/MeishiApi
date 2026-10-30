CREATE TABLE admin_audit_log (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id    uuid,
    action      varchar(32) NOT NULL,
    target_id   uuid NOT NULL,
    details     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX admin_audit_log_target_created_idx ON admin_audit_log (target_id, created_at);
