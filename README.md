# MeishiApi

Kotlin / Vert.x 5 REST API for Meishi user accounts, backed by PostgreSQL (Flyway migrations).
Full route reference: [`openapi.yaml`](openapi.yaml).

## Run locally

```sh
docker compose up -d postgres
set -a; source .env.example; set +a   # dev-only values, never reuse them elsewhere
./gradlew run
```

The API listens on `HTTP_PORT` (8080). Migrations run at startup. On first start an `ADMIN` user is
seeded from `ADMIN_NICKNAME` / `ADMIN_PASSWORD` if no admin exists.

## Tests

```sh
./gradlew test
```

Handler tests use an in-memory repository; there are no database-backed tests yet.

## Configuration (environment)

| Variable | Default | Notes |
|---|---|---|
| `JWT_SECRET` | required | at least 32 bytes, not the old dev value |
| `ADMIN_PASSWORD` | required | must not be `admin` |
| `DB_PASSWORD` | required | |
| `ADMIN_NICKNAME` | `admin` | |
| `HTTP_PORT` | `8080` | |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` | `localhost` / `5432` / `meishi` / `meishi` | |
| `DB_POOL_SIZE` / `DB_CONNECT_TIMEOUT_MS` | `5` / `5000` | |
| `DB_SSL_MODE` | unset | `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full` |
| `DB_MIGRATION_USER` / `DB_MIGRATION_PASSWORD` | runtime credentials | optional separate DDL role; password required if user is set |
| `OAUTH_CLIENTS` | unset (no clients) | JSON array of hosted-login clients, see below; malformed values fail at startup |
| `LOG_LEVEL` | `INFO` | level of the `tcg.accumulator.meishiapi` loggers |
| `OTEL_TRACES_EXPORTER` | `none` | e.g. `logging` |

## Logging

Logs are one JSON object per line (logstash encoder). Every line written while handling a request carries `requestId`
in the MDC: the caller's `X-Request-Id` when it matches `[A-Za-z0-9-]{1,64}`, otherwise a new UUID, echoed in the
response header.

- `access`: one line per request with `method`, `route` (the registered template such as `/api/users/:id`, or
  `unmatched`; never the query string), `status`, `durationMs`, `userId` (or `anonymous`) and `role`. 5xx is `ERROR`,
  401/403/429 `WARN`, health checks `DEBUG`, the rest `INFO`.
- `security`: `login_succeeded`, `login_failed` (`reason`, `userId` or `nicknameHash`, `clientIp`), `account_locked`,
  `login_blocked`, `login_rate_limited`, `registered`, `registration_failed`, `password_changed`,
  `password_change_failed`, `oauth_code_issued`, `oauth_code_rejected`, `oauth_token_issued`.
- Admin mutations log `admin_action` (`actorId`, `action`, `targetId`), matching the `admin_audit_log` row.

Never logged: passwords, tokens, activation keys, secrets, request and response bodies, query strings, headers,
nicknames as typed, email, phone, names, addresses, Discord names. People are identified by user id. An unknown login
name is logged only as `nicknameHash` (first 8 hex chars of SHA-256 of the lower-cased name). Client IPs appear only in
security events. Exceptions are logged as class plus our first stack frame, without their message. `AppConfig.toString()`
omits every secret. `LogCanaryTest` fails if any of this leaks.

## Conventions

- Errors are `{"error": "<message>"}` with the HTTP status; messages are fixed strings.
- Roles: `USER`, `ADMIN`. `/api/users*` requires a valid token; everything except `/api/users/me*` and
  `/api/users/nicknames` additionally requires `ADMIN`. Role and status are read from the database on every request.
- Bodies are limited to 16 KiB.
- CORS: no CORS handler. Browsers are expected to reach the API through a same-origin reverse proxy.

## Hosted login (OAuth 2 authorization code with PKCE)

See `docs/adr-meishi-identity-provider.md`. Clients are first party and come from `OAUTH_CLIENTS`:

```json
[{"id": "omiyage", "name": "Omiyage",
  "redirectUris": ["https://omiyage.example/auth/callback"],
  "returnUris": ["https://omiyage.example/account"]}]
```

URIs must be `https` (`http` only for `localhost`) with no fragment or user info, and are compared by exact string
equality. Codes live 60 seconds, work once and need the PKCE S256 verifier. The token is the usual Meishi JWT, capped
at the expiry of the session that authorized it.

## JWT contract (shared with omiyage-api)

HS256, key = raw UTF-8 bytes of `JWT_SECRET`, 24 h lifetime, claims `sub` (user UUID), `nickname`, `role`.
MeishiApi and omiyage-api must run with the same `JWT_SECRET`; rotate by restarting both together
(existing tokens become invalid).

## Deploy

CI builds the image on `master` and bumps the tag in `homelab-gitops`. `deploy/k8s` documents the manifest and the
`meishi-api-secrets` keys (`db-host`, `db-port`, `db-name`, `db-user`, `db-password`, `jwt-secret`, `admin-nickname`,
`admin-password`; optional `db-ssl-mode`, `db-migration-user`, `db-migration-password`).
Probes: `GET /health/live`, `GET /health/ready`.
