# MeishiApi

User identity/auth service for the tcg project: registration, login, JWT
issuance, and admin user management. Other services (OmiyageApi, ...)
resolve a caller's identity by forwarding their bearer token to this
service's `GET /api/users/me` rather than sharing the JWT secret - see
`AuthContext.kt` in those services for why.

## Why invite-only registration, not open sign-up

There's no public "create an account" endpoint. Provisioning is two steps:

1. An admin calls `POST /api/users` with a role, getting back an id and a
   fresh `activationKey` (a UUID) for a stub user that has no nickname or
   password yet.
2. The invited person calls `POST /api/auth/register` with that
   `activationKey` plus their chosen nickname/password, which activates the
   account and returns a JWT - the same response shape as login.

This is deliberate for a small, closed friend-group project: nobody should
be able to self-provision an account, but the admin never has to know or
set anyone's password either. `findByActivationKey` + `record.activatedAt
!= null` is what makes a key single-use.

## Auth model

JWT (HS256, shared secret `JWT_SECRET`), stateless - no session store, no
refresh tokens, 24h expiry. The token's `role` claim is trusted directly by
`UserHandler.requireAdmin` without a DB round-trip per request; a role
change via `PATCH /api/users/:id` only takes effect on that user's *next*
login (their existing token still carries the old role until it expires).
That's an accepted tradeoff for low request volume, not an oversight.

Passwords are hashed with PBKDF2 via Vert.x's built-in `HashingStrategy`
(`PasswordHasher.kt`) - it ships with the auth library already in use, no
extra dependency, and is adequate for the account volume this service will
ever see.

Failed logins are tracked per-account; the 3rd consecutive failure freezes
the account (`Status.FROZEN`) until an admin unfreezes it via
`PATCH /api/users/:id/status`. Crude, but enough brute-force resistance for
an internal tool with no rate limiting in front of it yet.

## Config-provisioned admins

`ADMIN_USERS` (see `AppConfig.kt`) is a JSON list of `{nickname, password}`
admin accounts, each ensured to exist at startup independent of the normal
invite/registration flow above - useful for the handful of admins who
should always exist regardless of database state. It's a Kubernetes Secret
in real deployments (it contains passwords), sourced from a masked+protected
GitLab CI/CD variable, never committed.

## Configuration

| Variable | Meaning |
|---|---|
| `HTTP_PORT` | HTTP port (default `8080`) |
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` | Postgres connection |
| `JWT_SECRET` | HS256 signing secret - anyone with this can mint valid tokens, treat as a real secret |
| `ADMIN_USERS` | JSON array of config-provisioned admin accounts, see above |

## Endpoints

| Endpoint | Auth | Meaning |
|---|---|---|
| `POST /api/auth/register` | activation key | Activate an invited account, returns a JWT |
| `POST /api/auth/login` | none | Returns a JWT |
| `GET /api/users/me` | any JWT | The caller's own id/nickname/role - what other services call to resolve a bearer token |
| `GET /api/users` | admin JWT | List all users |
| `POST /api/users` | admin JWT | Invite a new user (returns id + activation key) |
| `PATCH /api/users/:id` | admin JWT | Change role |
| `PATCH /api/users/:id/status` | admin JWT | Freeze/unfreeze |
| `DELETE /api/users/:id` | admin JWT | Remove a user |

## Running locally

`docker compose up -d --build` - Postgres + this API, migrations run on
startup (Flyway, see `Database.kt` / `src/main/resources/db/migration`).
