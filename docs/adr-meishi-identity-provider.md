# ADR: Meishi as the single identity provider

Status: proposed. Date: 2026-11-03.

## Decision

Meishi becomes the one place people log in and manage their profile. Apps send the browser to a hosted login page at
`meishifrontend`, get a single-use code back, and exchange it for the same JWT they already verify. The flow is the
OAuth 2 authorization-code grant with mandatory PKCE, implemented in MeishiApi. There is no third-party IdP. App
sessions, JWT format and `JWT_SECRET` do not change, and every existing login keeps working until each app has moved.

## Current state

- **MeishiApi** owns users, passwords (PBKDF2), roles, status and profile data. `POST /api/auth/login` and
  `/api/auth/register` return an HS256 JWT signed with `JWT_SECRET`: 24 h lifetime, claims `sub`, `nickname`, `role`.
  There is no server-side session and no revocation, but `/api/users*` re-reads role and status from the database on
  every request. There is no CORS, so browsers reach it through a same-origin proxy.
- **meishifrontend** is a Vue SPA. Its nginx proxies `/api/` to MeishiApi. The token lives in `localStorage`
  (`meishi.token`). It has login, activation-key registration, the account page and the admin user list. CSP is strict
  (`frame-ancestors 'none'`, `Referrer-Policy: no-referrer`). It is public at `https://meishi.gacnikhome.duckdns.org`:
  the edge proxy (Nginx Proxy Manager) forwards to NodePort 30084. `homelab-gitops` has no Ingress for it, so that
  route lives only in the edge proxy. The hosted flow depends on this host staying public.
- **omiyage-api** collects passwords for Meishi:
  - `MeishiAuthClient` proxies `POST /api/auth/login`, which already rejects frozen and locked accounts. Its extra
    `GET /api/users/me` call to reject frozen accounts is redundant.
  - `JwtVerifier` verifies the JWT locally with the shared secret. `AccountStatusChecker` re-checks status on writes.
  - `MeishiProfileClient` proxies profile, nickname and password changes, forwarding the user's bearer token.
  - `MeishiNicknameClient` and `MeishiAdminClient` forward the bearer token to `/api/users/nicknames` and `/api/users`.
  - App data (`user_profiles`) is keyed by the JWT `sub`.
- **omiyage-frontend** is a React SPA with its own login form and profile pages. It talks only to omiyage-api and keeps
  the token in `localStorage` (`omiyage.token`).
- **tcg-reader** is Next.js. Its `/login` form posts to its own server, which calls `POST /api/auth/login`, verifies
  the JWT with the shared `MEISHI_JWT_SECRET` and stores it in the httpOnly cookie `tcg_reader_session`.

Problems: each app handles raw passwords, each app has its own login and profile UI, and a login at one app does not
carry to another.

## Target

```
Browser          App                  meishifrontend             MeishiApi
  | open app      |                         |                        |
  |-------------->| make state + PKCE       |                        |
  |<-- redirect --|                         |                        |
  |-- /oauth/authorize?client_id&redirect_uri&state&code_challenge ->|
  |                                         | GET /api/oauth/client  |
  |                                         | (no session: /login)   |
  |                                         | POST /api/oauth/authorize (Bearer)
  |                                         |<----- redirectUrl -----|
  |<-- redirect_uri?code&state -------------|                        |
  |-------------->| check state             |                        |
  |               | POST /api/oauth/token (code + code_verifier) --->|
  |               |<------------ the usual Meishi JWT ---------------|
```

- Login, registration and profile pages live only in Meishi. Apps link to them with a return URL.
- Apps keep app-specific data keyed by the Meishi user id (`sub`) and store no credentials.
- First-party clients only, so there is no consent screen and there are no scopes.

### Endpoints

Browser routes on `meishifrontend`:

| Route | Purpose |
| --- | --- |
| `/oauth/authorize?response_type=code&client_id=&redirect_uri=&state=&code_challenge=&code_challenge_method=S256` | Hosted login. Invalid requests show an error page and never redirect. |
| `/profile?client_id=&return_uri=` | Profile page with a "Back to app" link. Both parameters are optional. |
| `/logout?client_id=&return_uri=` | Ends the Meishi session, then returns to the app. |

MeishiApi:

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /api/oauth/client?client_id=&redirect_uri=` or `&return_uri=` | none | 200 `{clientId, name}` if the client and URI are registered, else 400. Lets the SPA show the app name and refuse bad links. |
| `POST /api/oauth/authorize` JSON body with the query parameters above | Bearer (Meishi session) | Issues a code, returns `{redirectUrl}`. The URL is built by the server. |
| `POST /api/oauth/token` form-encoded `grant_type=authorization_code&code=&redirect_uri=&client_id=&code_verifier=` | none (code + verifier) | Returns `{access_token, token_type: "Bearer", expires_in}` with `Cache-Control: no-store`. Failure is 400 `{error: "invalid_grant"}`. |

### Client registry

`OAUTH_CLIENTS` is a JSON environment variable, kept in `homelab-gitops`. Unset means no clients, so the feature does
nothing and the app boots as today. Malformed values fail at startup like other bad config.

```json
[{"id": "omiyage", "name": "Omiyage",
  "redirectUris": ["https://omiyage.gacnikhome.duckdns.org/auth/callback"],
  "returnUris": ["https://omiyage.gacnikhome.duckdns.org/account"]}]
```

URIs must be absolute, have no fragment, and use `https` (`http` only for `localhost`). Matching is exact string
equality, with no prefix, wildcard or normalisation. An environment variable beats a table because there are three
clients, they change rarely, nothing is secret, and no admin UI is needed.

### Authorization codes

Table `oauth_authorization_codes`, an additive migration: `code_hash` (SHA-256, primary key), `client_id`,
`redirect_uri`, `user_id` (FK, `ON DELETE CASCADE`), `code_challenge`, `session_expires_at`, `expires_at`.

- 256 bits from `SecureRandom`, only the hash is stored, and codes and verifiers are never logged.
- Lifetime 60 seconds.
- Single use: `DELETE ... WHERE code_hash = $1 AND expires_at > now() RETURNING ...` is atomic, even with two replicas.
- The code is consumed before anything else is checked, so a wrong verifier, client or redirect URI burns it.
- `S256` only. `plain` is rejected. `state` is required.
- Expired rows are deleted when a new code is issued.

A database table is used over memory because a code must survive a pod restart during a redirect and stay single-use
if `replicas` ever grows.

The token endpoint has no IP rate limit. All calls come from app servers, so one user's traffic would throttle
everyone, and a 256-bit code cannot be guessed.

## Token and session strategy

- **The Meishi session is the existing JWT** in `localStorage` at `meishifrontend`. A valid one makes `/oauth/authorize`
  a silent redirect. That is single sign-on, and it needs no new session store.
- **The app token is the same JWT** (`sub`, `nickname`, `role`, HS256). `JwtVerifier`, `verifyMeishiToken`, the
  forwarding clients and `AccountStatusChecker` work unchanged.
- **No token lifetime extension.** A token minted through the flow gets the `exp` of the session that authorized it, so
  the login stays absolute at 24 h. Without this, one stolen token could mint fresh tokens forever. When the session
  ends the user logs in again, which matches today.
- **No refresh tokens.** The app re-runs the redirect. It is silent while the session lasts, and a refresh token would
  only add state and a second thing to steal.
- **No client secrets.** PKCE proves that the party redeeming a code started the flow. All clients are first party with
  fixed HTTPS redirect URIs, and a secret could not ship in an SPA anyway.
- `/api/oauth/authorize` and `/api/oauth/token` each let in only the accounts that `POST /api/auth/login` lets in: the
  user exists, has activated the account, is `ACTIVE` and is not locked. A frozen, locked, never-activated or deleted
  user gets no code and no token. `/api/oauth/authorize` is also limited to 30 requests per minute per user.
- Tokens are still not revocable and still work across apps. Both are true today and are unchanged here.

### Accepted tradeoffs

- **HS256 with a shared secret stays.** Each verifying app can forge tokens. Moving to RS256 with JWKS is the right
  next step but is independent of this flow and would change every verifier at once. A new client that should not hold
  the secret can skip local verification and call `GET /api/users/me` with the token.
- **`localStorage` for the Meishi session stays.** An httpOnly cookie resists XSS better, but needs a session table,
  CSRF protection and a rewrite of how the SPA calls the API. The strict CSP limits the risk, and the same token already
  sits in `localStorage` at two origins. Revisit this together with RS256.

## Why no third-party IdP

Keycloak, Authentik or Zitadel would add a stateful JVM or Python service, its database and its upgrades to a small home
cluster, plus a user migration across password hashes, nickname login and activation-key registration. Apps would still
need the same redirect work, and their JWT verifiers would have to change. What Meishi needs is one grant, one table and
three endpoints, for three first-party clients. OIDC discovery, ID tokens, scopes, consent and federation solve problems
Meishi does not have. A third-party product becomes worth revisiting if there are outside clients or social login.

## Threats

| Threat | Mitigation |
| --- | --- |
| Open redirect | Exact match against the registry. The URL comes from the server. Errors render at Meishi and never redirect. |
| Code interception | PKCE S256 is required, and the code is useless without the verifier. |
| Code replay | Atomic delete on first use, 60-second lifetime, hash at rest. |
| Login CSRF | `state` is required and the client must compare it. |
| Clickjacking of the silent redirect | `frame-ancestors 'none'` on meishifrontend. |
| Code leak via referrer or logs | `no-referrer` at Meishi. Clients remove the code from the URL and the API logs no query strings. |
| Token in URLs | Tokens only travel back-channel or in the JSON response. |

## Migration

Each step is independently deployable and reversible, and `POST /api/auth/login` keeps working throughout.

1. Ship MeishiApi and meishifrontend changes. With `OAUTH_CLIENTS` unset, nothing changes.
2. Add `OAUTH_CLIENTS` for Omiyage in `homelab-gitops`.
3. Make the login rate limit per client before any app moves. Today meishifrontend's nginx sets `X-Forwarded-For` to
   its `$remote_addr`, which is the edge proxy or a node after NodePort SNAT, and `CLIENT_IP_HEADER` is unset, so
   `LoginRateLimiter` keys on that address. Once every app logs in through meishifrontend, all users of all apps would
   share one 10-attempts-per-minute bucket. Keying the limit per nickname was rejected because anyone could then
   throttle a chosen user. The code side is inert until the infrastructure steps below are done: meishifrontend's
   nginx trusts `X-Real-IP` only from the edge proxy (`set_real_ip_from 192.168.0.22/32`), and MeishiApi ignores
   `X-Forwarded-For` while `CLIENT_IP_HEADER` is unset. The infrastructure steps go in `homelab-gitops` and the edge
   proxy, one at a time, each checked before the next:

   1. Point the edge proxy's Meishi host at the node that runs the meishifrontend pod (`192.168.0.24:30084`,
      k8s-node-2; today it is k8s-ctrl, `192.168.0.20`). This works with the current policy, so check the site
      before going on.
   2. Pin the meishifrontend Deployment to that node (`nodeSelector: kubernetes.io/hostname: k8s-node-2`). This is a
      single point of failure: if that node is down, Meishi is down until the pin and the upstream move. With one
      replica the pod already lives on one node, but today Kubernetes can reschedule it elsewhere.
   3. Set `externalTrafficPolicy: Local` on the meishifrontend Service. Only nodes that run the pod answer on the
      NodePort, and the pod now sees the edge proxy (`192.168.0.22`) as its peer instead of a flannel address
      (`10.244.0.0` today). Check that the nginx access log shows client addresses.
   4. Confirm that the internet path cannot set `X-Real-IP`. The edge proxy itself trusts `X-Real-IP` from CDN and
      private ranges and also listens on IPv6, and the owner is testing whether a client can spoof it. Stop here until
      that is settled.
   5. Make meishi-api unreachable from outside the cluster. Today it is a NodePort (30081), published by the edge
      proxy as `meishi-api.gacnikhome.duckdns.org`. Anyone who reaches it directly could send any `X-Forwarded-For`
      once the next step is done. The Service becomes `ClusterIP` and its edge proxy host is removed. omiyage-api
      already calls it by cluster DNS (`MEISHI_API_URL` is a `*.svc.cluster.local` address). Any other caller of the
      public host, such as tcg-reader, must move to meishifrontend's `/api/` or to cluster DNS first. A
      NetworkPolicy is no alternative: the CNI is flannel, which does not enforce NetworkPolicy.
   6. Set `CLIENT_IP_HEADER=X-Forwarded-For` on meishi-api. MeishiApi uses the last entry, which meishifrontend's
      nginx wrote from the trusted `X-Real-IP`.

   Rollback runs in reverse order: unset `CLIENT_IP_HEADER`, restore the meishi-api NodePort and edge host if needed,
   set the Service back to `externalTrafficPolicy: Cluster`, remove the pin, then point the edge proxy at any node
   again. Each step on its own leaves Meishi working, because the code falls back to today's behaviour while the header
   is not trusted.

   `set_real_ip_from` lists only the edge proxy address. Trusting node or pod ranges instead was rejected because it
   trusts every pod.
4. Omiyage adds "Continue with Meishi" next to the existing form, then links profile pages to Meishi.
5. tcg-reader does the same.
6. Once both are stable, apps remove their password forms and profile proxy routes. Tokens already issued stay valid
   until they expire.
7. Later, restrict `POST /api/auth/login` to meishifrontend. This is a separate decision, not part of this work.

## What each consumer changes

**meishifrontend**: add the three routes, send `/login` and `/register` back to the pending request, and keep admin
pages as they are.

**omiyage-frontend**: add a `/auth/callback` route. Before redirecting, create `state` and a verifier and keep them in
`sessionStorage`. On return, compare `state`, post `{code, codeVerifier}` to omiyage-api, then call the existing
`authStore.login(token)`. Replace profile and password pages with links to `/profile?client_id=omiyage&return_uri=...`.
Logout clears the local token, then goes to Meishi `/logout`.

**omiyage-api**: add `POST /api/auth/meishi/exchange`, which adds the configured `client_id` and `redirect_uri`, calls
`POST /api/oauth/token`, keeps the existing frozen check and returns `{token}` like today. This keeps the rule that
browsers talk only to omiyage-api, so MeishiApi needs no CORS. `JwtVerifier`, `AccountStatusChecker`,
`MeishiNicknameClient` and `MeishiAdminClient` stay. `MeishiAuthClient.login` and the mutating `MeishiProfileClient`
routes go away in step 6.

**tcg-reader**: add a start route that sets httpOnly `state` and verifier cookies and redirects, and a callback route
that checks `state`, calls the token endpoint, runs `verifyMeishiToken` and sets `tcg_reader_session`. Remove the form
and `/api/auth/login` in step 6.

**homelab-gitops**: the ordered steps of migration step 3 (pin meishifrontend, `externalTrafficPolicy: Local`,
`meishi-api` as `ClusterIP`, then `CLIENT_IP_HEADER=X-Forwarded-For`), and `OAUTH_CLIENTS` on the `meishi-api`
deployment.

## Consequences

- Apps stop seeing passwords, and Meishi becomes the single place to process user data.
- Meishi is now a login dependency for every app, as it already is in practice.
- A Meishi login lasts 24 h at most across all apps. There is no "stay signed in".
