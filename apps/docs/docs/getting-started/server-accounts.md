---
description: Optional accounts for server features
---

# Server accounts

Server accounts are optional and disabled by default. Existing installations keep
working without signing in. Enabling accounts adds a **Server Account** section in
Settings; it does not require a login to use Mere's existing features.

This is login groundwork only. Signing in does not upload, sync, encrypt, or move
medical records. Signing out revokes the server session; local records remain
available in the browser. A server account is separate from the local patient
profiles and the password used for encrypted browser storage.

## Enable accounts

Configure these environment variables on the API container:

| Variable                | Value                                                                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `PUBLIC_URL`            | The HTTPS URL users open, such as `https://mere.example`. HTTP is accepted only on loopback for local development.                 |
| `MERE_AUTH_DB_PATH`     | A writable SQLite file on a persistent mount, such as `/data/accounts.db`. Leave unset to disable accounts and all auth endpoints. |
| `MERE_AUTH_SETUP_TOKEN` | A random token of 32–512 characters, generated and stored privately by the operator. Required when accounts are enabled.           |

For example, generate a token locally with `openssl rand -hex 32`, then supply it
through your container's private environment file. Do not put it in a URL, an
invite link, or a public configuration file. This token is separate from `APP_KEY`
and its registration tokens for patient portals.

Create the mounted directory with mode `0700`, owned by the API's runtime user
(UID 1000 in the published image). The account file is created with mode `0600`.
Persist the entire directory, including SQLite's WAL files. Account storage holds
usernames, salted password hashes and hashed session tokens, not patient records.
Treat the directory and its backups as private credentials.

Restart Mere, open Settings, and enter a username, a password of 15–128 characters,
and the setup token. Usernames contain 3–64 letters, numbers, underscores or
hyphens, start with a letter or number, and are case insensitive. Setup creates
the first account and closes registration. Concurrent setup requests cannot
create extra accounts. Subsequent visits show a sign-in form without a setup
token field. Only share the setup token with the intended first account owner.

This initial feature has no additional-user registration, password reset, MFA, or
account administration. Keep the password in a password manager. These operations
need separate designs before accounts protect medical data.

## Sessions and future server endpoints

Passwords use Node's asynchronous Argon2id implementation (19 MiB, two passes,
one lane, a random 16-byte salt). Sessions use random 256-bit tokens, stored only
as SHA-256 hashes in SQLite. Cookies are HttpOnly, SameSite=Strict, scoped to
`/api`, and Secure when `PUBLIC_URL` is HTTPS. Sessions survive API restarts,
expire after eight hours or thirty minutes without an authenticated request, and
are revoked immediately on sign-out. Signing in replaces this browser's old
session. Expired rows are removed on the next successful sign-in.

Auth mutations require an exact `Origin` match with `PUBLIC_URL`. The configured
URL determines cookie security, including behind a TLS-terminating reverse proxy;
client-supplied forwarding headers are not trusted. Sign-in and setup are limited
to five requests per minute per direct client IP. Behind a proxy this may be a
shared limit; do not trust arbitrary forwarded IP headers to bypass it.

The API exposes `GET /api/v1/auth/status`, `POST /api/v1/auth/setup`,
`POST /api/v1/auth/sign-in`, `GET /api/v1/auth/session`, and
`POST /api/v1/auth/sign-out`. POST bodies are JSON, limited to 4 KiB; setup accepts
`username`, `password`, and `setupToken`, while sign-in accepts `username` and
`password`. Auth responses use `Cache-Control: no-store`.

Future server modules can import the configured `AuthModule`, use
`@UseGuards(SessionGuard)`, and read `request.serverUser.id` from
`AuthenticatedRequest`. The guard always rejects absent or expired sessions,
including on an empty account database, and checks the origin on unsafe requests.
It is deliberately not a global guard: existing PWA routes, patient portal
connections and the public tenant catalog retain their current behavior. A
future endpoint must still restrict each resource to that server user; this PR
does not establish a link to browser patient profiles.
