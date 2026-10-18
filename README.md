# DillShare

Self-hosted, end-to-end encrypted file sharing. Files are encrypted in the
browser with a per-share AES-256-GCM key that never reaches the server, and file
bytes travel directly between the browser and S3-compatible object storage
(Cloudflare R2, MinIO, Wasabi, B2, AWS S3). The Rust server only ever stores
ciphertext plus the metadata needed to enforce expiry and ownership.

## What it does

- **Zero-knowledge shares.** Each upload gets a fresh random key. It lives in the
  URL fragment (`/share/<uuid>#<key>`), so it is never sent in an HTTP request,
  never logged by a proxy, and never stored on the server.
- **Direct-to-bucket transfers.** Presigned `PUT`/`GET` URLs with SHA-256
  checksums; the server never proxies file bytes, so large transfers do not
  consume its bandwidth or disk.
- **Chunked streaming.** Files are encrypted in 4 MiB AES-GCM chunks so previews
  and downloads can decrypt arbitrary byte ranges, including media seeking.
- **Folders, thumbnails, markdown notes.** Upload whole directory trees, get
  image/video thumbnails, and attach a short note to a share.
- **Accounts.** Username + password (PBKDF2-SHA-256, 100k iterations, split into
  an auth key and an encryption key), passkeys (WebAuthn), TOTP 2FA, session
  listing/renaming/revocation, and a per-account encrypted share index.
- **Per-share expiry** with an hourly cleanup sweep, plus admin roles
  (superadmin/admin) for user and share management.
- **Single binary.** The SPA, vendored libraries and the webfont are embedded at
  compile time; the app runs fully offline with no CDN dependency.

## Quick start

```sh
cp .env.example .env
# fill in AWS_* (or R2/MinIO equivalents), URL, RP_ID and RP_ORIGIN
docker compose up -d --build
```

The container listens on `127.0.0.1:8000`. Put a TLS-terminating reverse proxy in
front of it, or passkeys and clipboard-based share keys will not work.

Without an S3 bucket configured the server starts in **memory mode**: accounts
work, but uploads are refused because direct transfers require presigning. This
mode is for UI work and tests only — restarting the process loses everything.

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `AWS_S3_BUCKET` / `S3_BUCKET` | — | Enables S3 storage. Without it the server runs in memory mode. |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION` | SDK chain | Standard AWS credential resolution also works (instance/task roles). |
| `AWS_ENDPOINT_URL` | — | Custom endpoint for R2/MinIO/Wasabi/B2. |
| `AWS_S3_FORCE_PATH_STYLE` | `false` | Set `true` for MinIO/LocalStack. |
| `PORT` | `8000` | Listen port. |
| `URL` | — | Public origin. When set, requests with a different `Host`/`Origin` are rejected (defence in depth against DNS rebinding) and CORS is restricted to it. `/healthz` is exempt so in-cluster probes keep working. |
| `RP_ID` / `RP_ORIGIN` | `localhost` / `http://localhost:3000` | WebAuthn relying party; must match the public origin for passkeys. |
| `JWT_SECRET` | generated | ≥32 bytes. If unset, a random secret is created atomically in the bucket at `config/jwt_secret.bin`. |
| `DILLSHARE_PRESIGN_TTL_SECONDS` | `300` | Clamped to 60–900. Applies to every presigned URL. |
| `DILLSHARE_PARTIAL_TIMEOUT_HOURS` | `12` | Hard lifetime of an unfinished upload session (1–168). |

The first account that registers becomes the superadmin. It can promote and
demote other accounts, and it cannot be deleted or demoted.

## Bucket setup

The bucket must stay private; all access is through presigned URLs. Add a CORS
rule that allows the application origin, the `PUT`/`GET`/`HEAD` methods, and the
`ETag` and `Content-Range` response headers (uploads read `ETag`, streaming
preview validates `Content-Range`):

```json
[
  {
    "AllowedOrigins": ["https://share.example.com"],
    "AllowedMethods": ["GET", "HEAD", "PUT"],
    "AllowedHeaders": ["*"],
    "ExposeHeaders": ["ETag", "Content-Range"],
    "MaxAgeSeconds": 3600
  }
]
```

Abandoned multipart uploads are aborted by the hourly sweep after
`DILLSHARE_PARTIAL_TIMEOUT_HOURS`, so an S3 lifecycle rule is optional but
harmless as a backstop.

## Security model

- Share keys never leave the browser except to the destination bucket inside the
  encrypted stream; possession of the full link is what grants access.
- The account encryption key is derived from the password (PBKDF2-SHA-256,
  100k iterations, username as salt) and cached in `localStorage` per account so
  passkey sign-in and background sync can decrypt without re-prompting. That
  cache is script-readable: any XSS on the origin would expose it, which is why
  share notes are rendered through a locked-down Markdown renderer (no raw HTML,
  no remote images, no `javascript:` links) and file lists are escaped.
- Sessions are HMAC-signed and tracked server-side; revoking a session invalidates
  the token immediately (open tabs are notified over a long poll).
- Failed sign-ins, TOTP attempts and registrations are rate limited per client
  address and per account (in memory, per instance).
- The server does learn: share existence, owner, file count, plaintext sizes,
  expiry, and who is downloading from which IP. It does not learn file names,
  MIME types, contents, or the share note.

### Known limitations

- A share link is a bearer capability: anyone holding it can read the files until
  the share expires or is deleted. There are no per-recipient passwords.
- Losing the account password loses the account encryption key, which means the
  saved share index cannot be decrypted (the share links themselves still work).
- Share notes are HTML-escaped by the renderer, so embedded images and raw HTML
  are shown as text instead of being rendered.

## Operations

- `GET /healthz` — liveness. Deliberately does not touch object storage, so a
  bucket outage does not restart healthy pods. `dillshare --healthcheck` performs
  the same check (used by the image's `HEALTHCHECK`).
- The cleanup worker runs hourly: expired shares, abandoned upload sessions,
  stale auth sessions, orphaned passkey indexes, and per-user objects outside
  the allowlist. It only ever deletes inside the application's own namespaces
  (`uploads/`, `users/`, `auth_sessions/`, `passkey_index/`, `config/`).
- Assets are served with content-hash `ETag`s and revalidated, so upgrading the
  binary never leaves clients on stale vendored JavaScript.

## Development

```sh
cargo test        # unit tests, including a cleanup-sweep regression test
cargo run         # memory mode unless AWS_S3_BUCKET is set
```

```
src/main.rs      HTTP API, auth, uploads, cleanup, admin
src/storage.rs   S3 + in-memory storage abstraction
src/index.html   single-file SPA (embedded at compile time)
src/sw.js        service worker that streams decrypted media ranges
src/vendor/      pinned third-party browser libraries
```

## License

MIT
