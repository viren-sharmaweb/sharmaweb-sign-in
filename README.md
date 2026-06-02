# sharmaweb-sign-in

A small Express app that demonstrates safe Google OAuth sign-in plus app-level
verification with passkeys.

## What this does

- Sends "Continue with Google" users to Google's real OAuth flow.
- Redirects users back to `/verify.html` after Google verifies their Google
  identity.
- Completes local app verification on your page.
- Requires a passkey for accounts that already have one.
- Lets signed-in users register a passkey for future sign-ins.

This app intentionally does **not** collect Google passwords or render a fake
Google credential screen. Google credentials should only be entered on
Google-owned pages; this app can verify only your application's own session and
passkeys.

## Quick start

```bash
npm install
cp .env.example .env
npm start
```

Open <http://localhost:3000>.

## Google OAuth setup

Create an OAuth client in Google Cloud Console, then add this authorized redirect
URI for local development:

```text
http://localhost:3000/auth/google/callback
```

Set these values in `.env`:

```text
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
ORIGIN=http://localhost:3000
RP_ID=localhost
SESSION_SECRET=a-long-random-secret
```

For production, `ORIGIN` must be your HTTPS origin and `RP_ID` must match the
effective domain used for passkeys, for example:

```text
ORIGIN=https://signin.example.com
RP_ID=example.com
```

## Passkey behavior

Passkeys use WebAuthn, so they require a secure context. Browsers allow this on
`localhost`; production deployments must use HTTPS.

The demo stores users and passkeys in memory. Replace the in-memory maps in
`server.js` with a database before deploying, and store each passkey credential
with its user, public key, counter, transports, and creation timestamp.

Set `REQUIRE_PASSKEY_AFTER_GOOGLE=true` if every Google sign-in must be followed
by passkey verification. Leave it `false` to allow first-time users to complete
local verification and then register their first passkey.

## Cloudflare Workers build

The repository includes `wrangler.json` and `src/worker.mjs` so Cloudflare
Workers Builds has a deployable entrypoint. Run the same dry-run build locally
with:

```bash
npm run build
```

For a Cloudflare deployment, configure these Worker variables/secrets:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `SESSION_SECRET`
- `ORIGIN`
- `RP_ID`
- `RP_NAME`
- `REQUIRE_PASSKEY_AFTER_GOOGLE`
