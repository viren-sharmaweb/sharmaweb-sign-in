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

## Google Workspace SSO with this app as an OIDC IdP

The app can also act as a custom OIDC identity provider for Google Workspace.
Use this when you want Google Workspace sign-ins for your domain to redirect to
`login.sharmaweb.com` and verify users with passkeys.

Important safety notes:

- Keep at least one Google Workspace super admin excluded from SSO while testing.
- The `email` claim returned by this app must match the user's primary Google
  Workspace email address.
- Bind a Cloudflare KV namespace as `AUTH_STORE` before production use so users
  and passkeys persist across Worker instances.
- First-time enrollment is controlled with `BOOTSTRAP_EMAILS` and optionally
  `BOOTSTRAP_CODE`. Do not enable `ALLOW_DOMAIN_BOOTSTRAP=true` unless you are
  comfortable letting any account in the domain self-enroll.

### 1. Generate OIDC secrets

```bash
npm run generate:oidc-secrets
```

Add the generated values to Cloudflare:

| Name | Type |
| --- | --- |
| `OIDC_CLIENT_ID` | Plaintext |
| `OIDC_CLIENT_SECRET` | Secret |
| `OIDC_PRIVATE_KEY_JWK` | Secret |
| `BOOTSTRAP_CODE` | Secret, optional |

Also add:

```text
ORIGIN=https://login.sharmaweb.com
RP_ID=login.sharmaweb.com
RP_NAME=SharmaWeb Sign In
WORKSPACE_DOMAIN=sharmaweb.com
BOOTSTRAP_EMAILS=admin@sharmaweb.com
ALLOW_DOMAIN_BOOTSTRAP=false
ALLOW_OIDC_WITHOUT_PASSKEY=false
```

### 2. Create the custom OIDC profile in Google Workspace Admin

Go to:

```text
admin.google.com
Security -> Authentication -> SSO with third-party IdPs
Add OIDC profile
```

Use:

```text
Issuer URL: https://login.sharmaweb.com
Client ID: value of OIDC_CLIENT_ID
Client secret: value of OIDC_CLIENT_SECRET
Change password URL: https://login.sharmaweb.com/signin.html
```

After saving, Google shows a generated **Redirect URI**. Copy that value into
Cloudflare as:

```text
OIDC_REDIRECT_URIS=<the redirect URI Google generated>
```

Redeploy the Worker after changing variables.

### 3. Assign the profile carefully

Assign the OIDC profile to a small test group first. Do not assign it to every
admin at once. Test this flow:

1. Go to a Google service and enter the Workspace email.
2. Google redirects to `https://login.sharmaweb.com/signin.html`.
3. The user verifies with an existing passkey or bootstraps their first passkey.
4. The app redirects back to Google with an OIDC authorization code.
5. Google exchanges the code and receives an ID token with the matching `email`
   claim.

