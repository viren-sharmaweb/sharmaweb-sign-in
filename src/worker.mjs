import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

const users = new Map();
const usersByEmail = new Map();
const usersByGoogleId = new Map();
const credentialsById = new Map();
const sessionCookieName = 'sw_session';
const textEncoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const session = await readSession(request, env);

    try {
      if (url.pathname === '/auth/google') {
        return handleGoogleStart(request, env, session);
      }

      if (url.pathname === '/auth/google/callback') {
        return handleGoogleCallback(request, env, session);
      }

      if (url.pathname === '/api/session' && request.method === 'GET') {
        return handleSession(request, env, session);
      }

      if (url.pathname === '/api/verify/complete' && request.method === 'POST') {
        return handleCompleteVerification(request, env, session);
      }

      if (
        url.pathname === '/api/passkeys/register/options' &&
        request.method === 'POST'
      ) {
        return handleRegisterOptions(request, env, session);
      }

      if (
        url.pathname === '/api/passkeys/register/verify' &&
        request.method === 'POST'
      ) {
        return handleRegisterVerify(request, env, session);
      }

      if (
        url.pathname === '/api/passkeys/authenticate/options' &&
        request.method === 'POST'
      ) {
        return handleAuthenticateOptions(request, env, session);
      }

      if (
        url.pathname === '/api/passkeys/authenticate/verify' &&
        request.method === 'POST'
      ) {
        return handleAuthenticateVerify(request, env, session);
      }

      if (url.pathname === '/api/sign-out' && request.method === 'POST') {
        const headers = new Headers({ 'content-type': 'application/json' });
        clearSessionCookie(headers, request);
        return new Response(JSON.stringify({ ok: true }), { headers });
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error(error);
      return json({ error: error.message || 'Unexpected server error' }, 500);
    }
  },
};

async function handleGoogleStart(request, env, session) {
  if (!googleConfigured(env)) {
    return json(
      {
        error: 'Google OAuth is not configured',
        requiredEnv: ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'ORIGIN'],
      },
      501,
    );
  }

  const origin = originFor(request, env);
  const state = randomBase64Url(32);
  session.oauthState = state;

  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', `${origin}/auth/google/callback`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid email profile');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('prompt', 'select_account');

  const headers = new Headers({ location: authUrl.toString() });
  await commitSessionCookie(headers, session, env, request);
  return new Response(null, { status: 302, headers });
}

async function handleGoogleCallback(request, env, session) {
  if (!googleConfigured(env)) {
    return redirect('/?error=google_not_configured');
  }

  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  if (!code || !state || state !== session.oauthState) {
    return redirect('/?error=google_state');
  }

  const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: `${originFor(request, env)}/auth/google/callback`,
    }),
  });

  if (!tokenResponse.ok) {
    return redirect('/?error=google_token');
  }

  const token = await tokenResponse.json();
  const profileResponse = await fetch(
    'https://openidconnect.googleapis.com/v1/userinfo',
    {
      headers: { authorization: `Bearer ${token.access_token}` },
    },
  );

  if (!profileResponse.ok) {
    return redirect('/?error=google_profile');
  }

  const profile = await profileResponse.json();
  const email = profile.email?.toLowerCase();

  if (!email) {
    return redirect('/?error=google_email');
  }

  const user = upsertGoogleUser({
    googleId: profile.sub,
    email,
    displayName: profile.name || email,
    photo: profile.picture,
  });

  session.pendingUserId = user.id;
  session.pendingProvider = 'google';
  delete session.userId;
  delete session.oauthState;

  const headers = new Headers({ location: '/verify.html' });
  await commitSessionCookie(headers, session, env, request);
  return new Response(null, { status: 302, headers });
}

function handleSession(request, env, session) {
  const user = getSessionUser(session);
  const pendingUser = session.pendingUserId
    ? users.get(session.pendingUserId)
    : null;

  return json({
    authenticated: Boolean(user),
    googleConfigured: googleConfigured(env),
    rpName: rpNameFor(env),
    requirePasskeyAfterGoogle: requirePasskeyAfterGoogle(env),
    user: user ? serializeUser(user) : null,
    pending: pendingUser
      ? {
          provider: session.pendingProvider,
          user: serializeUser(pendingUser),
          hasPasskeys: pendingUser.passkeys.length > 0,
        }
      : null,
  });
}

async function handleCompleteVerification(request, env, session) {
  const pendingUser = session.pendingUserId
    ? users.get(session.pendingUserId)
    : null;

  if (!pendingUser) {
    return json({ error: 'No pending Google sign-in to verify' }, 401);
  }

  if (pendingUser.passkeys.length > 0 || requirePasskeyAfterGoogle(env)) {
    return json(
      {
        error: 'Passkey verification is required for this account',
        code: 'passkey_required',
      },
      403,
    );
  }

  establishSession(session, pendingUser);
  const headers = new Headers({ 'content-type': 'application/json' });
  await commitSessionCookie(headers, session, env, request);
  return new Response(JSON.stringify({ user: serializeUser(pendingUser) }), {
    headers,
  });
}

async function handleRegisterOptions(request, env, session) {
  const user = getSessionUser(session);

  if (!user) {
    return json({ error: 'Sign in before registering a passkey' }, 401);
  }

  const options = await generateRegistrationOptions({
    rpName: rpNameFor(env),
    rpID: rpIDFor(request, env),
    userID: textEncoder.encode(user.id),
    userName: user.email,
    userDisplayName: user.displayName,
    attestationType: 'none',
    excludeCredentials: user.passkeys.map((passkey) => ({
      id: passkey.credential.id,
      transports: passkey.credential.transports,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
  });

  session.currentRegistrationChallenge = options.challenge;
  const headers = new Headers({ 'content-type': 'application/json' });
  await commitSessionCookie(headers, session, env, request);
  return new Response(JSON.stringify(options), { headers });
}

async function handleRegisterVerify(request, env, session) {
  const user = getSessionUser(session);

  if (!user) {
    return json({ error: 'Sign in before registering a passkey' }, 401);
  }

  const verification = await verifyRegistrationResponse({
    response: await request.json(),
    expectedChallenge: session.currentRegistrationChallenge,
    expectedOrigin: originFor(request, env),
    expectedRPID: rpIDFor(request, env),
    requireUserVerification: true,
  });

  if (!verification.verified || !verification.registrationInfo) {
    return json(
      { error: 'Passkey registration could not be verified' },
      400,
    );
  }

  const credential = verification.registrationInfo.credential;

  if (!credentialsById.has(credential.id)) {
    const passkey = {
      credential,
      createdAt: new Date().toISOString(),
    };

    user.passkeys.push(passkey);
    credentialsById.set(credential.id, { userId: user.id, passkey });
  }

  delete session.currentRegistrationChallenge;
  const headers = new Headers({ 'content-type': 'application/json' });
  await commitSessionCookie(headers, session, env, request);
  return new Response(JSON.stringify({ passkeyCount: user.passkeys.length }), {
    headers,
  });
}

async function handleAuthenticateOptions(request, env, session) {
  const payload = await request.json().catch(() => ({}));
  const user = findUserForPasskeyAuthentication(session, payload);

  if (!user) {
    return json({ error: 'No account found for passkey authentication' }, 404);
  }

  if (user.passkeys.length === 0) {
    return json({ error: 'This account does not have any passkeys yet' }, 400);
  }

  const options = await generateAuthenticationOptions({
    rpID: rpIDFor(request, env),
    allowCredentials: user.passkeys.map((passkey) => ({
      id: passkey.credential.id,
      transports: passkey.credential.transports,
    })),
    userVerification: 'required',
  });

  session.currentAuthenticationChallenge = options.challenge;
  session.currentAuthenticationUserId = user.id;
  const headers = new Headers({ 'content-type': 'application/json' });
  await commitSessionCookie(headers, session, env, request);
  return new Response(JSON.stringify(options), { headers });
}

async function handleAuthenticateVerify(request, env, session) {
  const body = await request.json();
  const expectedUser = session.currentAuthenticationUserId
    ? users.get(session.currentAuthenticationUserId)
    : null;
  const credentialRecord = credentialsById.get(body.id);

  if (
    !expectedUser ||
    !credentialRecord ||
    credentialRecord.userId !== expectedUser.id
  ) {
    return json({ error: 'Passkey does not match the requested account' }, 400);
  }

  const verification = await verifyAuthenticationResponse({
    response: body,
    expectedChallenge: session.currentAuthenticationChallenge,
    expectedOrigin: originFor(request, env),
    expectedRPID: rpIDFor(request, env),
    credential: credentialRecord.passkey.credential,
    requireUserVerification: true,
  });

  if (!verification.verified) {
    return json(
      { error: 'Passkey authentication could not be verified' },
      400,
    );
  }

  credentialRecord.passkey.credential.counter =
    verification.authenticationInfo.newCounter;
  establishSession(session, expectedUser);
  delete session.currentAuthenticationChallenge;
  delete session.currentAuthenticationUserId;

  const headers = new Headers({ 'content-type': 'application/json' });
  await commitSessionCookie(headers, session, env, request);
  return new Response(JSON.stringify({ user: serializeUser(expectedUser) }), {
    headers,
  });
}

function upsertGoogleUser(profile) {
  const existing =
    usersByGoogleId.get(profile.googleId) || usersByEmail.get(profile.email);

  if (existing) {
    existing.googleId = profile.googleId;
    existing.displayName = profile.displayName || existing.displayName;
    existing.photo = profile.photo || existing.photo;
    usersByGoogleId.set(profile.googleId, existing);
    return existing;
  }

  const user = {
    id: crypto.randomUUID(),
    googleId: profile.googleId,
    email: profile.email,
    displayName: profile.displayName,
    photo: profile.photo,
    passkeys: [],
    createdAt: new Date().toISOString(),
  };

  users.set(user.id, user);
  usersByEmail.set(user.email, user);
  usersByGoogleId.set(user.googleId, user);
  return user;
}

function getSessionUser(session) {
  return session.userId ? users.get(session.userId) : null;
}

function establishSession(session, user) {
  session.userId = user.id;
  delete session.pendingUserId;
  delete session.pendingProvider;
}

function findUserForPasskeyAuthentication(session, payload) {
  if (session.pendingUserId) {
    return users.get(session.pendingUserId);
  }

  const email = String(payload.email || '').trim().toLowerCase();
  return email ? usersByEmail.get(email) : null;
}

function serializeUser(user) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    photo: user.photo,
    passkeyCount: user.passkeys.length,
  };
}

function googleConfigured(env) {
  return Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
}

function requirePasskeyAfterGoogle(env) {
  return env.REQUIRE_PASSKEY_AFTER_GOOGLE === 'true';
}

function originFor(request, env) {
  return env.ORIGIN || new URL(request.url).origin;
}

function rpIDFor(request, env) {
  return env.RP_ID || new URL(originFor(request, env)).hostname;
}

function rpNameFor(env) {
  return env.RP_NAME || 'SharmaWeb Sign In';
}

function redirect(location) {
  return new Response(null, { status: 302, headers: { location } });
}

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

async function readSession(request, env) {
  const cookie = parseCookies(request.headers.get('cookie') || '')[
    sessionCookieName
  ];

  if (!cookie) {
    return {};
  }

  const [payload, signature] = cookie.split('.');

  if (!payload || !signature) {
    return {};
  }

  const expectedSignature = await sign(payload, env);

  if (signature !== expectedSignature) {
    return {};
  }

  try {
    return JSON.parse(new TextDecoder().decode(base64urlToBytes(payload)));
  } catch (_error) {
    return {};
  }
}

async function commitSessionCookie(headers, session, env, request) {
  const payload = bytesToBase64url(textEncoder.encode(JSON.stringify(session)));
  const signature = await sign(payload, env);
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';

  headers.append(
    'set-cookie',
    `${sessionCookieName}=${payload}.${signature}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${secure}`,
  );
}

function clearSessionCookie(headers, request) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  headers.append(
    'set-cookie',
    `${sessionCookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`,
  );
}

async function sign(value, env) {
  const secret = env.SESSION_SECRET || 'dev-secret-change-me';
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, textEncoder.encode(value));
  return bytesToBase64url(new Uint8Array(signature));
}

function parseCookies(header) {
  return header.split(';').reduce((cookies, cookie) => {
    const [rawName, ...rawValue] = cookie.trim().split('=');

    if (rawName) {
      cookies[rawName] = rawValue.join('=');
    }

    return cookies;
  }, {});
}

function randomBase64Url(size) {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytesToBase64url(bytes);
}

function bytesToBase64url(bytes) {
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64urlToBytes(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    '=',
  );
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}
