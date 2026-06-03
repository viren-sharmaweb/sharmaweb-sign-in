import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

const memoryUsers = new Map();
const memoryUsersByEmail = new Map();
const memoryUsersByGoogleId = new Map();
const memoryCredentialsById = new Map();
const sessionCookieName = 'sw_session';
const textEncoder = new TextEncoder();
let signingKeyCache;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const session = await readSession(request, env);

    try {
      if (url.pathname === '/.well-known/openid-configuration') {
        return handleOidcDiscovery(request, env);
      }

      if (url.pathname === '/.well-known/jwks.json') {
        return handleJwks(env);
      }

      if (url.pathname === '/oidc/authorize') {
        return handleOidcAuthorize(request, env, session);
      }

      if (url.pathname === '/oidc/token' && request.method === 'POST') {
        return handleOidcToken(request, env);
      }

      if (url.pathname === '/oidc/userinfo' && request.method === 'GET') {
        return handleOidcUserinfo(request, env);
      }

      if (url.pathname === '/auth/google') {
        return handleGoogleStart(request, env, session);
      }

      if (url.pathname === '/auth/google/callback') {
        return handleGoogleCallback(request, env, session);
      }

      if (url.pathname === '/api/session' && request.method === 'GET') {
        return handleSession(request, env, session);
      }

      if (url.pathname === '/api/oidc/context' && request.method === 'GET') {
        return handleOidcContext(env, session);
      }

      if (url.pathname === '/api/oidc/bootstrap' && request.method === 'POST') {
        return handleOidcBootstrap(request, env, session);
      }

      if (url.pathname === '/api/oidc/finish' && request.method === 'POST') {
        return handleOidcFinish(request, env, session);
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

function handleOidcDiscovery(request, env) {
  const issuer = originFor(request, env);

  return json({
    issuer,
    authorization_endpoint: `${issuer}/oidc/authorize`,
    token_endpoint: `${issuer}/oidc/token`,
    userinfo_endpoint: `${issuer}/oidc/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'email', 'profile'],
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
    ],
    claims_supported: [
      'sub',
      'iss',
      'aud',
      'exp',
      'iat',
      'nonce',
      'email',
      'email_verified',
      'name',
      'picture',
      'hd',
    ],
  });
}

async function handleJwks(env) {
  const { publicJwk } = await getSigningKey(env);
  return json({ keys: [publicJwk] });
}

async function handleOidcAuthorize(request, env, session) {
  if (!oidcConfigured(env)) {
    return htmlError(
      'OIDC is not configured',
      'Add OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URIS, and OIDC_PRIVATE_KEY_JWK in Cloudflare first.',
      501,
    );
  }

  const url = new URL(request.url);
  const clientId = url.searchParams.get('client_id');
  const redirectUri = url.searchParams.get('redirect_uri');
  const responseType = url.searchParams.get('response_type');
  const scope = url.searchParams.get('scope') || 'openid email profile';
  const state = url.searchParams.get('state') || '';
  const nonce = url.searchParams.get('nonce') || '';
  const loginHint = normalizeEmail(
    url.searchParams.get('login_hint') || url.searchParams.get('hd') || '',
  );

  if (responseType !== 'code') {
    return redirectWithError(redirectUri, state, 'unsupported_response_type');
  }

  if (clientId !== env.OIDC_CLIENT_ID) {
    return htmlError('Invalid OIDC client', 'The client_id does not match this identity provider.', 400);
  }

  if (!redirectUri || !allowedRedirectUris(env).includes(redirectUri)) {
    return htmlError(
      'Redirect URI is not allowed',
      'Copy the Redirect URI from Google Workspace into OIDC_REDIRECT_URIS in Cloudflare.',
      400,
    );
  }

  if (!scope.split(/\s+/).includes('openid')) {
    return redirectWithError(redirectUri, state, 'invalid_scope');
  }

  const currentUser = await getSessionUser(env, session);

  session.pendingOidc = {
    clientId,
    redirectUri,
    scope,
    state,
    nonce,
    loginHint,
    createdAt: Date.now(),
  };

  if (currentUser && oidcUserAllowed(env, currentUser.email, loginHint)) {
    if (!adminEmailAllowed(env, currentUser.email)) {
      const redirectTo = await buildOidcRedirect(request, env, session.pendingOidc, currentUser);
      delete session.pendingOidc;
      const headers = new Headers({ location: redirectTo });
      await commitSessionCookie(headers, session, env, request);
      return new Response(null, { status: 302, headers });
    }

    const headers = new Headers({ location: '/signin.html' });
    await commitSessionCookie(headers, session, env, request);
    return new Response(null, { status: 302, headers });
  }

  const headers = new Headers({ location: '/signin.html' });
  await commitSessionCookie(headers, session, env, request);
  return new Response(null, { status: 302, headers });
}

async function handleOidcToken(request, env) {
  if (!oidcConfigured(env)) {
    return oauthError('server_error', 'OIDC is not configured', 501);
  }

  const form = await request.formData();
  const auth = parseBasicAuth(request.headers.get('authorization') || '');
  const clientId = auth?.clientId || form.get('client_id');
  const clientSecret = auth?.clientSecret || form.get('client_secret');

  if (clientId !== env.OIDC_CLIENT_ID || clientSecret !== env.OIDC_CLIENT_SECRET) {
    return oauthError('invalid_client', 'Invalid client credentials', 401);
  }

  if (form.get('grant_type') !== 'authorization_code') {
    return oauthError('unsupported_grant_type', 'Only authorization_code is supported');
  }

  const authCode = await readSignedPayload(String(form.get('code') || ''), env, 'oidc_code');

  if (!authCode) {
    return oauthError('invalid_grant', 'Invalid or expired authorization code');
  }

  const redirectUri = String(form.get('redirect_uri') || '');

  if (authCode.redirectUri !== redirectUri) {
    return oauthError('invalid_grant', 'redirect_uri does not match the authorization request');
  }

  if (authCode.clientId !== clientId) {
    return oauthError('invalid_grant', 'client_id does not match the authorization request');
  }

  const user = await loadUser(env, authCode.userId);

  if (!user) {
    return oauthError('invalid_grant', 'User no longer exists');
  }

  const issuer = issuerFor(env);
  const now = Math.floor(Date.now() / 1000);
  const idToken = await signJwt(
    {
      iss: issuer,
      sub: subjectForUser(env, user),
      aud: clientId,
      exp: now + 300,
      iat: now,
      auth_time: authCode.authTime || now,
      nonce: authCode.nonce || undefined,
      email: user.email,
      email_verified: true,
      name: user.displayName || user.email,
      picture: user.photo || undefined,
      hd: workspaceDomainFor(env) || undefined,
    },
    env,
  );
  const accessToken = await createSignedPayload(
    {
      type: 'oidc_access_token',
      userId: user.id,
      clientId,
      exp: Date.now() + 300000,
    },
    env,
  );

  return tokenJson({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 300,
    scope: authCode.scope || 'openid email profile',
    id_token: idToken,
  });
}

async function handleOidcUserinfo(request, env) {
  const authorization = request.headers.get('authorization') || '';
  const token = authorization.startsWith('Bearer ')
    ? authorization.slice('Bearer '.length)
    : '';
  const accessToken = await readSignedPayload(token, env, 'oidc_access_token');

  if (!accessToken) {
    return oauthError('invalid_token', 'Missing or invalid access token', 401);
  }

  const user = await loadUser(env, accessToken.userId);

  if (!user) {
    return oauthError('invalid_token', 'User no longer exists', 401);
  }

  return json(oidcClaimsForUser(user, env));
}

async function handleOidcContext(env, session) {
  const pendingOidc = session.pendingOidc;
  const currentUser = await getSessionUser(env, session);

  if (!pendingOidc) {
    return json({ pending: false, authenticated: Boolean(currentUser) });
  }

  const hint = normalizeEmail(pendingOidc.loginHint || currentUser?.email || '');
  const user = hint ? await findUserByEmail(env, hint) : null;
  const bootstrapAllowed = hint ? bootstrapAllowedForEmail(env, hint) : false;
  const activeUser = currentUser || user;

  return json({
    pending: true,
    authenticated: Boolean(currentUser),
    loginHint: hint,
    workspaceDomain: workspaceDomainFor(env),
    user: currentUser ? serializeUser(currentUser) : null,
    hasPasskeys: Boolean(user?.passkeys.length),
    canBootstrap: !user && bootstrapAllowed,
    bootstrapRequiresCode: Boolean(env.BOOTSTRAP_CODE),
    passkeyRequired: Boolean(user?.passkeys.length),
    isAdmin: Boolean(activeUser && adminEmailAllowed(env, activeUser.email)),
    admin: adminContextFor(env),
  });
}

async function handleOidcBootstrap(request, env, session) {
  const pendingOidc = session.pendingOidc;

  if (!pendingOidc) {
    return json({ error: 'No pending Workspace sign-in' }, 401);
  }

  const email = normalizeEmail(pendingOidc.loginHint || '');

  if (!email) {
    return json({ error: 'Google did not provide a login_hint for this sign-in' }, 400);
  }

  if (!bootstrapAllowedForEmail(env, email)) {
    return json({ error: 'This email is not allowed to bootstrap a Workspace passkey' }, 403);
  }

  const payload = await request.json().catch(() => ({}));

  if (env.BOOTSTRAP_CODE && payload.inviteCode !== env.BOOTSTRAP_CODE) {
    return json({ error: 'The bootstrap code is incorrect' }, 403);
  }

  let user = await findUserByEmail(env, email);

  if (!user) {
    user = {
      id: crypto.randomUUID(),
      email,
      displayName: email,
      photo: undefined,
      passkeys: [],
      createdAt: new Date().toISOString(),
    };
    await saveUser(env, user);
  }

  establishSession(session, user);
  session.pendingOidc = pendingOidc;

  const headers = new Headers({ 'content-type': 'application/json' });
  await commitSessionCookie(headers, session, env, request);
  return new Response(JSON.stringify({ user: serializeUser(user) }), { headers });
}

async function handleOidcFinish(request, env, session) {
  const pendingOidc = session.pendingOidc;
  const user = await getSessionUser(env, session);

  if (!pendingOidc || !user) {
    return json({ error: 'No pending Workspace sign-in to finish' }, 401);
  }

  if (!oidcUserAllowed(env, user.email, pendingOidc.loginHint)) {
    return json({ error: 'Signed-in user does not match this Workspace sign-in' }, 403);
  }

  if (user.passkeys.length === 0 && env.ALLOW_OIDC_WITHOUT_PASSKEY !== 'true') {
    return json({ error: 'Register a passkey before finishing Workspace sign-in' }, 403);
  }

  const redirectTo = await buildOidcRedirect(request, env, pendingOidc, user);
  delete session.pendingOidc;
  const headers = new Headers({ 'content-type': 'application/json' });
  await commitSessionCookie(headers, session, env, request);
  return new Response(JSON.stringify({ redirectTo }), { headers });
}

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
  const email = normalizeEmail(profile.email || '');

  if (!email) {
    return redirect('/?error=google_email');
  }

  const user = await upsertGoogleUser(env, {
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

async function handleSession(request, env, session) {
  const user = await getSessionUser(env, session);
  const pendingUser = session.pendingUserId
    ? await loadUser(env, session.pendingUserId)
    : null;

  return json({
    authenticated: Boolean(user),
    googleConfigured: googleConfigured(env),
    oidcConfigured: oidcConfigured(env),
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
    ? await loadUser(env, session.pendingUserId)
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
  const user = await getSessionUser(env, session);

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
  const user = await getSessionUser(env, session);

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

  const credential = normalizeCredential(verification.registrationInfo.credential);

  if (!(await findCredential(env, credential.id))) {
    const passkey = {
      credential,
      createdAt: new Date().toISOString(),
    };

    user.passkeys.push(passkey);
    await saveUser(env, user);
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
  const user = await findUserForPasskeyAuthentication(env, session, payload);

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
    ? await loadUser(env, session.currentAuthenticationUserId)
    : null;
  const credentialRecord = await findCredential(env, body.id);

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
  await saveUser(env, expectedUser);
  establishSession(session, expectedUser);
  delete session.currentAuthenticationChallenge;
  delete session.currentAuthenticationUserId;

  if (session.pendingOidc) {
    if (adminEmailAllowed(env, expectedUser.email)) {
      const headers = new Headers({ 'content-type': 'application/json' });
      await commitSessionCookie(headers, session, env, request);
      return new Response(
        JSON.stringify({ user: serializeUser(expectedUser), adminReview: true }),
        { headers },
      );
    }

    const redirectTo = await buildOidcRedirect(request, env, session.pendingOidc, expectedUser);
    delete session.pendingOidc;
    const headers = new Headers({ 'content-type': 'application/json' });
    await commitSessionCookie(headers, session, env, request);
    return new Response(JSON.stringify({ user: serializeUser(expectedUser), redirectTo }), {
      headers,
    });
  }

  const headers = new Headers({ 'content-type': 'application/json' });
  await commitSessionCookie(headers, session, env, request);
  return new Response(JSON.stringify({ user: serializeUser(expectedUser) }), {
    headers,
  });
}

async function buildOidcRedirect(request, env, pendingOidc, user) {
  const code = await createSignedPayload(
    {
      type: 'oidc_code',
      userId: user.id,
      clientId: pendingOidc.clientId,
      redirectUri: pendingOidc.redirectUri,
      scope: pendingOidc.scope,
      nonce: pendingOidc.nonce,
      authTime: Math.floor(Date.now() / 1000),
      exp: Date.now() + 300000,
    },
    env,
  );
  const redirectUrl = new URL(pendingOidc.redirectUri);
  redirectUrl.searchParams.set('code', code);

  if (pendingOidc.state) {
    redirectUrl.searchParams.set('state', pendingOidc.state);
  }

  return redirectUrl.toString();
}

async function upsertGoogleUser(env, profile) {
  const existing =
    (profile.googleId ? await findUserByGoogleId(env, profile.googleId) : null) ||
    (await findUserByEmail(env, profile.email));

  if (existing) {
    existing.googleId = profile.googleId;
    existing.displayName = profile.displayName || existing.displayName;
    existing.photo = profile.photo || existing.photo;
    await saveUser(env, existing);
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

  await saveUser(env, user);
  return user;
}

async function getSessionUser(env, session) {
  return session.userId ? loadUser(env, session.userId) : null;
}

function establishSession(session, user) {
  session.userId = user.id;
  delete session.pendingUserId;
  delete session.pendingProvider;
}

async function findUserForPasskeyAuthentication(env, session, payload) {
  if (session.pendingUserId) {
    return loadUser(env, session.pendingUserId);
  }

  if (session.pendingOidc?.loginHint) {
    return findUserByEmail(env, session.pendingOidc.loginHint);
  }

  const email = normalizeEmail(payload.email || '');
  return email ? findUserByEmail(env, email) : null;
}

async function loadUser(env, userId) {
  if (!userId) {
    return null;
  }

  if (env.AUTH_STORE) {
    const stored = await env.AUTH_STORE.get(`user:${userId}`, 'json');
    return stored ? deserializeUser(stored) : null;
  }

  return memoryUsers.get(userId) || null;
}

async function findUserByEmail(env, email) {
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail) {
    return null;
  }

  if (env.AUTH_STORE) {
    const userId = await env.AUTH_STORE.get(`email:${normalizedEmail}`);
    return userId ? loadUser(env, userId) : null;
  }

  return memoryUsersByEmail.get(normalizedEmail) || null;
}

async function findUserByGoogleId(env, googleId) {
  if (!googleId) {
    return null;
  }

  if (env.AUTH_STORE) {
    const userId = await env.AUTH_STORE.get(`google:${googleId}`);
    return userId ? loadUser(env, userId) : null;
  }

  return memoryUsersByGoogleId.get(googleId) || null;
}

async function findCredential(env, credentialId) {
  if (!credentialId) {
    return null;
  }

  if (env.AUTH_STORE) {
    const userId = await env.AUTH_STORE.get(`credential:${credentialId}`);
    const user = userId ? await loadUser(env, userId) : null;
    const passkey = user?.passkeys.find(
      (candidate) => candidate.credential.id === credentialId,
    );
    return user && passkey ? { userId: user.id, passkey } : null;
  }

  return memoryCredentialsById.get(credentialId) || null;
}

async function saveUser(env, user) {
  const normalizedUser = {
    ...user,
    email: normalizeEmail(user.email),
    passkeys: user.passkeys.map((passkey) => ({
      ...passkey,
      credential: normalizeCredential(passkey.credential),
    })),
  };

  if (env.AUTH_STORE) {
    await env.AUTH_STORE.put(
      `user:${normalizedUser.id}`,
      JSON.stringify(serializeUserForStorage(normalizedUser)),
    );
    await env.AUTH_STORE.put(`email:${normalizedUser.email}`, normalizedUser.id);

    if (normalizedUser.googleId) {
      await env.AUTH_STORE.put(`google:${normalizedUser.googleId}`, normalizedUser.id);
    }

    await Promise.all(
      normalizedUser.passkeys.map((passkey) =>
        env.AUTH_STORE.put(`credential:${passkey.credential.id}`, normalizedUser.id),
      ),
    );
    return normalizedUser;
  }

  memoryUsers.set(normalizedUser.id, normalizedUser);
  memoryUsersByEmail.set(normalizedUser.email, normalizedUser);

  if (normalizedUser.googleId) {
    memoryUsersByGoogleId.set(normalizedUser.googleId, normalizedUser);
  }

  for (const passkey of normalizedUser.passkeys) {
    memoryCredentialsById.set(passkey.credential.id, {
      userId: normalizedUser.id,
      passkey,
    });
  }

  return normalizedUser;
}

function serializeUserForStorage(user) {
  return {
    ...user,
    passkeys: user.passkeys.map((passkey) => ({
      ...passkey,
      credential: {
        ...passkey.credential,
        publicKey: bytesToBase64url(toUint8Array(passkey.credential.publicKey)),
      },
    })),
  };
}

function deserializeUser(user) {
  return {
    ...user,
    passkeys: (user.passkeys || []).map((passkey) => ({
      ...passkey,
      credential: {
        ...passkey.credential,
        publicKey: base64urlToBytes(passkey.credential.publicKey),
      },
    })),
  };
}

function normalizeCredential(credential) {
  return {
    id: credential.id,
    publicKey: toUint8Array(credential.publicKey),
    counter: credential.counter || 0,
    transports: credential.transports || [],
  };
}

function toUint8Array(value) {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  if (Array.isArray(value)) {
    return new Uint8Array(value);
  }

  if (typeof value === 'string') {
    return base64urlToBytes(value);
  }

  return new Uint8Array(value || []);
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

function oidcClaimsForUser(user, env) {
  return {
    sub: subjectForUser(env, user),
    email: user.email,
    email_verified: true,
    name: user.displayName || user.email,
    picture: user.photo || undefined,
    hd: workspaceDomainFor(env) || undefined,
  };
}

function subjectForUser(env, user) {
  return env.OIDC_SUB_CLAIM === 'id' ? user.id : user.email;
}

function oidcUserAllowed(env, userEmail, loginHint) {
  const normalizedUserEmail = normalizeEmail(userEmail);
  const normalizedLoginHint = normalizeEmail(loginHint || '');
  const workspaceDomain = workspaceDomainFor(env);

  if (!normalizedUserEmail) {
    return false;
  }

  if (normalizedLoginHint && normalizedLoginHint !== normalizedUserEmail) {
    return false;
  }

  return !workspaceDomain || normalizedUserEmail.endsWith(`@${workspaceDomain}`);
}

function bootstrapAllowedForEmail(env, email) {
  const normalizedEmail = normalizeEmail(email);
  const allowedEmails = csv(env.BOOTSTRAP_EMAILS).map(normalizeEmail);
  const workspaceDomain = workspaceDomainFor(env);

  if (!normalizedEmail) {
    return false;
  }

  if (allowedEmails.includes(normalizedEmail)) {
    return true;
  }

  if (env.ALLOW_DOMAIN_BOOTSTRAP === 'true' && workspaceDomain) {
    return normalizedEmail.endsWith(`@${workspaceDomain}`);
  }

  return false;
}

function adminEmailAllowed(env, email) {
  const normalizedEmail = normalizeEmail(email);
  return Boolean(normalizedEmail && csv(env.ADMIN_EMAILS).map(normalizeEmail).includes(normalizedEmail));
}

function adminContextFor(env) {
  return {
    adminEmails: csv(env.ADMIN_EMAILS).map(normalizeEmail),
    bootstrapEmails: csv(env.BOOTSTRAP_EMAILS).map(normalizeEmail),
    allowDomainBootstrap: env.ALLOW_DOMAIN_BOOTSTRAP === 'true',
    allowWithoutPasskey: env.ALLOW_OIDC_WITHOUT_PASSKEY === 'true',
    requirePasskeyAfterGoogle: env.REQUIRE_PASSKEY_AFTER_GOOGLE === 'true',
    workspaceDomain: workspaceDomainFor(env),
    theme: {
      name: env.RP_NAME || 'SharmaWeb Sign In',
      accent: env.THEME_ACCENT || 'Pastel violet',
    },
  };
}

function oidcConfigured(env) {
  return Boolean(env.OIDC_CLIENT_ID && env.OIDC_CLIENT_SECRET && env.OIDC_REDIRECT_URIS);
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

function issuerFor(env) {
  return env.ORIGIN || 'https://login.sharmaweb.com';
}

function rpIDFor(request, env) {
  return env.RP_ID || new URL(originFor(request, env)).hostname;
}

function rpNameFor(env) {
  return env.RP_NAME || 'SharmaWeb Sign In';
}

function workspaceDomainFor(env) {
  return String(env.WORKSPACE_DOMAIN || '').trim().toLowerCase();
}

function allowedRedirectUris(env) {
  return csv(env.OIDC_REDIRECT_URIS);
}

function csv(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function parseBasicAuth(header) {
  if (!header.startsWith('Basic ')) {
    return null;
  }

  const decoded = new TextDecoder().decode(base64ToBytes(header.slice('Basic '.length)));
  const separatorIndex = decoded.indexOf(':');

  if (separatorIndex === -1) {
    return null;
  }

  return {
    clientId: decoded.slice(0, separatorIndex),
    clientSecret: decoded.slice(separatorIndex + 1),
  };
}

function redirect(location) {
  return new Response(null, { status: 302, headers: { location } });
}

function redirectWithError(redirectUri, state, error) {
  if (!redirectUri) {
    return oauthError(error, error, 400);
  }

  const url = new URL(redirectUri);
  url.searchParams.set('error', error);

  if (state) {
    url.searchParams.set('state', state);
  }

  return redirect(url.toString());
}

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function oauthError(error, description, status = 400) {
  return json({ error, error_description: description }, status);
}

function tokenJson(payload) {
  return new Response(JSON.stringify(payload), {
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      pragma: 'no-cache',
    },
  });
}

function htmlError(title, message, status = 400) {
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="/styles.css"></head><body><main class="shell"><section class="card"><p class="eyebrow">Configuration needed</p><h1>${escapeHtml(title)}</h1><p class="muted">${escapeHtml(message)}</p></section></main></body></html>`;
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}

async function readSession(request, env) {
  const cookie = parseCookies(request.headers.get('cookie') || '')[
    sessionCookieName
  ];

  if (!cookie) {
    return {};
  }

  return (await readSignedPayload(cookie, env, 'session')) || {};
}

async function commitSessionCookie(headers, session, env, request) {
  const payload = await createSignedPayload({ type: 'session', ...session }, env);
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';

  headers.append(
    'set-cookie',
    `${sessionCookieName}=${payload}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${secure}`,
  );
}

function clearSessionCookie(headers, request) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  headers.append(
    'set-cookie',
    `${sessionCookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`,
  );
}

async function createSignedPayload(payload, env) {
  const body = bytesToBase64url(textEncoder.encode(JSON.stringify(payload)));
  const signature = await signHmac(body, env);
  return `${body}.${signature}`;
}

async function readSignedPayload(value, env, expectedType) {
  const [body, signature] = String(value || '').split('.');

  if (!body || !signature) {
    return null;
  }

  const expectedSignature = await signHmac(body, env);

  if (signature !== expectedSignature) {
    return null;
  }

  try {
    const payload = JSON.parse(new TextDecoder().decode(base64urlToBytes(body)));

    if (expectedType && payload.type !== expectedType) {
      return null;
    }

    if (payload.exp && Date.now() > payload.exp) {
      return null;
    }

    return payload;
  } catch (_error) {
    return null;
  }
}

async function signHmac(value, env) {
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

async function signJwt(payload, env) {
  const { privateKey, publicJwk } = await getSigningKey(env);
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: publicJwk.kid,
  };
  const encodedHeader = bytesToBase64url(textEncoder.encode(JSON.stringify(header)));
  const encodedPayload = bytesToBase64url(textEncoder.encode(JSON.stringify(stripUndefined(payload))));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    textEncoder.encode(signingInput),
  );

  return `${signingInput}.${bytesToBase64url(new Uint8Array(signature))}`;
}

async function getSigningKey(env) {
  const cacheKey = env.OIDC_PRIVATE_KEY_JWK || '__ephemeral__';

  if (signingKeyCache?.cacheKey === cacheKey) {
    return signingKeyCache;
  }

  if (env.OIDC_PRIVATE_KEY_JWK) {
    const jwk = JSON.parse(env.OIDC_PRIVATE_KEY_JWK);
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const publicJwk = publicJwkFromPrivate(jwk);
    signingKeyCache = { cacheKey, privateKey, publicJwk };
    return signingKeyCache;
  }

  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';
  publicJwk.kid = 'dev-ephemeral';
  signingKeyCache = {
    cacheKey,
    privateKey: keyPair.privateKey,
    publicJwk,
  };
  return signingKeyCache;
}

function publicJwkFromPrivate(jwk) {
  return {
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
    alg: jwk.alg || 'RS256',
    use: 'sig',
    kid: jwk.kid || 'workspace-sso',
  };
}

function stripUndefined(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([_key, entryValue]) => entryValue !== undefined),
  );
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
  return base64ToBytes(padded);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
