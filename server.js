const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} = require('@simplewebauthn/server');
require('dotenv').config();

const app = express();
const port = Number(process.env.PORT || 3000);
const origin = process.env.ORIGIN || `http://localhost:${port}`;
const rpID = process.env.RP_ID || new URL(origin).hostname;
const rpName = process.env.RP_NAME || 'SharmaWeb Sign In';
const requirePasskeyAfterGoogle = process.env.REQUIRE_PASSKEY_AFTER_GOOGLE === 'true';

const users = new Map();
const usersByEmail = new Map();
const usersByGoogleId = new Map();
const credentialsById = new Map();

const googleConfigured = Boolean(
  process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET,
);

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: origin.startsWith('https://'),
    },
  }),
);
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((profile, done) => done(null, profile));
passport.deserializeUser((profile, done) => done(null, profile));

if (googleConfigured) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${origin}/auth/google/callback`,
      },
      (_accessToken, _refreshToken, profile, done) => {
        const email = profile.emails?.[0]?.value?.toLowerCase();

        if (!email) {
          return done(new Error('Google account did not provide an email address'));
        }

        done(null, {
          googleId: profile.id,
          email,
          displayName: profile.displayName || email,
          photo: profile.photos?.[0]?.value,
        });
      },
    ),
  );
}

app.use(express.static('public'));

app.get('/auth/google', (req, res, next) => {
  if (!googleConfigured) {
    return res.status(501).json({
      error: 'Google OAuth is not configured',
      requiredEnv: ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'ORIGIN'],
    });
  }

  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account',
  })(req, res, next);
});

app.get(
  '/auth/google/callback',
  googleConfigured
    ? passport.authenticate('google', { failureRedirect: '/?error=google' })
    : (_req, res) => res.redirect('/?error=google_not_configured'),
  (req, res) => {
    const user = upsertGoogleUser(req.user);

    req.session.pendingUserId = user.id;
    req.session.pendingProvider = 'google';
    req.session.userId = undefined;
    req.session.passport = undefined;

    res.redirect('/verify.html');
  },
);

app.get('/api/session', (req, res) => {
  const user = getSessionUser(req);
  const pendingUser = req.session.pendingUserId
    ? users.get(req.session.pendingUserId)
    : null;

  res.json({
    authenticated: Boolean(user),
    googleConfigured,
    rpName,
    requirePasskeyAfterGoogle,
    user: user ? serializeUser(user) : null,
    pending: pendingUser
      ? {
          provider: req.session.pendingProvider,
          user: serializeUser(pendingUser),
          hasPasskeys: pendingUser.passkeys.length > 0,
        }
      : null,
  });
});

app.post('/api/verify/complete', (req, res) => {
  const pendingUser = req.session.pendingUserId
    ? users.get(req.session.pendingUserId)
    : null;

  if (!pendingUser) {
    return res.status(401).json({ error: 'No pending Google sign-in to verify' });
  }

  if (pendingUser.passkeys.length > 0 || requirePasskeyAfterGoogle) {
    return res.status(403).json({
      error: 'Passkey verification is required for this account',
      code: 'passkey_required',
    });
  }

  establishSession(req, pendingUser);
  res.json({ user: serializeUser(pendingUser) });
});

app.post('/api/passkeys/register/options', async (req, res, next) => {
  try {
    const user = getSessionUser(req);

    if (!user) {
      return res.status(401).json({ error: 'Sign in before registering a passkey' });
    }

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(user.id),
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

    req.session.currentRegistrationChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    next(error);
  }
});

app.post('/api/passkeys/register/verify', async (req, res, next) => {
  try {
    const user = getSessionUser(req);

    if (!user) {
      return res.status(401).json({ error: 'Sign in before registering a passkey' });
    }

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: req.session.currentRegistrationChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Passkey registration could not be verified' });
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

    req.session.currentRegistrationChallenge = undefined;
    res.json({ passkeyCount: user.passkeys.length });
  } catch (error) {
    next(error);
  }
});

app.post('/api/passkeys/authenticate/options', async (req, res, next) => {
  try {
    const user = findUserForPasskeyAuthentication(req);

    if (!user) {
      return res.status(404).json({ error: 'No account found for passkey authentication' });
    }

    if (user.passkeys.length === 0) {
      return res.status(400).json({ error: 'This account does not have any passkeys yet' });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: user.passkeys.map((passkey) => ({
        id: passkey.credential.id,
        transports: passkey.credential.transports,
      })),
      userVerification: 'required',
    });

    req.session.currentAuthenticationChallenge = options.challenge;
    req.session.currentAuthenticationUserId = user.id;
    res.json(options);
  } catch (error) {
    next(error);
  }
});

app.post('/api/passkeys/authenticate/verify', async (req, res, next) => {
  try {
    const expectedUser = req.session.currentAuthenticationUserId
      ? users.get(req.session.currentAuthenticationUserId)
      : null;
    const credentialRecord = credentialsById.get(req.body.id);

    if (!expectedUser || !credentialRecord || credentialRecord.userId !== expectedUser.id) {
      return res.status(400).json({ error: 'Passkey does not match the requested account' });
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: req.session.currentAuthenticationChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: credentialRecord.passkey.credential,
      requireUserVerification: true,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Passkey authentication could not be verified' });
    }

    credentialRecord.passkey.credential.counter =
      verification.authenticationInfo.newCounter;

    establishSession(req, expectedUser);
    req.session.currentAuthenticationChallenge = undefined;
    req.session.currentAuthenticationUserId = undefined;

    res.json({ user: serializeUser(expectedUser) });
  } catch (error) {
    next(error);
  }
});

app.post('/api/sign-out', (req, res, next) => {
  req.logout((error) => {
    if (error) {
      return next(error);
    }

    req.session.destroy((destroyError) => {
      if (destroyError) {
        return next(destroyError);
      }

      res.clearCookie('connect.sid');
      res.json({ ok: true });
    });
  });
});

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ error: error.message || 'Unexpected server error' });
});

app.listen(port, () => {
  console.log(`${rpName} listening on ${origin}`);
  console.log(`WebAuthn relying party ID: ${rpID}`);
});

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

function getSessionUser(req) {
  return req.session.userId ? users.get(req.session.userId) : null;
}

function establishSession(req, user) {
  req.session.userId = user.id;
  req.session.pendingUserId = undefined;
  req.session.pendingProvider = undefined;
}

function findUserForPasskeyAuthentication(req) {
  if (req.session.pendingUserId) {
    return users.get(req.session.pendingUserId);
  }

  const email = String(req.body.email || '').trim().toLowerCase();
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
