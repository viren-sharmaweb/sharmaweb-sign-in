const message = document.querySelector('#message');

let oidcContext = null;

document.addEventListener('DOMContentLoaded', () => {
  void hydratePage();
  bindHomePage();
  bindVerifyPage();
  bindOidcPage();
});

async function hydratePage() {
  if (document.querySelector('#oidc-signin')) {
    oidcContext = await request('/api/oidc/context');
    renderOidcState(oidcContext);
    return;
  }

  const session = await request('/api/session');

  if (document.querySelector('#account')) {
    renderHomeState(session);
  }

  if (document.querySelector('#pending-account')) {
    renderVerifyState(session);
  }
}

function bindHomePage() {
  const passkeyForm = document.querySelector('#passkey-sign-in');
  const registerButton = document.querySelector('#register-passkey');
  const signOutButton = document.querySelector('#sign-out');

  passkeyForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    setMessage('Requesting passkey challenge...');

    try {
      const email = new FormData(passkeyForm).get('email');
      await authenticateWithPasskey({ email });
      setMessage('Signed in with passkey.');
      await hydratePage();
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  registerButton?.addEventListener('click', async () => {
    setMessage('Starting passkey registration...');

    try {
      await registerPasskey();
      setMessage('Passkey registered for this account.');
      await hydratePage();
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  signOutButton?.addEventListener('click', async () => {
    await request('/api/sign-out', { method: 'POST' });
    window.location.href = '/';
  });
}

function bindVerifyPage() {
  const verifyPasskeyButton = document.querySelector('#verify-passkey');
  const completeButton = document.querySelector('#complete-verification');

  verifyPasskeyButton?.addEventListener('click', async () => {
    setMessage('Waiting for your passkey...');

    try {
      await authenticateWithPasskey({});
      window.location.href = '/';
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  completeButton?.addEventListener('click', async () => {
    setMessage('Completing local verification...');

    try {
      await request('/api/verify/complete', { method: 'POST' });
      window.location.href = '/';
    } catch (error) {
      setMessage(error.message, true);
    }
  });
}

function bindOidcPage() {
  const passkeyButton = document.querySelector('#oidc-passkey');
  const bootstrapForm = document.querySelector('#oidc-bootstrap');
  const finishButton = document.querySelector('#oidc-finish');
  const signOutButton = document.querySelector('#oidc-sign-out');

  passkeyButton?.addEventListener('click', async () => {
    setMessage('Glide through your passkey prompt to continue...');

    try {
      const result = await authenticateWithPasskey({});
      redirectIfPresent(result);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  bootstrapForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    setMessage('Creating your protected Workspace session...');

    try {
      const inviteCode = new FormData(bootstrapForm).get('inviteCode') || '';
      await request('/api/oidc/bootstrap', {
        method: 'POST',
        body: JSON.stringify({ inviteCode }),
      });
      setMessage('Now register a passkey for future Workspace sign-ins...');
      await registerPasskey();
      const result = await finishOidcSignIn();
      redirectIfPresent(result);
    } catch (error) {
      setMessage(error.message, true);
      await hydratePage();
    }
  });

  finishButton?.addEventListener('click', async () => {
    setMessage('Finishing Workspace sign-in...');

    try {
      const result = await finishOidcSignIn();
      redirectIfPresent(result);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  signOutButton?.addEventListener('click', async () => {
    await request('/api/sign-out', { method: 'POST' });
    window.location.reload();
  });
}

function renderHomeState(session) {
  const account = document.querySelector('#account');
  const accountDetails = document.querySelector('#account-details');

  if (!session.googleConfigured) {
    setMessage(
      'Google OAuth is not configured yet. Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and ORIGIN to enable it.',
      true,
    );
  }

  if (!session.authenticated) {
    account.classList.add('hidden');
    return;
  }

  account.classList.remove('hidden');
  accountDetails.innerHTML = `
    <div class="account-row">
      ${avatarMarkup(session.user)}
      <div>
        <strong>${escapeHtml(session.user.displayName)}</strong>
        <span>${escapeHtml(session.user.email)}</span>
        <small>${session.user.passkeyCount} passkey(s) registered</small>
      </div>
    </div>
  `;
}

function renderVerifyState(session) {
  const pendingAccount = document.querySelector('#pending-account');
  const verifyPasskeyButton = document.querySelector('#verify-passkey');
  const completeButton = document.querySelector('#complete-verification');

  if (!session.pending) {
    window.location.href = '/';
    return;
  }

  pendingAccount.innerHTML = `
    ${avatarMarkup(session.pending.user)}
    <div>
      <strong>${escapeHtml(session.pending.user.displayName)}</strong>
      <span>${escapeHtml(session.pending.user.email)}</span>
      <small>Provider: ${escapeHtml(session.pending.provider)}</small>
    </div>
  `;

  const passkeyRequired =
    session.pending.hasPasskeys || session.requirePasskeyAfterGoogle;

  verifyPasskeyButton.disabled = !session.pending.hasPasskeys;
  completeButton.disabled = passkeyRequired;

  if (passkeyRequired && session.pending.hasPasskeys) {
    setMessage('This account has passkeys, so passkey verification is required.');
  } else if (passkeyRequired) {
    setMessage('A passkey is required, but this account has no passkeys yet.', true);
  } else {
    setMessage('First-time accounts can complete verification, then register a passkey.');
  }
}

function renderOidcState(context) {
  const account = document.querySelector('#oidc-account');
  const passkeyPanel = document.querySelector('#oidc-passkey-panel');
  const bootstrapPanel = document.querySelector('#oidc-bootstrap-panel');
  const finishPanel = document.querySelector('#oidc-finish-panel');
  const blockedPanel = document.querySelector('#oidc-blocked-panel');
  const codeField = document.querySelector('#bootstrap-code-field');

  if (!context.pending) {
    setMessage('No Workspace sign-in is waiting. Start again from Google.');
    hide(passkeyPanel, bootstrapPanel, finishPanel);
    show(blockedPanel);
    return;
  }

  account.innerHTML = `
    <div class="identity-orb">${escapeHtml((context.loginHint || '?').slice(0, 1))}</div>
    <div>
      <strong>${escapeHtml(context.loginHint || 'Workspace user')}</strong>
      <span>${escapeHtml(context.workspaceDomain || 'Google Workspace')}</span>
    </div>
  `;

  hide(passkeyPanel, bootstrapPanel, finishPanel, blockedPanel);

  if (context.authenticated && context.user?.passkeyCount > 0) {
    show(finishPanel);
    setMessage('You are verified. Continue back to Google Workspace.');
    return;
  }

  if (context.hasPasskeys) {
    show(passkeyPanel);
    setMessage('Use your passkey to continue to Google Workspace.');
    return;
  }

  if (context.canBootstrap) {
    codeField.classList.toggle('hidden', !context.bootstrapRequiresCode);
    show(bootstrapPanel);
    setMessage('Create your first passkey for this Workspace account.');
    return;
  }

  show(blockedPanel);
  setMessage(
    'This account is not enrolled yet. Ask an admin to add it to BOOTSTRAP_EMAILS or enable domain bootstrap.',
    true,
  );
}

async function registerPasskey() {
  ensureWebAuthn();

  const options = await request('/api/passkeys/register/options', {
    method: 'POST',
  });
  const credential = await navigator.credentials.create({
    publicKey: prepareCreationOptions(options),
  });

  if (!credential) {
    throw new Error('No passkey was created');
  }

  return request('/api/passkeys/register/verify', {
    method: 'POST',
    body: JSON.stringify(serializeRegistrationCredential(credential)),
  });
}

async function authenticateWithPasskey(payload) {
  ensureWebAuthn();

  const options = await request('/api/passkeys/authenticate/options', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  const credential = await navigator.credentials.get({
    publicKey: prepareRequestOptions(options),
  });

  if (!credential) {
    throw new Error('No passkey was selected');
  }

  return request('/api/passkeys/authenticate/verify', {
    method: 'POST',
    body: JSON.stringify(serializeAuthenticationCredential(credential)),
  });
}

function finishOidcSignIn() {
  return request('/api/oidc/finish', { method: 'POST' });
}

function prepareCreationOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64urlToBuffer(options.user.id),
    },
    excludeCredentials: options.excludeCredentials?.map((credential) => ({
      ...credential,
      id: base64urlToBuffer(credential.id),
    })),
  };
}

function prepareRequestOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: options.allowCredentials?.map((credential) => ({
      ...credential,
      id: base64urlToBuffer(credential.id),
    })),
  };
}

function serializeRegistrationCredential(credential) {
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      attestationObject: bufferToBase64url(credential.response.attestationObject),
      transports: credential.response.getTransports?.() || [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function serializeAuthenticationCredential(credential) {
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64url(credential.response.authenticatorData),
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      signature: bufferToBase64url(credential.response.signature),
      userHandle: credential.response.userHandle
        ? bufferToBase64url(credential.response.userHandle)
        : undefined,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

async function request(url, options = {}) {
  const response = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    credentials: 'same-origin',
    ...options,
  });
  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(payload.error || payload.error_description || 'Request failed');
  }

  return payload;
}

function ensureWebAuthn() {
  if (!window.PublicKeyCredential) {
    throw new Error('This browser does not support passkeys/WebAuthn');
  }
}

function base64urlToBuffer(input) {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return window
    .btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function setMessage(text, isError = false) {
  if (!message) {
    return;
  }

  message.textContent = text;
  message.classList.toggle('error', isError);
}

function redirectIfPresent(result) {
  if (result?.redirectTo) {
    window.location.href = result.redirectTo;
  }
}

function show(...elements) {
  for (const element of elements) {
    element?.classList.remove('hidden');
  }
}

function hide(...elements) {
  for (const element of elements) {
    element?.classList.add('hidden');
  }
}

function avatarMarkup(user) {
  if (user.photo) {
    return `<img class="avatar" src="${escapeHtml(user.photo)}" alt="" />`;
  }

  return `<div class="avatar fallback">${escapeHtml(user.displayName.slice(0, 1))}</div>`;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
