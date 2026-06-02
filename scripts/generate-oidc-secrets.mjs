import { generateKeyPairSync, randomBytes } from 'node:crypto';

const { privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicExponent: 0x10001,
});
const jwk = privateKey.export({ format: 'jwk' });

jwk.alg = 'RS256';
jwk.use = 'sig';
jwk.kid = `workspace-sso-${randomBytes(4).toString('hex')}`;

console.log('Add these to Cloudflare Variables and Secrets:');
console.log('');
console.log('OIDC_CLIENT_ID=sharmaweb-workspace');
console.log(`OIDC_CLIENT_SECRET=${randomBytes(32).toString('base64url')}`);
console.log(`OIDC_PRIVATE_KEY_JWK=${JSON.stringify(jwk)}`);
console.log(`BOOTSTRAP_CODE=${randomBytes(18).toString('base64url')}`);
console.log('');
console.log('Keep OIDC_CLIENT_SECRET, OIDC_PRIVATE_KEY_JWK, and BOOTSTRAP_CODE as Secrets.');
