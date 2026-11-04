import { argon2, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(argon2);
export const ARGON = Object.freeze({ memory: 65536, passes: 3, parallelism: 1, tagLength: 32 });
export const token = () => randomBytes(32).toString('base64url');

export function equalText(a, b) {
  // Compare fixed-length digests so differing input lengths do not cause exceptions.
  return timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest());
}

export async function createCredentials(username, password) {
  if (!/^[A-Za-z0-9_.-]{3,64}$/.test(username)) throw new Error('Username must be 3–64 letters, numbers, dots, underscores or hyphens.');
  if (Buffer.byteLength(password) < 15 || Buffer.byteLength(password) > 512) throw new Error('Password must be 15–512 UTF-8 bytes.');
  const salt = randomBytes(16);
  const hash = await derive('argon2id', { ...ARGON, message: password, nonce: salt });
  return { username, algorithm: 'argon2id', parameters: ARGON, salt: salt.toString('hex'), hash: hash.toString('hex') };
}

export function validateCredentials(config) {
  if (!config || !/^[A-Za-z0-9_.-]{3,64}$/.test(config.username ?? '') || config.algorithm !== 'argon2id'
      || !/^[a-f0-9]{32}$/.test(config.salt ?? '') || !/^[a-f0-9]{64}$/.test(config.hash ?? '')
      || Object.entries(ARGON).some(([key, value]) => config.parameters?.[key] !== value)) {
    throw new Error('Invalid credentials configuration. Run setup.mjs with the required Node.js version.');
  }
}

export async function verifyCredentials(config, username, password) {
  // Derive even for an unknown username to avoid a quick username-existence response.
  const candidate = await derive('argon2id', { ...ARGON, message: password, nonce: Buffer.from(config.salt, 'hex') });
  const passwordOK = timingSafeEqual(candidate, Buffer.from(config.hash, 'hex'));
  const usernameOK = equalText(username, config.username);
  return passwordOK && usernameOK;
}
