import { randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { createCredentials } from './auth.mjs';

try {
  const username = process.argv[2] ?? 'defenders';
  const password = randomBytes(24).toString('base64url');
  const config = await createCredentials(username, password);
  await writeFile(new URL('./.auth-config.json', import.meta.url), JSON.stringify(config, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(`Account created. Store these credentials privately.\nUsername: ${username}\nPassword: ${password}\n\nOnly the salted Argon2id hash was saved; the password is displayed once.`);
} catch (error) {
  console.error(error.code === 'EEXIST'
    ? 'An account already exists. Setup will not overwrite it. See README.md for password rotation.'
    : `Setup failed: ${error.message}`);
  process.exitCode = 1;
}
