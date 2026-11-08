export interface AuthConfig {
  path: string;
  origin: string;
  secure: boolean;
  setupToken: string;
}

export const SETUP_TOKEN_MIN_LENGTH = 32;
export const SETUP_TOKEN_MAX_LENGTH = 512;

/** No database is opened and no auth routes are installed unless opted in. */
export function authConfig(
  env: Record<string, string | undefined>,
): AuthConfig | undefined {
  if (!env.MERE_AUTH_DB_PATH) return undefined;
  const url = new URL(env.PUBLIC_URL || '');
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (
    (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) ||
    url.username ||
    url.password
  ) {
    throw new Error(
      'Server accounts require an HTTPS PUBLIC_URL (HTTP is allowed on loopback).',
    );
  }
  if (
    !env.MERE_AUTH_SETUP_TOKEN ||
    env.MERE_AUTH_SETUP_TOKEN.length < SETUP_TOKEN_MIN_LENGTH ||
    env.MERE_AUTH_SETUP_TOKEN.length > SETUP_TOKEN_MAX_LENGTH
  ) {
    throw new Error(
      'Server accounts require MERE_AUTH_SETUP_TOKEN with 32–512 characters.',
    );
  }
  return {
    path: env.MERE_AUTH_DB_PATH,
    origin: url.origin,
    secure: url.protocol === 'https:',
    setupToken: env.MERE_AUTH_SETUP_TOKEN,
  };
}
