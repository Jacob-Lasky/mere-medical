import { FormEvent, useEffect, useState } from 'react';
import { useConfig } from '../../../app/providers/AppConfigProvider';

async function authRequest(path: string, body?: Record<string, string>) {
  const response = await fetch(`/api/v1/auth/${path}`, {
    method: body ? 'POST' : 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    ...(body
      ? {
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        }
      : {}),
  });
  if (!response.ok) {
    if (response.status === 401 && path === 'session') return null;
    if (response.status === 401)
      throw new Error('Invalid credentials. Please try again.');
    if (response.status === 429)
      throw new Error('Too many attempts. Please try again in a minute.');
    throw new Error('Could not update your server account. Please try again.');
  }
  return response.status === 204 ? null : response.json();
}

export function ServerAccountSettingsGroup() {
  const config = useConfig();
  return config.SERVER_ACCOUNTS_ENABLED ? <ServerAccountForm /> : null;
}

function ServerAccountForm() {
  const [setupRequired, setSetupRequired] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [setupToken, setSetupToken] = useState('');
  const [signedInAs, setSignedInAs] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    Promise.all([authRequest('status'), authRequest('session')])
      .then(([status, user]) => {
        if (!cancelled) {
          setSetupRequired(status.setupRequired);
          setSignedInAs(user?.username ?? null);
        }
      })
      .catch(() => {
        if (!cancelled)
          setError('Could not reach the server. Reload to try again.');
      })
      .finally(() => {
        if (!cancelled) setBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      if (setupRequired) {
        await authRequest('setup', { username, password, setupToken });
        setSetupRequired(false);
        setSetupToken('');
      }
      await authRequest('sign-in', { username, password });
      const user = await authRequest('session');
      if (!user) throw new Error('Session unavailable. Please sign in again.');
      setSignedInAs(user.username);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Sign-in failed.');
    } finally {
      setPassword('');
      setSetupToken('');
      setBusy(false);
    }
  }

  async function signOut() {
    setBusy(true);
    setError('');
    try {
      await authRequest('sign-out', {});
      setSignedInAs(null);
    } catch {
      setError('Could not sign out. Please try again.');
    } finally {
      setBusy(false);
    }
  }

  const inputClass =
    'mt-1 block w-full rounded-md border-gray-300 bg-white text-gray-900 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100';
  const buttonClass =
    'rounded-md bg-primary-600 px-4 py-2 text-white disabled:opacity-50';
  return (
    <section aria-labelledby="server-account-heading">
      <h1 id="server-account-heading" className="py-6 text-xl font-extrabold">
        Server Account
      </h1>
      <p className="mb-4 text-sm">
        An optional account for server features. Your medical records stay in
        this browser. Signing out leaves your local records available.
      </p>
      {error && (
        <p role="alert" className="mb-4 text-red-700 dark:text-red-300">
          {error}
        </p>
      )}
      {signedInAs ? (
        <div className="flex items-center gap-4">
          <p role="status">Signed in as {signedInAs}</p>
          <button className={buttonClass} disabled={busy} onClick={signOut}>
            Sign out
          </button>
        </div>
      ) : (
        <form
          onSubmit={submit}
          className="max-w-sm space-y-4"
          aria-label={
            setupRequired ? 'Create server account' : 'Sign in to server'
          }
        >
          <label className="block text-sm">
            Username
            <input
              className={inputClass}
              name="username"
              autoComplete="username"
              required
              minLength={3}
              maxLength={64}
              pattern={'[a-zA-Z0-9][a-zA-Z0-9_\\-]{2,63}'}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
          </label>
          <label className="block text-sm">
            Password (15–128 characters)
            <input
              className={inputClass}
              name="password"
              type="password"
              autoComplete={setupRequired ? 'new-password' : 'current-password'}
              required
              minLength={15}
              maxLength={128}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          {setupRequired && (
            <label className="block text-sm">
              Setup token from your server administrator
              <input
                className={inputClass}
                name="setupToken"
                type="password"
                autoComplete="off"
                required
                minLength={32}
                maxLength={512}
                value={setupToken}
                onChange={(event) => setSetupToken(event.target.value)}
              />
            </label>
          )}
          <button className={buttonClass} type="submit" disabled={busy}>
            {busy
              ? 'Connecting…'
              : setupRequired
                ? 'Create account and sign in'
                : 'Sign in'}
          </button>
        </form>
      )}
    </section>
  );
}
