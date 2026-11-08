import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useConfig } from '../../../app/providers/AppConfigProvider';
import { ServerAccountSettingsGroup } from './ServerAccountSettingsGroup';

jest.mock('../../../app/providers/AppConfigProvider', () => ({
  useConfig: jest.fn(),
}));

describe('ServerAccountSettingsGroup', () => {
  const originalFetch = global.fetch;
  let fetcher: jest.Mock;
  const reply = (body: unknown, status = 200) => ({
    ok: status < 400,
    status,
    json: async () => body,
  });

  beforeEach(() => {
    jest.mocked(useConfig).mockReturnValue({ SERVER_ACCOUNTS_ENABLED: true });
    fetcher = jest
      .fn()
      .mockImplementation(async (path: string) =>
        path.endsWith('status')
          ? reply({ setupRequired: false })
          : reply(null, 401),
      );
    global.fetch = fetcher;
  });
  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('renders nothing and makes no auth calls when accounts are disabled', () => {
    jest.mocked(useConfig).mockReturnValue({});
    const { container } = render(<ServerAccountSettingsGroup />);
    expect(container.innerHTML).toBe('');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('rejects invalid usernames with browser form validation', async () => {
    render(<ServerAccountSettingsGroup />);
    const input = (await screen.findByLabelText(
      'Username',
    )) as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'invalid!' } });
    expect(input.checkValidity()).toBe(false);
    fireEvent.change(input, { target: { value: 'test-user' } });
    expect(input.checkValidity()).toBe(true);
  });

  it('signs in and signs out without persisting the password', async () => {
    render(<ServerAccountSettingsGroup />);
    await waitFor(() =>
      expect(
        (screen.getByRole('button', { name: 'Sign in' }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    fireEvent.change(screen.getByLabelText('Username'), {
      target: { value: 'test-user' },
    });
    fireEvent.change(screen.getByLabelText(/Password/), {
      target: { value: 'synthetic test password' },
    });
    fetcher
      .mockResolvedValueOnce(reply(null, 204))
      .mockResolvedValueOnce(reply({ username: 'test-user' }));
    fireEvent.submit(screen.getByRole('form'));
    await screen.findByText('Signed in as test-user');
    expect(fetcher).toHaveBeenCalledWith(
      '/api/v1/auth/sign-in',
      expect.objectContaining({
        credentials: 'same-origin',
        cache: 'no-store',
      }),
    );
    fetcher.mockResolvedValueOnce(reply(null, 204));
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await screen.findByRole('button', { name: 'Sign in' });
    expect((screen.getByLabelText(/Password/) as HTMLInputElement).value).toBe(
      '',
    );
  });

  it('shows setup only when the server has no accounts', async () => {
    fetcher
      .mockResolvedValueOnce(reply({ setupRequired: true }))
      .mockResolvedValueOnce(reply(null, 401));
    render(<ServerAccountSettingsGroup />);
    await screen.findByLabelText('Setup token from your server administrator');
    fireEvent.change(screen.getByLabelText('Username'), {
      target: { value: 'test-user' },
    });
    fireEvent.change(screen.getByLabelText(/Password/), {
      target: { value: 'synthetic test password' },
    });
    fireEvent.change(screen.getByLabelText(/Setup token/), {
      target: { value: 'synthetic-setup-token-for-tests-only' },
    });
    fetcher
      .mockResolvedValueOnce(reply({ id: 'user-id' }, 201))
      .mockResolvedValueOnce(reply(null, 204))
      .mockResolvedValueOnce(reply({ username: 'test-user' }));
    fireEvent.submit(screen.getByRole('form'));
    await screen.findByText('Signed in as test-user');
    expect(fetcher).toHaveBeenCalledWith(
      '/api/v1/auth/setup',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('reports invalid credentials and clears the password', async () => {
    render(<ServerAccountSettingsGroup />);
    await waitFor(() =>
      expect(
        (screen.getByRole('button', { name: 'Sign in' }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    fireEvent.change(screen.getByLabelText(/Password/), {
      target: { value: 'synthetic test password' },
    });
    fetcher.mockResolvedValueOnce(reply(null, 401));
    fireEvent.submit(screen.getByRole('form'));
    expect((await screen.findByRole('alert')).textContent).toContain(
      'Invalid credentials',
    );
    expect((screen.getByLabelText(/Password/) as HTMLInputElement).value).toBe(
      '',
    );
  });

  it('keeps sign-out available after a network failure', async () => {
    fetcher
      .mockResolvedValueOnce(reply({ setupRequired: false }))
      .mockResolvedValueOnce(reply({ username: 'test-user' }));
    render(<ServerAccountSettingsGroup />);
    await screen.findByText('Signed in as test-user');
    fetcher.mockRejectedValueOnce(new Error('offline'));
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect((await screen.findByRole('alert')).textContent).toContain(
      'Could not sign out',
    );
    expect(
      (screen.getByRole('button', { name: 'Sign out' }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
  });
});
