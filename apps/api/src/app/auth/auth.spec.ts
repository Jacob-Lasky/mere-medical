import {
  Controller,
  Get,
  INestApplication,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import request from 'supertest';
import { authConfig, AuthConfig } from './auth.config';
import { AuthModule } from './auth.module';
import {
  AuthService,
  SESSION_IDLE_TIME,
  SESSION_LIFETIME,
} from './auth.service';
import { AuthenticatedRequest, SessionGuard } from './session.guard';

const origin = 'https://mere.example';
const setupToken = 'synthetic-setup-token-for-tests-only';
const account = {
  username: 'test-user',
  password: 'synthetic password for tests',
};

@Controller('guarded')
@UseGuards(SessionGuard)
class GuardedController {
  @Get()
  get(@Req() request: AuthenticatedRequest) {
    return request.serverUser;
  }
  @Post()
  post(@Req() request: AuthenticatedRequest) {
    return request.serverUser;
  }
}

describe('optional server accounts', () => {
  let app: INestApplication;
  let dir: string;
  let config: AuthConfig;

  async function start() {
    const module = await Test.createTestingModule({
      imports: [
        AuthModule.register(config),
        ThrottlerModule.forRoot([{ name: 'short', ttl: 1000, limit: 30 }]),
      ],
      controllers: [GuardedController],
      providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }],
    }).compile();
    app = module.createNestApplication({ bodyParser: false });
    app.setGlobalPrefix('api');
    await app.init();
  }

  const post = (path: string, body: object) =>
    request(app.getHttpServer())
      .post(`/api/v1/auth/${path}`)
      .set('Origin', origin)
      .send(body);
  const session = (cookie?: string) => {
    const call = request(app.getHttpServer()).get('/api/v1/auth/session');
    return cookie ? call.set('Cookie', cookie) : call;
  };
  async function createAccount() {
    return post('setup', { ...account, setupToken }).expect(201);
  }
  async function signIn() {
    const result = await post('sign-in', account).expect(204);
    return (result.headers['set-cookie'] as unknown as string[])[0].split(
      ';',
    )[0];
  }

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'mere-auth-'));
    config = {
      path: join(dir, 'accounts.db'),
      origin,
      secure: true,
      setupToken,
    };
    await start();
  });
  afterEach(async () => {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('leaves accounts disabled by default and rejects insecure or incomplete opt-in', () => {
    expect(authConfig({})).toBeUndefined();
    for (const length of [31, 513]) {
      expect(() =>
        authConfig({
          MERE_AUTH_DB_PATH: config.path,
          PUBLIC_URL: origin,
          MERE_AUTH_SETUP_TOKEN: 's'.repeat(length),
        }),
      ).toThrow();
    }
    expect(
      authConfig({
        MERE_AUTH_DB_PATH: config.path,
        PUBLIC_URL: origin,
        MERE_AUTH_SETUP_TOKEN: 's'.repeat(512),
      })?.setupToken,
    ).toHaveLength(512);
    expect(() => authConfig({ MERE_AUTH_DB_PATH: config.path })).toThrow();
    expect(() =>
      authConfig({
        MERE_AUTH_DB_PATH: config.path,
        PUBLIC_URL: 'http://mere.example',
        MERE_AUTH_SETUP_TOKEN: setupToken,
      }),
    ).toThrow();
    expect(() =>
      authConfig({ MERE_AUTH_DB_PATH: config.path, PUBLIC_URL: origin }),
    ).toThrow();
    expect(
      authConfig({
        MERE_AUTH_DB_PATH: config.path,
        PUBLIC_URL: 'http://localhost:8080',
        MERE_AUTH_SETUP_TOKEN: setupToken,
      })?.secure,
    ).toBe(false);
  });

  it('with no accounts, exposes setup status but refuses guarded routes and sign-in', async () => {
    const status = await request(app.getHttpServer())
      .get('/api/v1/auth/status')
      .expect(200);
    expect(status.body).toEqual({ setupRequired: true });
    expect(status.headers['cache-control']).toBe('no-store');
    await session().expect(401);
    await request(app.getHttpServer()).get('/api/guarded').expect(401);
    await post('sign-in', account).expect(401);
  });

  it('requires the setup token and validates request bodies without disclosing hashes', async () => {
    await post('setup', { ...account, setupToken: 'x'.repeat(32) }).expect(401);
    await post('setup', { ...account, password: 'short', setupToken }).expect(
      400,
    );
    await post('setup', { username: {}, password: [], setupToken }).expect(400);
    const result = await createAccount();
    expect(Object.keys(result.body).sort()).toEqual(['id', 'username']);
    expect(result.body.username).toBe(account.username);
    await post('setup', { ...account, setupToken }).expect(409);
  });

  it('creates only one account during concurrent setup requests', async () => {
    const results = await Promise.all([
      post('setup', { ...account, setupToken }),
      post('setup', { ...account, username: 'other', setupToken }),
    ]);
    expect(results.map((result) => result.status).sort()).toEqual([201, 409]);
  });

  it('signs in, resolves a durable user id, rotates sessions, and revokes on sign-out', async () => {
    const created = await createAccount();
    const first = await signIn();
    const result = await session(first).expect(200);
    expect(result.body).toEqual(created.body);
    const guarded = await request(app.getHttpServer())
      .get('/api/guarded')
      .set('Cookie', first)
      .expect(200);
    expect(guarded.body.id).toBe(created.body.id);
    const rotation = await post('sign-in', account)
      .set('Cookie', first)
      .expect(204);
    const cookieHeader = (
      rotation.headers['set-cookie'] as unknown as string[]
    )[0];
    expect(cookieHeader).toContain('HttpOnly');
    expect(cookieHeader).toContain('Secure');
    expect(cookieHeader).toContain('SameSite=Strict');
    expect(cookieHeader).toContain('Path=/api');
    const second = cookieHeader.split(';')[0];
    expect(second).not.toEqual(first);
    await session(first).expect(401);
    await post('sign-out', {}).set('Cookie', second).expect(204);
    await session(second).expect(401);
    await request(app.getHttpServer())
      .get('/api/guarded')
      .set('Cookie', second)
      .expect(401);
    await post('sign-out', {}).expect(204);
  });

  it('rejects wrong passwords, unknown users and malformed session cookies', async () => {
    await createAccount();
    await post('sign-in', {
      ...account,
      password: 'a different test password',
    }).expect(401);
    await post('sign-in', { ...account, username: 'unknown' }).expect(401);
    await session('mere_session=%bad').expect(401);
    await session('mere_session=' + 'a'.repeat(64)).expect(401);
  });

  it.each([SESSION_LIFETIME, SESSION_IDLE_TIME])(
    'expires sessions after %i milliseconds',
    async (elapsed) => {
      await createAccount();
      const cookie = await signIn();
      if (elapsed === SESSION_LIFETIME) {
        const db = new DatabaseSync(config.path);
        db.prepare('UPDATE sessions SET last_seen = ?').run(
          Date.now() + elapsed,
        );
        db.close();
      }
      const clock = jest
        .spyOn(Date, 'now')
        .mockReturnValue(Date.now() + elapsed);
      try {
        await session(cookie).expect(401);
      } finally {
        clock.mockRestore();
      }
    },
  );

  it('preserves accounts and hashed sessions across restarts', async () => {
    await createAccount();
    const cookie = await signIn();
    await app.close();
    const db = new DatabaseSync(config.path);
    const row = db.prepare('SELECT * FROM sessions').get();
    expect(JSON.stringify(row)).not.toContain(
      cookie.slice('mere_session='.length),
    );
    expect(
      JSON.stringify(db.prepare('SELECT * FROM users').get()),
    ).not.toContain(account.password);
    db.close();
    await start();
    await session(cookie).expect(200);
    expect(app.get(AuthService).needsSetup()).toBe(false);
  });

  it('rejects missing and foreign origins on auth mutations and guarded writes', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/auth/setup')
      .send({ ...account, setupToken })
      .expect(403);
    await post('setup', { ...account, setupToken })
      .set('Origin', 'https://attacker.example')
      .expect(403);
    await createAccount();
    const cookie = await signIn();
    await post('sign-out', {})
      .set('Cookie', cookie)
      .set('Origin', 'https://attacker.example')
      .expect(403);
    await request(app.getHttpServer())
      .post('/api/guarded')
      .set('Cookie', cookie)
      .expect(403);
    await request(app.getHttpServer())
      .post('/api/guarded')
      .set('Cookie', cookie)
      .set('Origin', origin)
      .expect(201);
    await session(cookie).expect(200);
  });

  it('limits request size and repeated password attempts', async () => {
    await post('sign-in', { ...account, password: 'x'.repeat(5000) }).expect(
      413,
    );
    for (let i = 0; i < 5; i++) await post('sign-in', account).expect(401);
    await post('sign-in', account).expect(429);
  });

  it('rejects malformed JSON without reflecting the credential body', async () => {
    const result = await request(app.getHttpServer())
      .post('/api/v1/auth/sign-in')
      .set('Origin', origin)
      .set('Content-Type', 'application/json')
      .send('{"password":"synthetic-unclosed-password')
      .expect(400);
    expect(JSON.stringify(result.body)).not.toContain(
      'synthetic-unclosed-password',
    );
  });
});
