import {
  ConflictException,
  Inject,
  Injectable,
  OnModuleDestroy,
  UnauthorizedException,
} from '@nestjs/common';
import {
  argon2,
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { closeSync, openSync } from 'node:fs';
import { AuthConfig } from './auth.config';

export const AUTH_CONFIG = Symbol('AUTH_CONFIG');
export const SESSION_COOKIE = 'mere_session';
export const SESSION_LIFETIME = 8 * 60 * 60 * 1000;
export const SESSION_IDLE_TIME = 30 * 60 * 1000;
// Persisted Argon2id v19 parameters; changing them requires a hash migration.
const ARGON2 = { memory: 19456, passes: 2, parallelism: 1, tagLength: 32 };

export interface ServerUser {
  id: string;
  username: string;
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function passwordHash(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    argon2(
      'argon2id',
      { ...ARGON2, message: password, nonce: salt },
      (error, key) => {
        if (error) reject(error);
        else resolve(key);
      },
    );
  });
}

@Injectable()
export class AuthService implements OnModuleDestroy {
  private readonly db: DatabaseSync;

  constructor(@Inject(AUTH_CONFIG) readonly config: AuthConfig) {
    closeSync(openSync(config.path, 'a', 0o600));
    this.db = new DatabaseSync(config.path);
    this.db.exec(`
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        salt BLOB NOT NULL,
        password_hash BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
      );
    `);
  }

  onModuleDestroy() {
    this.db.close();
  }

  needsSetup(): boolean {
    return !this.db.prepare('SELECT 1 FROM users LIMIT 1').get();
  }

  async createFirstAccount(
    username: string,
    password: string,
    setupToken: string,
  ): Promise<ServerUser> {
    if (!this.needsSetup())
      throw new ConflictException('Account setup is already complete.');
    if (
      !timingSafeEqual(
        Buffer.from(digest(setupToken)),
        Buffer.from(digest(this.config.setupToken)),
      )
    ) {
      throw new UnauthorizedException('Invalid setup token.');
    }
    const salt = randomBytes(16);
    const hash = await passwordHash(password, salt);
    const user = { id: randomUUID(), username };
    // The conditional INSERT also closes the race between concurrent setup requests.
    const result = this.db
      .prepare(
        `
      INSERT INTO users (id, username, salt, password_hash)
      SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)
    `,
      )
      .run(user.id, username, salt, hash);
    if (result.changes !== 1)
      throw new ConflictException('Account setup is already complete.');
    return user;
  }

  async signIn(username: string, password: string): Promise<string> {
    const row = this.db
      .prepare('SELECT * FROM users WHERE username = ?')
      .get(username) as
      | (ServerUser & { salt: Uint8Array; password_hash: Uint8Array })
      | undefined;
    // Unknown usernames still perform the same expensive password derivation.
    const salt = row ? Buffer.from(row.salt) : Buffer.alloc(16);
    const candidate = await passwordHash(password, salt);
    if (!row || !timingSafeEqual(candidate, Buffer.from(row.password_hash))) {
      throw new UnauthorizedException('Invalid username or password.');
    }
    const now = Date.now();
    this.db
      .prepare('DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?')
      .run(now, now - SESSION_IDLE_TIME);
    const token = randomBytes(32).toString('hex');
    this.db
      .prepare('INSERT INTO sessions VALUES (?, ?, ?, ?)')
      .run(digest(token), row.id, now + SESSION_LIFETIME, now);
    return token;
  }

  userForSession(token: string | undefined): ServerUser | undefined {
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return undefined;
    const now = Date.now();
    const user = this.db
      .prepare(
        `
      SELECT users.id, users.username FROM sessions JOIN users ON users.id = sessions.user_id
      WHERE token_hash = ? AND expires_at > ? AND last_seen > ?
    `,
      )
      .get(digest(token), now, now - SESSION_IDLE_TIME) as unknown as
      | ServerUser
      | undefined;
    if (user)
      this.db
        .prepare('UPDATE sessions SET last_seen = ? WHERE token_hash = ?')
        .run(now, digest(token));
    return user;
  }

  signOut(token: string | undefined) {
    if (token)
      this.db
        .prepare('DELETE FROM sessions WHERE token_hash = ?')
        .run(digest(token));
  }
}
