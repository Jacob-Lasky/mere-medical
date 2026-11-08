import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService, SESSION_COOKIE, ServerUser } from './auth.service';

export type AuthenticatedRequest = Request & { serverUser: ServerUser };

export function sessionToken(request: Request): string | undefined {
  return request.headers.cookie
    ?.split(';')
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith(`${SESSION_COOKIE}=`))
    ?.slice(SESSION_COOKIE.length + 1);
}

@Injectable()
export class SessionGuard implements CanActivate {
  constructor(private readonly auth: AuthService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    context
      .switchToHttp()
      .getResponse<Response>()
      .setHeader('Cache-Control', 'no-store');
    if (
      !['GET', 'HEAD', 'OPTIONS'].includes(request.method) &&
      request.headers.origin !== this.auth.config.origin
    ) {
      throw new ForbiddenException('Untrusted request origin.');
    }
    const user = this.auth.userForSession(sessionToken(request));
    if (!user)
      throw new UnauthorizedException('Sign in to use this server feature.');
    request.serverUser = user;
    return true;
  }
}
