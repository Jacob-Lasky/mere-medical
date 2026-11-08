import {
  DynamicModule,
  BadRequestException,
  ForbiddenException,
  MiddlewareConsumer,
  Module,
  NestModule,
  PayloadTooLargeException,
} from '@nestjs/common';
import { json, Request, Response, NextFunction } from 'express';
import { AuthConfig } from './auth.config';
import { AuthController } from './auth.controller';
import { AUTH_CONFIG, AuthService } from './auth.service';
import { SessionGuard } from './session.guard';

@Module({})
export class AuthModule implements NestModule {
  constructor(private readonly auth: AuthService) {}

  configure(consumer: MiddlewareConsumer) {
    const parseJson = json({ limit: '4kb' });
    consumer
      .apply(
        (request: Request, response: Response, next: NextFunction) => {
          response.setHeader('Cache-Control', 'no-store');
          if (
            request.method !== 'GET' &&
            request.headers.origin !== this.auth.config.origin
          ) {
            throw new ForbiddenException('Untrusted request origin.');
          }
          next();
        },
        (request: Request, response: Response, next: NextFunction) => {
          parseJson(request, response, (error?: { status?: number }) => {
            // Parser errors can contain the raw body. Never pass credentials to
            // Nest's unknown-exception logger or return them to the client.
            next(
              error
                ? error.status === 413
                  ? new PayloadTooLargeException()
                  : new BadRequestException('Invalid JSON body.')
                : undefined,
            );
          });
        },
      )
      .forRoutes(AuthController);
  }

  static register(config: AuthConfig): DynamicModule {
    return {
      module: AuthModule,
      controllers: [AuthController],
      providers: [
        { provide: AUTH_CONFIG, useValue: config },
        AuthService,
        SessionGuard,
      ],
      exports: [AuthService, SessionGuard],
    };
  }
}
