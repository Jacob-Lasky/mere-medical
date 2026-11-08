import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { Throttle } from '@nestjs/throttler';
import { z } from 'zod';
import { SETUP_TOKEN_MIN_LENGTH, SETUP_TOKEN_MAX_LENGTH } from './auth.config';
import { AuthService, SESSION_COOKIE, SESSION_LIFETIME } from './auth.service';
import {
  AuthenticatedRequest,
  SessionGuard,
  sessionToken,
} from './session.guard';

const credentials = z.object({
  username: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^[a-z0-9][a-z0-9_-]{2,63}$/),
  password: z.string().min(15).max(128),
});
const setup = credentials.extend({
  setupToken: z
    .string()
    .min(SETUP_TOKEN_MIN_LENGTH)
    .max(SETUP_TOKEN_MAX_LENGTH),
});

@Controller('v1/auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Get('status')
  status() {
    return { setupRequired: this.auth.needsSetup() };
  }

  @Post('setup')
  @Throttle({ short: { limit: 5, ttl: 60000 } })
  async createAccount(@Body() body: unknown) {
    const parsed = setup.safeParse(body);
    if (!parsed.success)
      throw new BadRequestException(
        'Use a 3–64 character username and a 15–128 character password.',
      );
    return this.auth.createFirstAccount(
      parsed.data.username,
      parsed.data.password,
      parsed.data.setupToken,
    );
  }

  @Post('sign-in')
  @HttpCode(204)
  @Throttle({ short: { limit: 5, ttl: 60000 } })
  async signIn(
    @Body() body: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    const parsed = credentials.safeParse(body);
    if (!parsed.success)
      throw new BadRequestException(
        'Use a 3–64 character username and a 15–128 character password.',
      );
    const token = await this.auth.signIn(
      parsed.data.username,
      parsed.data.password,
    );
    this.auth.signOut(sessionToken(request));
    response.cookie(SESSION_COOKIE, token, {
      httpOnly: true,
      secure: this.auth.config.secure,
      sameSite: 'strict',
      path: '/api',
      maxAge: SESSION_LIFETIME,
    });
  }

  @Get('session')
  @UseGuards(SessionGuard)
  session(@Req() request: AuthenticatedRequest) {
    return request.serverUser;
  }

  @Post('sign-out')
  @HttpCode(204)
  signOut(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    this.auth.signOut(sessionToken(request));
    response.clearCookie(SESSION_COOKIE, {
      httpOnly: true,
      secure: this.auth.config.secure,
      sameSite: 'strict',
      path: '/api',
    });
  }
}
