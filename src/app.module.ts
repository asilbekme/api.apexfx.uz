import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler'
import { PrismaModule } from './prisma/prisma.module.js';
import { AuthModule } from './auth/auth.module.js';
import { UsersModule } from './users/users.module.js';

@Module({
  imports: [
    ThrottlerModule.forRoot([
      {
        ttl: 60,
        limit: 5
      }
    ]),
    PrismaModule,
    AuthModule,
    UsersModule,
  ]
})
export class AppModule { }