import {
    Body,
    Controller,
    Get,
    Post,
    UseGuards,
} from '@nestjs/common';

import { AuthService } from './auth.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { CurrentUser } from '../common/decorators/current-user.decorator.js';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
    ) { }

    @Post('register')
    register(
        @Body() dto: RegisterDto,
    ) {
        return this.authService.register(dto);
    }

    @Post('login')
    login(
        @Body() dto: LoginDto,
    ) {
        return this.authService.login(dto);
    }

    @Get('me')
    @UseGuards(JwtAuthGuard)
    me(
        @CurrentUser() user: any,
    ) {
        return this.authService.me(user.sub);
    }

    @Post('refresh')
    refresh(
        @Body('refreshToken')
        refreshToken: string,
    ) {
        return this.authService.refresh(
            refreshToken,
        );
    }

    @Post('logout')
    @UseGuards(JwtAuthGuard)
    logout(
        @CurrentUser() user: any,
    ) {
        return this.authService.logout(
            user.sub,
        );
    }
}