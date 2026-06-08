import {
    ConflictException,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';

import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

import { PrismaService } from '../prisma/prisma.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';

@Injectable()
export class AuthService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly jwtService: JwtService,
    ) { }

    private async generateTokens(
        userId: string,
        email: string,
    ) {
        const payload = {
            sub: userId,
            email,
        };

        const accessToken =
            await this.jwtService.signAsync(payload, {
                expiresIn: '15m',
            });

        const refreshToken =
            await this.jwtService.signAsync(payload, {
                secret:
                    process.env.JWT_REFRESH_SECRET,
                expiresIn: '30d',
            });

        return {
            accessToken,
            refreshToken,
        };
    }

    async register(dto: RegisterDto) {
        const email =
            dto.email.trim().toLowerCase();

        const existingUser =
            await this.prisma.user.findUnique({
                where: {
                    email,
                },
            });

        if (existingUser) {
            throw new ConflictException(
                'Email already registered',
            );
        }

        const hashedPassword =
            await bcrypt.hash(dto.password, 12);

        const user =
            await this.prisma.user.create({
                data: {
                    email,
                    password: hashedPassword,
                    countryCode: dto.countryCode,
                },
            });

        const {
            accessToken,
            refreshToken,
        } = await this.generateTokens(
            user.id,
            user.email,
        );

        await this.saveRefreshToken(
            user.id,
            refreshToken,
        );

        return {
            success: true,

            user: {
                id: user.id,
                email: user.email,
                countryCode: user.countryCode,
                isVerified: user.isVerified,
            },

            accessToken,
            refreshToken,
        };
    }

    async login(dto: LoginDto) {
        const email =
            dto.email.trim().toLowerCase();

        const user =
            await this.prisma.user.findUnique({
                where: {
                    email,
                },
            });

        if (!user) {
            throw new UnauthorizedException(
                'Invalid email or password',
            );
        }

        const validPassword =
            await bcrypt.compare(
                dto.password,
                user.password,
            );

        if (!validPassword) {
            throw new UnauthorizedException(
                'Invalid email or password',
            );
        }

        const {
            accessToken,
            refreshToken,
        } = await this.generateTokens(
            user.id,
            user.email,
        );

        await this.saveRefreshToken(
            user.id,
            refreshToken,
        );

        return {
            success: true,

            user: {
                id: user.id,
                email: user.email,
                countryCode: user.countryCode,
                isVerified: user.isVerified,
            },

            accessToken,
            refreshToken,
        };
    }

    async me(userId: string) {
        const user =
            await this.prisma.user.findUnique({
                where: {
                    id: userId,
                },

                select: {
                    id: true,
                    email: true,
                    countryCode: true,
                    isVerified: true,
                    isActive: true,
                    createdAt: true,
                },
            });

        if (!user) {
            throw new UnauthorizedException(
                'User not found',
            );
        }

        return user;
    }

    private async saveRefreshToken(
        userId: string,
        refreshToken: string,
    ) {
        const hashedToken =
            await bcrypt.hash(refreshToken, 10);

        await this.prisma.user.update({
            where: {
                id: userId,
            },

            data: {
                refreshToken: hashedToken,
            },
        });
    }

    async refresh(
        refreshToken: string,
    ) {
        try {
            const payload =
                await this.jwtService.verifyAsync(
                    refreshToken,
                    {
                        secret:
                            process.env.JWT_REFRESH_SECRET,
                    },
                );

            const user =
                await this.prisma.user.findUnique({
                    where: {
                        id: payload.sub,
                    },
                });

            if (
                !user ||
                !user.refreshToken
            ) {
                throw new UnauthorizedException();
            }

            const valid =
                await bcrypt.compare(
                    refreshToken,
                    user.refreshToken,
                );

            if (!valid) {
                throw new UnauthorizedException();
            }

            const tokens =
                await this.generateTokens(
                    user.id,
                    user.email,
                );

            await this.saveRefreshToken(
                user.id,
                tokens.refreshToken,
            );

            return {
                success: true,
                ...tokens,
            };
        } catch {
            throw new UnauthorizedException(
                'Invalid refresh token',
            );
        }
    }

    async logout(userId: string) {
        await this.prisma.user.update({
            where: {
                id: userId,
            },

            data: {
                refreshToken: null,
            },
        });

        return {
            success: true,
            message: 'Logged out successfully',
        };
    }

    
}
