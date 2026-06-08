import {
    IsEmail,
    IsString,
    Length,
    MinLength,
} from 'class-validator';

export class RegisterDto {
    @IsEmail()
    email!: string;

    @MinLength(8)
    password!: string;

    @IsString()
    @Length(2, 2)
    countryCode!: string;
}