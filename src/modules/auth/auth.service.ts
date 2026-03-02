import { randomBytes } from 'node:crypto';
import { ConflictException, Injectable, InternalServerErrorException } from '@nestjs/common';
import * as bcrypt from 'bcrypt'

import { JwtService } from '@nestjs/jwt';

import { RegisterDto } from './dto/register.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthResponseDto } from './dto/auth-response.dto';

@Injectable()
export class AuthService {

  private readonly SALT_ROUNDS = 12;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto): Promise<AuthResponseDto> {
    const { email, password, firstName, lastName } = registerDto

    const existingUser = await this.prisma.user.findUnique({
      where: { email }
    })

    if (existingUser)
      throw new ConflictException('User with this email already exist')

    try {
      const hashedPassword = await bcrypt.hash(password, this.SALT_ROUNDS)
      const user = await this.prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          firstName,
          lastName
        },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          password: true,
        }
      })

      const tokens = await this.generateTokens(user.id, user.email)

      await this.updateRefreshToken(user.id, tokens.refreshToken)

      return {
        ...tokens,
        user
      }
    } catch (error) {
      console.log('Error on register: ', error);
      throw new InternalServerErrorException("An error occurred during registration")
    }

  }

  private async generateTokens(
    userId: string,
    email: string
  ): Promise<{ accessToken: string, refreshToken: string }> {
    const payload = { sub: userId, email }
    const refreshId = randomBytes(16).toString('hex')
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, { expiresIn: '15m' }),
      this.jwtService.signAsync({ ...payload, refreshId }, { expiredIn: '7d' })
    ])

    return { accessToken, refreshToken }
  }

  async updateRefreshToken(userId: string, refreshToken: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken }
    })
  }

}
