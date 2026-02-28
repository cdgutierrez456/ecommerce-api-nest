import { Injectable } from '@nestjs/common';

import { RegisterDto } from './dto/register.dto';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {

  constructor(
    private readonly prisma: PrismaService
  ) {}

  register(registerDto: RegisterDto) {

  }

}
