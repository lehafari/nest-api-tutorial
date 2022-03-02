import { Controller, Get, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { GetUser } from 'src/auth/decorator';
import { JwtGuard } from 'src/auth/guard';

//JtwGuard es un customGuard que extiende del Guard de autenticacion de passport
@UseGuards(JwtGuard)
@Controller('users')
export class UserController {
  // El decorador UseGuard nos permite usar el guard de autenticacion, en este caso de passport y nos permite acceder a la informacion del usuario que este autenticado a traves de la request (req) que nos llega por parametro en el metodo

  // ****metodo getMe****

  @Get('me')
  getMe(@GetUser() user: User) {
    return user;
  }
}
