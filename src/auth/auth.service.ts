import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable({})
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}
  //****metodo signup****
  async signup(dto: AuthDto) {
    //creamos el hash de la contraseña
    const hash = await argon.hash(dto.password);
    //guardamos el usuario en la base de datos
    // usamos el try catch para capturar el error
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      //despues de guardar al usuario borramos el hash para que no se muestre en la respuesta
      delete user.hash;
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Email already exists');
        }
      }
      throw error;
    }
  }
  //****metodo signin****
  async signin(dto: AuthDto) {
    //buscamos el usuario por el email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    //si no existe devolvemos un error
    if (!user) {
      throw new ForbiddenException('User not found');
    }
    //Si el usuario existe comparamos la contraseña con el hash
    const pwMatch = await argon.verify(user.hash, dto.password);
    //si no coincide devolvemos un error
    if (!pwMatch) {
      throw new ForbiddenException('Invalid credentials');
    }
    //si todo es correcto borramos el hash y mostramos el usuario
    delete user.hash;
    return user;
  }
}
