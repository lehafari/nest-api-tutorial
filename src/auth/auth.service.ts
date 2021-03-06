import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

type token = {
  access_token: string;
};

@Injectable({})
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}
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
    //si todo es correcto borramos el hash
    delete user.hash;
    //y llamamos al metodo ***signToken*** para generar y devolver el token
    return this.signToken(user.id, user.email);
  }

  //****metodo signToken ****
  // convertimos la informacion del usuario en un token (jwt)
  async signToken(userID: number, email: string): Promise<token> {
    //le pasamos la informacion en un payload
    const payload = {
      sub: userID,
      email,
    };
    //buscamos la clave secreta que tenemos en .env
    const secret = this.config.get('JWT_SECRET');
    //le pasamos el payload y como segundo argumento en un objeto le pasamos el tiempo de expiracion del token y la clave secreta para generar el token
    const token = this.jwt.sign(payload, {
      expiresIn: '1d',
      secret,
    });
    //finalmente retornamos el token que llegara hasta el controlador para que lo pueda guardar en la respuesta
    return { access_token: token };
  }
}
