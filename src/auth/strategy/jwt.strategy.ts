import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';

//Este objeto es un provider por lo que le colocalos el decorador Injectable para poder inyectarlo en otros componentes
@Injectable()
// Extiende de PassportStrategy que recibe un tipo de estrategia, en este caso jwt
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService, private prisma: PrismaService) {
    // Aqui una config que heredamos de PassportStrategy
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get('JWT_SECRET'),
    });
  }
  // usa automaticamente el metodo validate, que recibe el payload del token que el usuario envia con la informacion del usuario
  async validate(payload: { sub: number; email: string }) {
    // buscamos el usuario en base de datos que coincida con los datos del payload
    const user = await this.prisma.user.findUnique({
      where: {
        id: payload.sub,
      },
    });
    // eliminamos el hash del usuario para que no se muestre en la respuesta
    delete user.hash;
    // devolvemos el usuario que se agregara automaticamente a la request por medio del decorador @UseGuards
    return user;
  }
}
