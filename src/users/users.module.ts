import { Module } from '@nestjs/common';
import { UserController } from './users.controller';
import { UserService } from './users.service';
import { User, UserSchema } from './schemas/users.schemas';
import { EmailVerification, EmailVerificationSchema } from './schemas/email-verification.schemas';
import { MongooseModule } from '@nestjs/mongoose';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from 'src/auth/jwt.strategy';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: EmailVerification.name, schema: EmailVerificationSchema },
    ]),

    PassportModule.register({ defaultStrategy: 'jwt' }),
  ],
  controllers: [UserController],
  providers: [UserService, JwtStrategy],
})
export class UsersModule {}
