import { Module } from '@nestjs/common';
import { UserModule } from './user/user.module';
import { UsersModule } from './users/users.module';
import { UserController } from './user/user.controller';
import { UserService } from './user/user.service';

@Module({
  imports: [UserModule, UsersModule],
  controllers: [UserController],
  providers: [UserService],
})
export class AppModule {}
