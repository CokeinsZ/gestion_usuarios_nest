import {
  Body,
  Controller,
  Post,
  Get,
  Put,
  Delete,
  Param,
  UseGuards,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from './users.service';
import {
  CreateUserDto,
  LoginDto,
  UpdateUserDto,
  ChangePasswordDto,
  VerifyUserDto,
} from './dto/users.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('api/v1/users')
export class UserController {
  constructor(private readonly userService: UserService) { }

  @Post()
  async create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  @Post('verify')
  async verifyUser(@Body() verifyUserDto: VerifyUserDto) {
    return this.userService.verifyUser(verifyUserDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.userService.login(loginDto);
  }

  @Post('refresh')
  async refreshToken(@Body('email') email: string) {
    return this.userService.refreshAccesToken(email);
  }

  @UseGuards(AuthGuard('jwt'))
  @Put(':id/password')
  async changePassword(@Param('id') id: string, @Body() dto: ChangePasswordDto) {
    return this.userService.changePassword(id, dto);
  }

  @Get()
  async findAll() {
    return this.userService.findAll();
  }

  @Get('byEmail')
  async findByEmail(@Body('email') email: string) {
    return this.userService.findByEmail(email);
  }

  @Get(':id')
  async findOne(@Param('id') id: string) {
    return this.userService.findById(id);
  }

  @UseGuards(AuthGuard('jwt'))
  @Put(':id')
  async update(@Param('id') id: string, @Body() dto: UpdateUserDto) {
    return this.userService.update(id, dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete(':id')
  async delete(@Param('id') id: string) {
    return this.userService.delete(id);
  }

  @Post('send-verification-email')
  async sendVerificationCode(@Body('email') email: string) {
    return this.userService.sendVerificationCode(email);
  }
}