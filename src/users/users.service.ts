import {
    Injectable,
    ConflictException,
    NotFoundException,
    UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as nodemailer from 'nodemailer';
import { User } from './interfaces/users.interfaces';
import { User as UserModel } from './schemas/users.schemas';
import { EmailVerification } from './schemas/email-verification.schemas';
import {
    CreateUserDto,
    LoginDto,
    UpdateUserDto,
    ChangePasswordDto,
    VerifyUserDto,
} from './dto/users.dto';

@Injectable()
export class UserService {
    private transporter: nodemailer.Transporter;
    private readonly refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET || (() => { throw new Error('REFRESH_TOKEN_SECRET is not defined'); })();
    private readonly accessTokenSecret = process.env.ACCESS_TOKEN_SECRET || (() => { throw new Error('ACCESS_TOKEN_SECRET is not defined'); })();

    constructor(
        @InjectModel(UserModel.name) private userModel: Model<UserModel>,
        @InjectModel(EmailVerification.name) private emailVerificationModel: Model<EmailVerification>,
    ) {
        this.transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT || '3001'),
            secure: false,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            },
        });
        
    }

    async create(createUserDto: CreateUserDto): Promise<User> {
        const existingUser = await this.userModel.findOne({ email: createUserDto.email });
        if (existingUser) throw new ConflictException('Email already registered');

        const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

        const newUser = new this.userModel({
            ...createUserDto,
            password: hashedPassword,
            isVerified: false,
            role: 'user',
        });

        await newUser.save();
        await this.sendVerificationCode(createUserDto.email);

        return this.mapToUserInterface(newUser);
    }

    async sendVerificationCode(email: string): Promise<void> {
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    
        const newVerificationCode = await this.emailVerificationModel.findOneAndUpdate(
            { email }, // Filtro para buscar por email
            {
                email,
                verificationCode,
                verificationCodeExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
            }, // Datos a actualizar o insertar
            { upsert: true, new: true } // Crear si no existe y devolver el documento actualizado
        );

        await this.transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to: email,
            subject: 'Verify Your Email',
            html: `<p>Your verification code is: <b>${verificationCode}</b></p>`,
        });
    }

    async findAll(): Promise < User[] > {
            const users = await this.userModel.find();
            return users.map(usuario => this.mapToUserInterface(usuario));
        }

    async findById(id: string): Promise < User > {
            const user = await this.userModel.findById(id);
            if(!user) throw new NotFoundException('User not found');
            return this.mapToUserInterface(user);
        }

    async findByEmail(email: string): Promise < User > {
            const user = await this.userModel.findOne({ email });
            if(!user) throw new NotFoundException('User not found');
            return this.mapToUserInterface(user);
        }

    async update(id: string, updateUserDto: UpdateUserDto): Promise < User > {
            if(updateUserDto.password) {
            updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
        }
        const updatedUser = await this.userModel.findByIdAndUpdate(id, updateUserDto, { new: true, });
        if (!updatedUser) throw new NotFoundException('User not found');
        return this.mapToUserInterface(updatedUser);
    }

    async delete(id: string): Promise<void> {
        await this.userModel.findByIdAndDelete(id);
    }

    async verifyUser(verifyUserDto: VerifyUserDto): Promise<User> {
        const user = await this.userModel.findOne({email: verifyUserDto.email});
        if (!user) throw new NotFoundException('User not found');
        if (user.isVerified) throw new ConflictException('User already verified');

        const emailVerification = await this.emailVerificationModel.findOne({ email: verifyUserDto.email });
        if (!emailVerification) throw new NotFoundException('Verification email and code not found. Please request a new verification code.');
        if (emailVerification.verificationCode !== verifyUserDto.verificationCode) throw new UnauthorizedException('Invalid code');

        user.isVerified = true;
        user.verificationCode = undefined;
        user.verificationCodeExpires = undefined;

        await user.save();
        await emailVerification.deleteOne();

        return this.mapToUserInterface(user);
    }

    async login(loginDto: LoginDto) {
        const user = await this.userModel.findOne({ email: loginDto.email });
        if (!user) throw new UnauthorizedException('Invalid email');

        const isPasswordValid = await bcrypt.compare(loginDto.password, user.password);
        if (!isPasswordValid) throw new UnauthorizedException('Invalid credentials');
        if (!user.isVerified) throw new UnauthorizedException('User not verified');

        const accessToken = this.generateAccessToken(user);
        const refreshToken = this.generateRefreshToken(user);
        user.refreshToken = refreshToken;
        await user.save();

        return {
            accessToken,
            user: {
                role: user.role,
                isVerified: user.isVerified,
            },
        };
    }

    async refreshAccesToken(email: string) {
        const user = await this.userModel.findOne({ email });
        if (!user) throw new NotFoundException('User not found');
        if (!user.refreshToken) throw new UnauthorizedException('Refresh token is missing, please login again');

        try {
            const payload = jwt.verify(user.refreshToken, this.refreshTokenSecret, { ignoreExpiration: false });
            if (payload.sub !== user.id) throw new UnauthorizedException('Invalid refresh token, please login again');

            const newAccessToken = this.generateAccessToken(user);

            return {
                accessToken: newAccessToken,
                user: {
                    role: user.role,
                    isVerified: user.isVerified,
                },
            };
        } catch (error) {
            throw new UnauthorizedException('Invalid refresh token, please login again');
        }
    }

    async changePassword(id: string, changePasswordDto: ChangePasswordDto) {
        const user = await this.userModel.findById(id);
        if (!user) throw new NotFoundException('User not found');

        const isValid = await bcrypt.compare(changePasswordDto.currentPassword, user.password);
        if (!isValid) throw new UnauthorizedException('Current password is incorrect');

        user.password = await bcrypt.hash(changePasswordDto.newPassword, 10);
        await user.save();
    }

    private generateAccessToken(user: any) {
        return jwt.sign(
            { 
                sub: user.id, 
                email: user.email, 
                role: user.role
            },
            this.accessTokenSecret,
            { expiresIn: '30m' },
        );
    }

    private generateRefreshToken(user: any) {
        return jwt.sign(
            { sub: user.id },
            this.refreshTokenSecret,
            { expiresIn: '1d' },
        );
    }

    private mapToUserInterface(user: any): User {
        return {
            id: user._id ? user._id.toString() : user.id,
            name: user.name,
            email: user.email,
            isVerified: user.isVerified,
            role: user.role,
            refreshToken: user.refreshToken,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        };
    }
}