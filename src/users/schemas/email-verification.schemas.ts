import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document } from 'mongoose';

export type EmailVerificationDocument = EmailVerification & Document;

@Schema()
export class EmailVerification {
    @Prop({ required: true, unique: true })
    email: string;

    @Prop({ required: true })
    verificationCode: string;
}

export const EmailVerificationSchema = SchemaFactory.createForClass(EmailVerification);