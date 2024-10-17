// src/user/user.module.ts
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthService } from 'src/auth/auth.service';
import { AuthController } from 'src/auth/auth.controller';
import { UserSchema } from 'src/user/schemas/user.schema'; // Modèle d'utilisateur
import { RefreshTokenSchema } from 'src/auth/schemas/refresh-token.schema';
import { ResetTokenSchema } from 'src/auth/schemas/reset-token.schema';
import { MailModule } from 'src/services/mail.module'; // Module Mail
import { RolesModule } from 'src/roles/roles.module'; // Assurez-vous que ce chemin est correct

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: 'user', schema: UserSchema }, // Modèle d'utilisateur
      { name: 'RefreshToken', schema: RefreshTokenSchema },
      { name: 'ResetToken', schema: ResetTokenSchema },
    ]),
    MailModule,
    RolesModule, // Importer le RolesModule ici
  ],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [AuthService, MongooseModule],
})
export class UserModule {}
