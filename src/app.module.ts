import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from './user/user.module';
import { ProductModule } from './product/product.module';
import { AuthModule } from './auth/auth.module';
import { RolesService } from './roles/roles.service';
import { RolesController } from './roles/roles.controller';
import { RolesModule } from './roles/roles.module';
import config from 'src/config/config'; // Import de ton fichier de configuration

@Module({
  imports: [
    // Chargement des variables d'environnement et du fichier de config
    ConfigModule.forRoot({
      isGlobal: true,
      load: [config], // Charge le fichier config.ts
      cache: true,
    }),

    // Connexion MongoDB (asynchrone avec ConfigService)
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (config: ConfigService) => ({
        uri: config.get<string>('database.connectionString'),
      }),
      inject: [ConfigService],
    }),

    // Configuration du module JWT (asynchrone)
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (config: ConfigService) => ({
        secret: config.get<string>('jwt.secret'),
        signOptions: { expiresIn: '1h' },
      }),
      global: true,
      inject: [ConfigService],
    }),

    // Modules de l'application
    UserModule,
    ProductModule,
    AuthModule,
    RolesModule,
  ],
  providers: [RolesService],
  controllers: [RolesController],
})
export class AppModule {}
