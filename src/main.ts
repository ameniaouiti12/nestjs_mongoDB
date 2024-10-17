import * as dotenv from 'dotenv';
dotenv.config(); // Charger les variables d'environnement

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Utiliser un pipe global pour valider les DTOs
  app.useGlobalPipes(new ValidationPipe()); 

  const port = process.env.PORT || 3000; // Utilise PORT depuis .env si disponible
  await app.listen(port);
  console.log(`Application is running on: http://localhost:${port}`);
}
bootstrap();
