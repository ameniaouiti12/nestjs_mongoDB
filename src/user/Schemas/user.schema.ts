import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema, Types } from 'mongoose';

@Schema({ timestamps: true }) // Ajout automatique des champs createdAt et updatedAt
export class user extends Document {
  @Prop({ required: true })
  name: string; // Type corrigé (string)

  @Prop({ required: true })
  email: string;

  @Prop({ required: true })
  password: string;
  
  @Prop({ required: true, type: MongooseSchema.Types.ObjectId })
  roleId: Types.ObjectId;  // Ajout de roleId
}

// Création du schéma Mongoose
export const UserSchema = SchemaFactory.createForClass(user);
