import { Schema, Document } from 'mongoose';

export interface user extends Document {
  name: string;
  email: string;
  password: string;
  roleId: string;
}

export const UserSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  roleId: { type: String, required: true },
});
