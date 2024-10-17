// src/product/schemas/product.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class Product extends Document {
  @Prop({ required: true })
  name: string;

  @Prop()
  description: string;

  @Prop({ required: true, type: Number })
  price: number;

  @Prop({ default: Date.now })
  createdAt: Date;
}

// Export the schema properly
export const ProductSchema = SchemaFactory.createForClass(Product);
