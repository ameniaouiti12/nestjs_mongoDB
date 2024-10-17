import { PartialType } from '@nestjs/mapped-types';
import { CreateProductDto } from 'src/product/dto/create_poduct_dto';

export class UpdateProductDto extends PartialType(CreateProductDto) {}
