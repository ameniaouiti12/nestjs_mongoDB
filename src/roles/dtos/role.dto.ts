import { Type } from 'class-transformer';
import {
    ArrayUnique,
  IsEnum,
  IsString,
  ValidateNested,
} from 'class-validator';
import { Action } from '../enums/action.enum';
import { Resource } from 'src/roles/enums/recource.enum';

export class CreateRoleDto {
  @IsString()
  name: string;

  @ValidateNested()
  @Type(() => Permission)
  permissions: Permission[];
}

export class Permission {
  @IsEnum(Resource)
  resource: Resource;

  @IsEnum(Action, { each: true })
  @ArrayUnique()
  actions: Action[];
}
