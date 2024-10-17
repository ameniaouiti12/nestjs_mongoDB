import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Role, RoleSchema } from './schemas/role.schema'; // Adjust the path accordingly
import { RolesService } from './roles.service';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Role.name, schema: RoleSchema }]),
  ],
  providers: [RolesService],
  exports: [RolesService, MongooseModule], // Ensure RoleModel is exported
})
export class RolesModule {}
