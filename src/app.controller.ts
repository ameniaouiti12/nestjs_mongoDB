import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AppService } from 'src/app.service';
import { AuthenticationGuard } from './guards/authentication.guard';
import { Permission } from 'src/roles/dtos/role.dto';
import { Resource } from 'src/roles/enums/recource.enum';
import { Action } from './roles/enums/action.enum';
import { AuthorizationGuard } from './guards/authorization.guard';

@UseGuards(AuthenticationGuard, AuthorizationGuard)

@Controller('products')
export class AppController {
  constructor(private readonly appService: AppService) {}

  //  @Permissions([{ resource: Resource.products, actions: [Action.read] }])
  
  @UseGuards(AuthenticationGuard)
  @Get()
  someProtectedRoute(@Req() req) {
    return { message: 'Accessed Resource', userId: req.userId };
  }
}
