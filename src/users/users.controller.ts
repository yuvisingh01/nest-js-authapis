import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/auth/jwt.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  getMyUser(@Param() params:{id:string,},){
    return this.usersService.getMyUser(params.id)
  }

  @Get()
  getUsers(){
    return this.usersService.getUsers();
  }

}
