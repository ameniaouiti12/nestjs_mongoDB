import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { user } from './Schemas/user.schema';
import { Model } from 'mongoose';

@Injectable()
export class UserService {

  constructor(@InjectModel(user.name) private userModel: Model<user>) { }


  async create(createUserDto: CreateUserDto): Promise<user> {
    const createdUser = new this.userModel(createUserDto);
    return createdUser.save();
  }

  async findAll(): Promise<user[]> {
    return this.userModel.find().exec();
  }

  async findOne(id: string): Promise<user> {
    return this.userModel.findById(id).exec();
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<user> {


    return this.userModel.findByIdAndUpdate(id, updateUserDto, { new: true }).exec();
  }

  async remove(id: string): Promise<user> {
    return this.userModel.findByIdAndDelete(id).exec()
  }
}
