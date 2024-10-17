import {
    BadRequestException,
    Injectable,
    InternalServerErrorException,
    NotFoundException,
    UnauthorizedException,
  } from '@nestjs/common';
  import { SignupDto } from 'src/auth/dtos/signup.dto';
  import { InjectModel } from '@nestjs/mongoose';
  import { user } from 'src/user/Schemas/user.schema';
  import mongoose, { Model } from 'mongoose';
  import * as bcrypt from 'bcrypt';
  import { LoginDto } from 'src/auth/dtos/login.dto';
  import { JwtService } from '@nestjs/jwt';
  import { RefreshToken } from './schemas/refresh-token.schema';
  import { v4 as uuidv4 } from 'uuid';
  import { nanoid } from 'nanoid';
  import { ResetToken } from 'src/auth/schemas/reset-token.schema';
  import { MailService } from 'src/services/mail.service';
  import { RolesService } from 'src/roles/roles.service';
  
  @Injectable()
  export class AuthService {
    constructor(
      @InjectModel(user.name) private UserModel: Model<user>,
      @InjectModel(RefreshToken.name) private RefreshTokenModel: Model<RefreshToken>,
      @InjectModel(ResetToken.name) private ResetTokenModel: Model<ResetToken>,
      private jwtService: JwtService,
      private mailService: MailService,
      private rolesService: RolesService,
    ) {}
  
    async signup(signupData: SignupDto) {
      const { email, password, name } = signupData;
  
      // Check if email is in use
      const emailInUse = await this.UserModel.findOne({ email }).lean();
      if (emailInUse) {
        throw new BadRequestException('Email already in use');
      }
  
      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create user document and save in mongodb
      return await this.UserModel.create({
        name,
        email,
        password: hashedPassword,
      });
    }
  
    async login(credentials: LoginDto) {
      const { email, password } = credentials;
  
      // Find if user exists by email
      const user = await this.UserModel.findOne({ email }).lean();
      if (!user) {
        throw new UnauthorizedException('Wrong credentials');
      }
  
      // Compare entered password with existing password
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        throw new UnauthorizedException('Wrong credentials');
      }
  
      // Generate JWT tokens
      const tokens = await this.generateUserTokens(user._id.toString());
      return {
        ...tokens,
        userId: user._id.toString(),
      };
    }
  
    async changePassword(userId: string, oldPassword: string, newPassword: string) {
      // Find the user
      const user = await this.UserModel.findById(userId).lean();
      if (!user) {
        throw new NotFoundException('User not found...');
      }
  
      // Compare the old password with the password in DB
      const passwordMatch = await bcrypt.compare(oldPassword, user.password);
      if (!passwordMatch) {
        throw new UnauthorizedException('Wrong credentials');
      }
  
      // Change user's password
      const newHashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = newHashedPassword;
      await user.save();
    }
  
    async forgotPassword(email: string) {
      // Check that user exists
      const user = await this.UserModel.findOne({ email }).lean();
  
      if (user) {
        // If user exists, generate password reset link
        const expiryDate = new Date();
        expiryDate.setHours(expiryDate.getHours() + 1);
  
        const resetToken = nanoid(64);
        await this.ResetTokenModel.create({
          token: resetToken,
          userId: user._id,
          expiryDate,
        });
  
        // Send the link to the user by email
        await this.mailService.sendPasswordResetEmail(email, resetToken);
      }
  
      return { message: 'If this user exists, they will receive an email' };
    }
  
    async resetPassword(newPassword: string, resetToken: string) {
      // Find a valid reset token document
      const token = await this.ResetTokenModel.findOneAndDelete({
        token: resetToken,
        expiryDate: { $gte: new Date() },
      });
  
      if (!token) {
        throw new UnauthorizedException('Invalid link');
      }
  
      // Change user password (MAKE SURE TO HASH!!)
      const user = await this.UserModel.findById(token.userId).lean();
      if (!user) {
        throw new InternalServerErrorException();
      }
  
      user.password = await bcrypt.hash(newPassword, 10);
      await user.save();
    }
  
    async refreshTokens(refreshToken: string) {
      const token = await this.RefreshTokenModel.findOne({
        token: refreshToken,
        expiryDate: { $gte: new Date() },
      }).lean();
  
      if (!token) {
        throw new UnauthorizedException('Refresh Token is invalid');
      }
      return this.generateUserTokens(token.userId.toString());
    }
  
    async generateUserTokens(userId: string) {
      const accessToken = this.jwtService.sign({ userId }, { expiresIn: '10h' });
      const refreshToken = uuidv4();
  
      await this.storeRefreshToken(refreshToken, userId);
      return {
        accessToken,
        refreshToken,
      };
    }
  
    async storeRefreshToken(token: string, userId: string) {
      // Calculate expiry date 3 days from now
      const expiryDate = new Date();
      expiryDate.setDate(expiryDate.getDate() + 3);
  
      await this.RefreshTokenModel.updateOne(
        { userId },
        { $set: { expiryDate, token } },
        {
          upsert: true,
        },
      );
    }
  
    async getUserPermissions(userId: string) {
      const user = await this.UserModel.findById(userId).lean();
  
      if (!user) throw new BadRequestException('User not found');
  
      const role = await this.rolesService.getRoleById(user.roleId.toString());
      if (!role) {
        throw new NotFoundException('Role not found');
      }
      return role.permissions;
    }
  }
  