import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from 'src/auth/dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { user } from 'src/user/schemas/user.schema'; // Assurez-vous que le schéma de l'utilisateur est correctement importé
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

  // Méthode d'inscription
  async signup(signupData: SignupDto) {
    const { email, password, name } = signupData;
  
    // Validation des champs requis
    if (!email || !password || !name) {
      throw new BadRequestException('All fields are required');
    }
  
    // Vérifier si l'email est déjà utilisé
    const emailInUse = await this.UserModel.findOne({ email }).lean();
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }
  
    // Hachage du mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Remplacez par l'ID réel de votre rôle par défaut
    const defaultRoleId = new mongoose.Types.ObjectId("609d1e90fdb3a2421cfa7d55"); // Exemple d'ID ObjectId
  
    try {
      // Création d'un nouvel utilisateur
      const newUser = await this.UserModel.create({
        name,
        email,
        password: hashedPassword,
        roleId: defaultRoleId, // Assurez-vous que cela correspond à un rôle valide dans votre base de données
      });
  
      return {
        message: 'User registered successfully',
        userId: newUser._id.toString(),
      };
    } catch (error) {
      console.error('Error creating user:', error);
      // Gérer les erreurs de validation
      if (error instanceof mongoose.Error.ValidationError) {
        throw new BadRequestException(error.message);
      }
      // Gérer les autres erreurs internes
      throw new InternalServerErrorException('Failed to signup user');
    }
  }
  // Méthode pour récupérer tous les utilisateurs
  async getAllUsers() {
    const users = await this.UserModel.find().lean();
    if (!users || users.length === 0) {
      throw new NotFoundException('No users found');
    }
    return users;
  }  

  // Méthode de connexion
  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    //Find if user exists by email
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Wrong credentials');
    }

    //Compare entered password with existing password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    //Generate JWT tokens
    const tokens = await this.generateUserTokens(user.id);
    return {
      ...tokens,
      userId: user._id,
    };
  }

  // Méthode de changement de mot de passe
  async changePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Incorrect old password');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
  }

  // Méthode pour le mot de passe oublié
  async forgotPassword(email: string) {
    const user = await this.UserModel.findOne({ email }).lean();
    if (!user) {
      return { message: 'If this user exists, they will receive an email' };
    }

    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + 1);

    const resetToken = nanoid(64);
    await this.ResetTokenModel.create({
      token: resetToken,
      userId: user._id,
      expiryDate,
    });

    await this.mailService.sendPasswordResetEmail(email, resetToken);
    return { message: 'Password reset email sent' };
  }

  // Méthode de réinitialisation du mot de passe
  async resetPassword(newPassword: string, resetToken: string) {
    const token = await this.ResetTokenModel.findOneAndDelete({
      token: resetToken,
      expiryDate: { $gte: new Date() },
    });

    if (!token) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    const user = await this.UserModel.findById(token.userId);
    if (!user) {
      throw new InternalServerErrorException('User not found');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
  }

  // Méthode de rafraîchissement des tokens
  async refreshTokens(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOne({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    }).lean();

    if (!token) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    return this.generateUserTokens(token.userId.toString());
  }

  // Méthode pour générer des tokens utilisateur
  async generateUserTokens(userId: string) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '10h' });
    const refreshToken = uuidv4();

    await this.storeRefreshToken(refreshToken, userId);

    return {
      accessToken,
      refreshToken,
      expiresIn: '10h',
    };
  }

  // Méthode pour stocker un token de rafraîchissement
  async storeRefreshToken(token: string, userId: string) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    await this.RefreshTokenModel.updateOne(
      { userId },
      { $set: { expiryDate, token } },
      { upsert: true },
    );
  }

  // Méthode pour obtenir les permissions de l'utilisateur
  async getUserPermissions(userId: string) {
    const user = await this.UserModel.findById(userId).lean();
    if (!user) {
      throw new BadRequestException('User not found');
    }

    const role = await this.rolesService.getRoleById(user.roleId?.toString());
    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return role.permissions;
  }
}
