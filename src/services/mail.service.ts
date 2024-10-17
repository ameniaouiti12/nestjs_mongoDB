import * as nodemailer from 'nodemailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    // Configuration du transporteur SMTP
    this.transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      auth: {
        user: 'lilla.terry55@ethereal.email', // Remplacez par votre utilisateur
        pass: 'yQQSg25MR1QwugbNnN', // Remplacez par votre mot de passe
      },
    });
  }

  async sendPasswordResetEmail(to: string, token: string) {
    // Lien de réinitialisation
    const resetLink = `http://yourapp.com/reset-password?token=${token}`;
    const mailOptions = {
      from: 'Auth-backend service',
      to: to,
      subject: 'Password Reset Request',
      html: `<p>You requested a password reset. Click the link below to reset your password:</p><p><a href="${resetLink}">Reset Password</a></p>`,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`Password reset email sent to ${to}`);
    } catch (error) {
      console.error(`Failed to send email to ${to}:`, error);
      throw new Error('Could not send password reset email');
    }
  }
}
