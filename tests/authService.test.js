const authService = require('../src/services/authService');
const authModel = require('../src/models/authModel');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const authToken = require('../src/middlewares/authToken');
const mailer = require('../src/utils/mailer');
const validator = require('validator');

jest.mock('../src/models/authModel');
jest.mock('bcrypt');
jest.mock('crypto');
jest.mock('../src/middlewares/authToken');
jest.mock('../src/utils/mailer');
jest.mock('validator');

describe('Auth Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('registerUser', () => {
    const validUserData = {
      first_name: 'John',
      last_name: 'Doe',
      email: 'john.doe@example.com',
      password: 'Password123!',
      address: '123 Test Street',
      phone: '0123456789'
    };

    it('should register a user successfully', async () => {
      validator.isEmail.mockReturnValue(true);
      authModel.findByEmail.mockResolvedValue(null);
      bcrypt.hash.mockResolvedValue('hashed-password');
      crypto.randomBytes.mockReturnValue({ toString: () => 'email-token' });
      crypto.createHash.mockReturnValue({
        update: () => ({ digest: () => 'hashed-email-token' })
      });
      authModel.createUser.mockResolvedValue({ id: 1 });
      mailer.sendValidationEmail.mockResolvedValue();

      process.env.URL_AUTH = 'http://localhost:5000';

      await authService.registerUser(
        validUserData.first_name,
        validUserData.last_name,
        validUserData.email,
        validUserData.password,
        validUserData.address,
        validUserData.phone
      );

      expect(validator.isEmail).toHaveBeenCalledWith(validUserData.email);
      expect(authModel.findByEmail).toHaveBeenCalledWith(validUserData.email);
      expect(bcrypt.hash).toHaveBeenCalledWith(validUserData.password, 10);
      expect(authModel.createUser).toHaveBeenCalled();
      expect(mailer.sendValidationEmail).toHaveBeenCalled();
    });

    it('should throw error for invalid email', async () => {
      validator.isEmail.mockReturnValue(false);

      await expect(
        authService.registerUser(
          validUserData.first_name,
          validUserData.last_name,
          'invalid-email',
          validUserData.password,
          validUserData.address,
          validUserData.phone
        )
      ).rejects.toThrow('Adresse email invalide');
    });

    it('should throw error for short password', async () => {
      validator.isEmail.mockReturnValue(true);

      await expect(
        authService.registerUser(
          validUserData.first_name,
          validUserData.last_name,
          validUserData.email,
          'short',
          validUserData.address,
          validUserData.phone
        )
      ).rejects.toThrow('Le mot de passe doit contenir au moins 6 caractères');
    });

    it('should throw error for weak password', async () => {
      validator.isEmail.mockReturnValue(true);

      await expect(
        authService.registerUser(
          validUserData.first_name,
          validUserData.last_name,
          validUserData.email,
          'weakpassword',
          validUserData.address,
          validUserData.phone
        )
      ).rejects.toThrow('Le mot de passe doit contenir une majuscule, une minuscule, un chiffre et un caractère spécial');
    });

    it('should throw error for existing email', async () => {
      validator.isEmail.mockReturnValue(true);
      authModel.findByEmail.mockResolvedValue({ id: 1 });

      await expect(
        authService.registerUser(
          validUserData.first_name,
          validUserData.last_name,
          validUserData.email,
          validUserData.password,
          validUserData.address,
          validUserData.phone
        )
      ).rejects.toThrow('Email already exists');
    });
  });

  describe('loginUser', () => {
    const validUser = {
      id: 1,
      email: 'john.doe@example.com',
      password_hash: 'hashed-password',
      is_verified: true
    };

    it('should login user successfully', async () => {
      authModel.findByEmail.mockResolvedValue(validUser);
      bcrypt.compare.mockResolvedValue(true);
      authToken.generateAccessToken.mockReturnValue('access-token');
      authToken.generateRefreshToken.mockReturnValue('refresh-token');
      crypto.createHash.mockReturnValue({
        update: () => ({ digest: () => 'hashed-refresh-token' })
      });
      authModel.insertRefreshToken.mockResolvedValue(1);

      const result = await authService.loginUser(validUser.email, 'password');

      expect(result).toEqual({
        accessToken: 'access-token',
        refreshToken: 'refresh-token'
      });
      expect(authModel.findByEmail).toHaveBeenCalledWith(validUser.email);
      expect(bcrypt.compare).toHaveBeenCalledWith('password', validUser.password_hash);
    });

    it('should throw error for non-existent user', async () => {
      authModel.findByEmail.mockResolvedValue(null);

      await expect(
        authService.loginUser('nonexistent@example.com', 'password')
      ).rejects.toThrow('Cannot find user');
    });

    it('should throw error for invalid password', async () => {
      authModel.findByEmail.mockResolvedValue(validUser);
      bcrypt.compare.mockResolvedValue(false);

      await expect(
        authService.loginUser(validUser.email, 'wrong-password')
      ).rejects.toThrow('Invalid credentials');
    });

    it('should throw error for unverified email', async () => {
      const unverifiedUser = { ...validUser, is_verified: false };
      authModel.findByEmail.mockResolvedValue(unverifiedUser);
      bcrypt.compare.mockResolvedValue(true);

      await expect(
        authService.loginUser(validUser.email, 'password')
      ).rejects.toThrow('Email not verified');
    });
  });

  describe('verifyEmailToken', () => {
    it('should verify email token successfully', async () => {
      const token = 'valid-token';
      const user = { id: 1 };

      crypto.createHash.mockReturnValue({
        update: () => ({ digest: () => 'hashed-token' })
      });
      authModel.findByEmailToken.mockResolvedValue(user);
      authModel.setUserAsVerified.mockResolvedValue();
      authModel.deleteEmailToken.mockResolvedValue();

      await authService.verifyEmailToken(token);

      expect(authModel.findByEmailToken).toHaveBeenCalledWith('hashed-token');
      expect(authModel.setUserAsVerified).toHaveBeenCalledWith(user.id);
      expect(authModel.deleteEmailToken).toHaveBeenCalledWith(user.id);
    });

    it('should throw error for invalid token', async () => {
      crypto.createHash.mockReturnValue({
        update: () => ({ digest: () => 'hashed-token' })
      });
      authModel.findByEmailToken.mockResolvedValue(null);

      await expect(
        authService.verifyEmailToken('invalid-token')
      ).rejects.toThrow('Invalid or expired token');
    });
  });

  describe('requestPasswordReset', () => {
    it('should request password reset successfully', async () => {
      const user = { id: 1, email: 'john.doe@example.com' };
      
      authModel.findByEmail.mockResolvedValue(user);
      crypto.randomBytes.mockReturnValue({ toString: () => 'reset-token' });
      crypto.createHash.mockReturnValue({
        update: () => ({ digest: () => 'hashed-reset-token' })
      });
      authModel.setResetToken.mockResolvedValue();
      mailer.sendResetPasswordEmail.mockResolvedValue();

      process.env.URL_AUTH = 'http://localhost:5000';

      await authService.requestPasswordReset(user.email);

      expect(authModel.findByEmail).toHaveBeenCalledWith(user.email);
      expect(authModel.setResetToken).toHaveBeenCalled();
      expect(mailer.sendResetPasswordEmail).toHaveBeenCalled();
    });

    it('should return silently for non-existent user', async () => {
      authModel.findByEmail.mockResolvedValue(null);

      await expect(
        authService.requestPasswordReset('nonexistent@example.com')
      ).resolves.toBeUndefined();
    });
  });

  describe('resetPassword', () => {
    it('should reset password successfully', async () => {
      const user = {
        id: 1,
        reset_password_expires_at: new Date(Date.now() + 60000)
      };

      crypto.createHash.mockReturnValue({
        update: () => ({ digest: () => 'hashed-token' })
      });
      authModel.findByResetToken.mockResolvedValue(user);
      bcrypt.hash.mockResolvedValue('new-hashed-password');
      authModel.updateUserPassword.mockResolvedValue();

      await authService.resetPassword('valid-token', 'NewPassword123!');

      expect(authModel.findByResetToken).toHaveBeenCalledWith('hashed-token');
      expect(bcrypt.hash).toHaveBeenCalledWith('NewPassword123!', 10);
      expect(authModel.updateUserPassword).toHaveBeenCalledWith(user.id, 'new-hashed-password');
    });

    it('should throw error for invalid token', async () => {
      crypto.createHash.mockReturnValue({
        update: () => ({ digest: () => 'hashed-token' })
      });
      authModel.findByResetToken.mockResolvedValue(null);

      await expect(
        authService.resetPassword('invalid-token', 'NewPassword123!')
      ).rejects.toThrow('Token invalide ou expiré');
    });

    it('should throw error for expired token', async () => {
      const user = {
        id: 1,
        reset_password_expires_at: new Date(Date.now() - 60000)
      };

      crypto.createHash.mockReturnValue({
        update: () => ({ digest: () => 'hashed-token' })
      });
      authModel.findByResetToken.mockResolvedValue(user);

      await expect(
        authService.resetPassword('expired-token', 'NewPassword123!')
      ).rejects.toThrow('Token invalide ou expiré');
    });
  });
});
