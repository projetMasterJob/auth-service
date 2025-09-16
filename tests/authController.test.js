const request = require('supertest');
const express = require('express');
const authController = require('../src/controllers/authController');
const authService = require('../src/services/authService');

jest.mock('../src/services/authService');

const app = express();
app.use(express.json());

app.post('/register', authController.register);
app.post('/login', authController.login);
app.get('/verify-email', authController.verifyEmail);
app.post('/request-password-reset', authController.requestPasswordReset);
app.post('/reset-password', authController.resetPassword);

describe('Auth Controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /register', () => {
    it('should register a user successfully', async () => {
      const userData = {
        first_name: 'John',
        last_name: 'Doe',
        email: 'john.doe@example.com',
        password: 'Password123!',
        address: '123 Test Street',
        phone: '0123456789',
        role: 'user'
      };

      authService.registerUser.mockResolvedValue();

      const response = await request(app)
        .post('/register')
        .send(userData)
        .expect(201);

      expect(response.body).toEqual({ message: 'User registered successfully' });
      expect(authService.registerUser).toHaveBeenCalledWith(
        userData.first_name,
        userData.last_name,
        userData.email,
        userData.password,
        userData.address,
        userData.phone,
        userData.role
      );
    });

    it('should return 400 if registration fails', async () => {
      const userData = {
        first_name: 'John',
        last_name: 'Doe',
        email: 'invalid-email',
        password: 'weak',
        address: '123 Test Street',
        phone: '0123456789'
      };

      authService.registerUser.mockRejectedValue(new Error('Adresse email invalide'));

      const response = await request(app)
        .post('/register')
        .send(userData)
        .expect(400);

      expect(response.body).toEqual({ message: 'Adresse email invalide' });
    });
  });

  describe('POST /login', () => {
    it('should login user successfully', async () => {
      const loginData = {
        email: 'john.doe@example.com',
        password: 'Password123!'
      };

      const mockTokens = {
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token'
      };

      authService.loginUser.mockResolvedValue(mockTokens);

      const response = await request(app)
        .post('/login')
        .send(loginData)
        .expect(200);

      expect(response.body).toEqual({ accessToken: mockTokens.accessToken });
      expect(authService.loginUser).toHaveBeenCalledWith(loginData.email, loginData.password);
    });

    it('should return 400 if login fails', async () => {
      const loginData = {
        email: 'john.doe@example.com',
        password: 'wrong-password'
      };

      authService.loginUser.mockRejectedValue(new Error('Invalid credentials'));

      const response = await request(app)
        .post('/login')
        .send(loginData)
        .expect(400);

      expect(response.body).toEqual({ message: 'Invalid credentials' });
    });
  });

  describe('GET /verify-email', () => {
    it('should verify email successfully', async () => {
      const token = 'valid-token';

      authService.verifyEmailToken.mockResolvedValue();

      const response = await request(app)
        .get('/verify-email')
        .query({ token })
        .expect(200);

      expect(response.body).toEqual({ message: 'Email verified successfully!' });
      expect(authService.verifyEmailToken).toHaveBeenCalledWith(token);
    });

    it('should return 400 if token is invalid', async () => {
      const token = 'invalid-token';

      authService.verifyEmailToken.mockRejectedValue(new Error('Invalid or expired token'));

      const response = await request(app)
        .get('/verify-email')
        .query({ token })
        .expect(400);

      expect(response.body).toEqual({ message: 'Invalid or expired token' });
    });
  });

  describe('POST /request-password-reset', () => {
    it('should request password reset successfully', async () => {
      const email = 'john.doe@example.com';

      authService.requestPasswordReset.mockResolvedValue();

      const response = await request(app)
        .post('/request-password-reset')
        .send({ email })
        .expect(200);

      expect(response.body).toEqual({ message: 'Password reset request sent successfully!' });
      expect(authService.requestPasswordReset).toHaveBeenCalledWith(email);
    });

    it('should return 400 if request fails', async () => {
      const email = 'nonexistent@example.com';

      authService.requestPasswordReset.mockRejectedValue(new Error('User not found'));

      const response = await request(app)
        .post('/request-password-reset')
        .send({ email })
        .expect(400);

      expect(response.body).toEqual({ message: 'User not found' });
    });
  });

  describe('POST /reset-password', () => {
    it('should reset password successfully', async () => {
      const resetData = {
        token: 'valid-reset-token',
        newPassword: 'NewPassword123!'
      };

      authService.resetPassword.mockResolvedValue();

      const response = await request(app)
        .post('/reset-password')
        .send(resetData)
        .expect(200);

      expect(response.body).toEqual({ message: 'Password updated successfully!' });
      expect(authService.resetPassword).toHaveBeenCalledWith(resetData.token, resetData.newPassword);
    });

    it('should return 400 if reset fails', async () => {
      const resetData = {
        token: 'invalid-token',
        newPassword: 'NewPassword123!'
      };

      authService.resetPassword.mockRejectedValue(new Error('Token invalide ou expiré'));

      const response = await request(app)
        .post('/reset-password')
        .send(resetData)
        .expect(400);

      expect(response.body).toEqual({ message: 'Token invalide ou expiré' });
    });
  });
});
