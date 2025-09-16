const request = require('supertest');
const express = require('express');
const authRoutes = require('../src/routes/authRoutes');
const authController = require('../src/controllers/authController');

jest.mock('../src/controllers/authController');

const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);

describe('Auth Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /api/auth/register', () => {
    it('should call register controller', async () => {
      authController.register.mockImplementation((req, res) => {
        res.status(201).json({ message: 'User registered successfully' });
      });

      const userData = {
        first_name: 'John',
        last_name: 'Doe',
        email: 'john.doe@example.com',
        password: 'Password123!',
        address: '123 Test Street',
        phone: '0123456789'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(authController.register).toHaveBeenCalled();
      expect(response.body).toEqual({ message: 'User registered successfully' });
    });

    it('should handle registration errors', async () => {
      authController.register.mockImplementation((req, res) => {
        res.status(400).json({ message: 'Email already exists' });
      });

      const userData = {
        first_name: 'John',
        last_name: 'Doe',
        email: 'existing@example.com',
        password: 'Password123!',
        address: '123 Test Street',
        phone: '0123456789'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);

      expect(authController.register).toHaveBeenCalled();
      expect(response.body).toEqual({ message: 'Email already exists' });
    });
  });

  describe('POST /api/auth/login', () => {
    it('should call login controller', async () => {
      authController.login.mockImplementation((req, res) => {
        res.status(200).json({ accessToken: 'mock-access-token' });
      });

      const loginData = {
        email: 'john.doe@example.com',
        password: 'Password123!'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(200);

      expect(authController.login).toHaveBeenCalled();
      expect(response.body).toEqual({ accessToken: 'mock-access-token' });
    });

    it('should handle login errors', async () => {
      authController.login.mockImplementation((req, res) => {
        res.status(400).json({ message: 'Invalid credentials' });
      });

      const loginData = {
        email: 'john.doe@example.com',
        password: 'wrong-password'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(400);

      expect(authController.login).toHaveBeenCalled();
      expect(response.body).toEqual({ message: 'Invalid credentials' });
    });
  });

  describe('GET /api/auth/verify-email', () => {
    it('should call verifyEmail controller', async () => {
      authController.verifyEmail.mockImplementation((req, res) => {
        res.status(200).json({ message: 'Email verified successfully!' });
      });

      const response = await request(app)
        .get('/api/auth/verify-email')
        .query({ token: 'valid-token' })
        .expect(200);

      expect(authController.verifyEmail).toHaveBeenCalled();
      expect(response.body).toEqual({ message: 'Email verified successfully!' });
    });

    it('should handle verification errors', async () => {
      authController.verifyEmail.mockImplementation((req, res) => {
        res.status(400).json({ message: 'Invalid or expired token' });
      });

      const response = await request(app)
        .get('/api/auth/verify-email')
        .query({ token: 'invalid-token' })
        .expect(400);

      expect(authController.verifyEmail).toHaveBeenCalled();
      expect(response.body).toEqual({ message: 'Invalid or expired token' });
    });
  });

  describe('POST /api/auth/request-password', () => {
    it('should call requestPasswordReset controller', async () => {
      authController.requestPasswordReset.mockImplementation((req, res) => {
        res.status(200).json({ message: 'Password reset request sent successfully!' });
      });

      const response = await request(app)
        .post('/api/auth/request-password')
        .send({ email: 'john.doe@example.com' })
        .expect(200);

      expect(authController.requestPasswordReset).toHaveBeenCalled();
      expect(response.body).toEqual({ message: 'Password reset request sent successfully!' });
    });

    it('should handle request password reset errors', async () => {
      authController.requestPasswordReset.mockImplementation((req, res) => {
        res.status(400).json({ message: 'User not found' });
      });

      const response = await request(app)
        .post('/api/auth/request-password')
        .send({ email: 'nonexistent@example.com' })
        .expect(400);

      expect(authController.requestPasswordReset).toHaveBeenCalled();
      expect(response.body).toEqual({ message: 'User not found' });
    });
  });

  describe('POST /api/auth/reset-password', () => {
    it('should call resetPassword controller', async () => {
      authController.resetPassword.mockImplementation((req, res) => {
        res.status(200).json({ message: 'Password updated successfully!' });
      });

      const resetData = {
        token: 'valid-reset-token',
        newPassword: 'NewPassword123!'
      };

      const response = await request(app)
        .post('/api/auth/reset-password')
        .send(resetData)
        .expect(200);

      expect(authController.resetPassword).toHaveBeenCalled();
      expect(response.body).toEqual({ message: 'Password updated successfully!' });
    });

    it('should handle reset password errors', async () => {
      authController.resetPassword.mockImplementation((req, res) => {
        res.status(400).json({ message: 'Token invalide ou expiré' });
      });

      const resetData = {
        token: 'invalid-token',
        newPassword: 'NewPassword123!'
      };

      const response = await request(app)
        .post('/api/auth/reset-password')
        .send(resetData)
        .expect(400);

      expect(authController.resetPassword).toHaveBeenCalled();
      expect(response.body).toEqual({ message: 'Token invalide ou expiré' });
    });
  });

  describe('Route validation', () => {
    it('should return 404 for non-existent routes', async () => {
      await request(app)
        .get('/api/auth/non-existent')
        .expect(404);
    });

    it('should handle POST requests to GET-only routes', async () => {
      authController.verifyEmail.mockImplementation((req, res) => {
        res.status(405).json({ message: 'Method not allowed' });
      });

      await request(app)
        .post('/api/auth/verify-email')
        .send({ token: 'test' })
        .expect(404);
    });

    it('should handle GET requests to POST-only routes', async () => {
      await request(app)
        .get('/api/auth/register')
        .expect(404);
    });

    it('should accept JSON content type for POST routes', async () => {
      authController.register.mockImplementation((req, res) => {
        res.status(201).json({ message: 'User registered successfully' });
      });

      const userData = {
        first_name: 'John',
        last_name: 'Doe',
        email: 'john.doe@example.com',
        password: 'Password123!',
        address: '123 Test Street',
        phone: '0123456789'
      };

      await request(app)
        .post('/api/auth/register')
        .set('Content-Type', 'application/json')
        .send(userData)
        .expect(201);

      expect(authController.register).toHaveBeenCalled();
    });
  });
});
