const jwt = require('jsonwebtoken');
const authToken = require('../src/middlewares/authToken');

jest.mock('jsonwebtoken');

describe('Auth Token Middleware', () => {
  const mockUser = {
    id: 1,
    email: 'john.doe@example.com'
  };

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.JWT_SECRET = 'test-jwt-secret';
    process.env.JWT_REFRESH_SECRET = 'test-jwt-refresh-secret';
  });

  describe('generateAccessToken', () => {
    it('should generate access token with correct payload and options', () => {
      const mockToken = 'mock-access-token';
      jwt.sign.mockReturnValue(mockToken);

      const result = authToken.generateAccessToken(mockUser);

      expect(jwt.sign).toHaveBeenCalledWith(
        { id: mockUser.id, email: mockUser.email },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );
      expect(result).toBe(mockToken);
    });
  });

  describe('generateRefreshToken', () => {
    it('should generate refresh token with correct payload and options', () => {
      const mockToken = 'mock-refresh-token';
      jwt.sign.mockReturnValue(mockToken);

      const result = authToken.generateRefreshToken(mockUser);

      expect(jwt.sign).toHaveBeenCalledWith(
        { id: mockUser.id, email: mockUser.email },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
      );
      expect(result).toBe(mockToken);
    });
  });

  describe('authenticateToken', () => {
    let req, res, next;

    beforeEach(() => {
      req = {
        headers: {}
      };
      res = {
        sendStatus: jest.fn()
      };
      next = jest.fn();
    });

    it('should authenticate valid token successfully', () => {
      const mockToken = 'valid-token';
      const mockDecodedUser = { id: 1, email: 'john.doe@example.com' };

      req.headers['authorization'] = `Bearer ${mockToken}`;
      jwt.verify.mockImplementation((token, secret, callback) => {
        callback(null, mockDecodedUser);
      });

      authToken.authenticateToken(req, res, next);

      expect(jwt.verify).toHaveBeenCalledWith(
        mockToken,
        process.env.JWT_SECRET,
        expect.any(Function)
      );
      expect(req.user).toEqual(mockDecodedUser);
      expect(next).toHaveBeenCalled();
      expect(res.sendStatus).not.toHaveBeenCalled();
    });

    it('should return 401 if no token provided', () => {
      authToken.authenticateToken(req, res, next);

      expect(res.sendStatus).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if authorization header is missing', () => {
      req.headers['authorization'] = undefined;

      authToken.authenticateToken(req, res, next);

      expect(res.sendStatus).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if authorization header format is invalid', () => {
      req.headers['authorization'] = 'InvalidFormat';

      authToken.authenticateToken(req, res, next);

      expect(res.sendStatus).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 403 if token is invalid', () => {
      const mockToken = 'invalid-token';
      const mockError = new Error('Invalid token');

      req.headers['authorization'] = `Bearer ${mockToken}`;
      jwt.verify.mockImplementation((token, secret, callback) => {
        callback(mockError, null);
      });

      authToken.authenticateToken(req, res, next);

      expect(jwt.verify).toHaveBeenCalledWith(
        mockToken,
        process.env.JWT_SECRET,
        expect.any(Function)
      );
      expect(res.sendStatus).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
      expect(req.user).toBeUndefined();
    });

    it('should return 403 if token is expired', () => {
      const mockToken = 'expired-token';
      const mockError = new jwt.TokenExpiredError('Token expired', new Date());

      req.headers['authorization'] = `Bearer ${mockToken}`;
      jwt.verify.mockImplementation((token, secret, callback) => {
        callback(mockError, null);
      });

      authToken.authenticateToken(req, res, next);

      expect(res.sendStatus).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });


  });
});
