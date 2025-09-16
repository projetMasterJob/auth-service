const authModel = require('../src/models/authModel');
const pool = require('../src/config/dbConfig');

jest.mock('../src/config/dbConfig');

describe('Auth Model', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('findByEmail', () => {
    it('should find user by email', async () => {
      const mockUser = {
        id: 1,
        password_hash: 'hashed-password',
        is_verified: true
      };

      pool.query.mockResolvedValue({
        rows: [mockUser]
      });

      const result = await authModel.findByEmail('john.doe@example.com');

      expect(pool.query).toHaveBeenCalledWith(
        'SELECT id, password_hash, is_verified FROM users WHERE email = $1',
        ['john.doe@example.com']
      );
      expect(result).toEqual(mockUser);
    });

    it('should return undefined if user not found', async () => {
      pool.query.mockResolvedValue({
        rows: []
      });

      const result = await authModel.findByEmail('nonexistent@example.com');

      expect(result).toBeUndefined();
    });
  });

  describe('createUser', () => {
    it('should create user successfully', async () => {
      const userData = {
        first_name: 'John',
        last_name: 'Doe',
        email: 'john.doe@example.com',
        password_hash: 'hashed-password',
        address: '123 Test Street',
        phone: '0123456789',
        emailTokenHash: 'hashed-email-token',
        tokenExpiresAt: new Date()
      };

      const mockResult = { id: 1 };

      pool.query.mockResolvedValue({
        rows: [mockResult]
      });

      const result = await authModel.createUser(
        userData.first_name,
        userData.last_name,
        userData.email,
        userData.password_hash,
        userData.address,
        userData.phone,
        userData.emailTokenHash,
        userData.tokenExpiresAt
      );

      expect(pool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO users'),
        [
          userData.first_name,
          userData.last_name,
          userData.email,
          userData.password_hash,
          userData.address,
          userData.phone,
          userData.emailTokenHash,
          userData.tokenExpiresAt
        ]
      );
      expect(result).toEqual(mockResult);
    });
  });

  describe('insertRefreshToken', () => {
    it('should insert refresh token successfully', async () => {
      pool.query.mockResolvedValue({
        rowCount: 1
      });

      const result = await authModel.insertRefreshToken('refresh-token', 1);

      expect(pool.query).toHaveBeenCalledWith(
        `
    UPDATE users
    SET jwt_token = $1
    WHERE id = $2
  `,
        ['refresh-token', 1]
      );
      expect(result).toBe(1);
    });

    it('should return 0 if no rows affected', async () => {
      pool.query.mockResolvedValue({
        rowCount: 0
      });

      const result = await authModel.insertRefreshToken('refresh-token', 999);

      expect(result).toBe(0);
    });
  });

  describe('insertTokenMail', () => {
    it('should insert email token successfully', async () => {
      const tokenExpiresAt = new Date();

      pool.query.mockResolvedValue({
        rowCount: 1
      });

      const result = await authModel.insertTokenMail('email-token', tokenExpiresAt, 1);

      expect(pool.query).toHaveBeenCalledWith(
        `
    UPDATE users
    SET email_token = $1, email_token_expires_at = $2
    WHERE id = $3
  `,
        ['email-token', tokenExpiresAt, 1]
      );
      expect(result).toBe(1);
    });
  });

  describe('findByEmailToken', () => {
    it('should find user by email token', async () => {
      const mockUser = { id: 1 };

      pool.query.mockResolvedValue({
        rows: [mockUser]
      });

      const result = await authModel.findByEmailToken('email-token');

      expect(pool.query).toHaveBeenCalledWith(
        `
    SELECT id FROM users
    WHERE email_token = $1 AND email_token_expires_at > NOW()
  `,
        ['email-token']
      );
      expect(result).toEqual(mockUser);
    });

    it('should return undefined if token not found or expired', async () => {
      pool.query.mockResolvedValue({
        rows: []
      });

      const result = await authModel.findByEmailToken('invalid-token');

      expect(result).toBeUndefined();
    });
  });

  describe('deleteEmailToken', () => {
    it('should delete email token successfully', async () => {
      pool.query.mockResolvedValue({
        rowCount: 1
      });

      const result = await authModel.deleteEmailToken(1);

      expect(pool.query).toHaveBeenCalledWith(
        `
    UPDATE users
    SET email_token = NULL, email_token_expires_at = NULL
    WHERE id = $1
  `,
        [1]
      );
      expect(result).toBe(1);
    });
  });

  describe('setUserAsVerified', () => {
    it('should set user as verified successfully', async () => {
      pool.query.mockResolvedValue({
        rowCount: 1
      });

      const result = await authModel.setUserAsVerified(1);

      expect(pool.query).toHaveBeenCalledWith(
        `
    UPDATE users
    SET is_verified = TRUE
    WHERE id = $1
  `,
        [1]
      );
      expect(result).toBe(1);
    });
  });

  describe('setResetToken', () => {
    it('should set reset token successfully', async () => {
      const expiresAt = new Date();

      pool.query.mockResolvedValue({
        rowCount: 1
      });

      const result = await authModel.setResetToken(1, 'reset-token', expiresAt);

      expect(pool.query).toHaveBeenCalledWith(
        `
    UPDATE users
    SET reset_token = $1, reset_token_expires_at = $2
    WHERE id = $3
  `,
        ['reset-token', expiresAt, 1]
      );
      expect(result).toBe(1);
    });
  });

  describe('findByResetToken', () => {
    it('should find user by reset token', async () => {
      const mockUser = {
        id: 1,
        reset_token_expires_at: new Date()
      };

      pool.query.mockResolvedValue({
        rows: [mockUser]
      });

      const result = await authModel.findByResetToken('reset-token');

      expect(pool.query).toHaveBeenCalledWith(
        `
    SELECT id, reset_token_expires_at FROM users
    WHERE reset_token = $1 AND reset_token_expires_at > NOW()
  `,
        ['reset-token']
      );
      expect(result).toEqual(mockUser);
    });

    it('should return undefined if token not found or expired', async () => {
      pool.query.mockResolvedValue({
        rows: []
      });

      const result = await authModel.findByResetToken('invalid-token');

      expect(result).toBeUndefined();
    });
  });

  describe('updateUserPassword', () => {
    it('should update user password successfully', async () => {
      pool.query.mockResolvedValue({
        rowCount: 1
      });

      const result = await authModel.updateUserPassword(1, 'new-hashed-password');

      expect(pool.query).toHaveBeenCalledWith(
        `
    UPDATE users
    SET password_hash = $1, reset_token = NULL, reset_token_expires_at = NULL
    WHERE id = $2
  `,
        ['new-hashed-password', 1]
      );
      expect(result).toBe(1);
    });

    it('should return 0 if user not found', async () => {
      pool.query.mockResolvedValue({
        rowCount: 0
      });

      const result = await authModel.updateUserPassword(999, 'new-hashed-password');

      expect(result).toBe(0);
    });
  });
});
