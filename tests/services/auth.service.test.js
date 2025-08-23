// tests/unit/services/auth.service.test.js

jest.mock('../../src/models/authModel', () => ({
  findByEmail: jest.fn(),
  createUser: jest.fn(),
  createCompany: jest.fn(),
  insertRefreshToken: jest.fn(),
  findByEmailToken: jest.fn(),
  setUserAsVerified: jest.fn(),
  deleteEmailToken: jest.fn(),
  setResetToken: jest.fn(),
  findByResetToken: jest.fn(),
  updateUserPassword: jest.fn(),
  findById: jest.fn(),
  updateUserJwtToken: jest.fn(),
}));

jest.mock('bcrypt', () => ({
  hash: jest.fn(async (pwd) => `hashed(${pwd})`),
  compare: jest.fn(async () => true),
}));

const mockUpdate = jest.fn().mockReturnThis();
const mockDigest = jest.fn(() => 'sha256(<input>)');

jest.mock('crypto', () => {
  const randomBytes = jest.fn(() => Buffer.from('a1b2', 'hex')); // => "a1b2"
  const createHash = jest.fn(() => ({ update: mockUpdate, digest: mockDigest }));
  // Supporte require('crypto') ET import crypto from 'crypto'
  return {
    __esModule: true,
    randomBytes,
    createHash,
    default: { randomBytes, createHash },
  };
});

jest.mock('../../src/middlewares/authToken', () => {
  const crypto = require('crypto');
  return {
    generateAccessToken: jest.fn(() => 'access.jwt'),
    generateRefreshToken: jest.fn(() => 'refresh.jwt'),
    hash: (v) => crypto.createHash('sha256').update(v).digest('hex'),
    verifyRefreshToken: jest.fn((token) => ({ sub: 42, typ: 'refresh' })),
  };
});

jest.mock('../../src/utils/mailer', () => ({
  sendValidationEmail: jest.fn(async () => {}),
  sendResetPasswordEmail: jest.fn(async () => {}),
}));

jest.mock('validator', () => ({
  isEmail: jest.fn(() => true),
  isURL: jest.fn(() => true),
}));

const authModel = require('../../src/models/authModel');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const authToken = require('../../src/middlewares/authToken');
const mailer = require('../../src/utils/mailer');
const validator = require('validator');

const service = require('../../src/services/authService');

describe('authService', () => {
  const OLD_ENV = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...OLD_ENV, URL_AUTH: 'https://auth.example.com' };
  });

  afterAll(() => {
    process.env = OLD_ENV;
  });

  // ---------------- REGISTER USER ----------------
  describe('registerUser', () => {
    const baseArgs = {
      first_name: 'Ada',
      last_name: 'Lovelace',
      email: 'ada@example.com',
      password: 'Str0ng!',
      address: '10 Downing St',
      phone: '0102030405',
      role: 'user',
      company: undefined,
    };

    test('refuse email invalide', async () => {
      validator.isEmail.mockReturnValueOnce(false);

      await expect(service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, baseArgs.password,
        baseArgs.address, baseArgs.phone, baseArgs.role, baseArgs.company
      )).rejects.toThrow('Adresse email invalide');

      expect(validator.isEmail).toHaveBeenCalledWith('ada@example.com');
    });

    test('refuse mot de passe trop court', async () => {
      await expect(service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, '123',
        baseArgs.address, baseArgs.phone, baseArgs.role, baseArgs.company
      )).rejects.toThrow('Le mot de passe doit contenir au moins 6 caractères');
    });

    test('refuse mot de passe non conforme (complexité)', async () => {
      // 6+ chars mais pas de majuscule, etc.
      await expect(service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, 'password',
        baseArgs.address, baseArgs.phone, baseArgs.role, baseArgs.company
      )).rejects.toThrow('Le mot de passe doit contenir une majuscule, une minuscule, un chiffre et un caractère spécial');
    });

    test('refuse role invalide', async () => {
      await expect(service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, 'Abcdef1!',
        baseArgs.address, baseArgs.phone, 'admin', baseArgs.company
      )).rejects.toThrow("Rôle invalide (attendu: 'user' ou 'pro')");
    });

    test('role=pro : refuse company manquante', async () => {
      await expect(service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, 'Abcdef1!',
        baseArgs.address, baseArgs.phone, 'pro', undefined
      )).rejects.toThrow('Les informations entreprise sont requises pour role=pro');
    });

    test('role=pro : refuse champs company manquants', async () => {
      await expect(service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, 'Abcdef1!',
        baseArgs.address, baseArgs.phone, 'pro', { name: 'ACME' }
      )).rejects.toThrow('Champs entreprise manquants: name, description et website sont requis');
    });

    test('role=pro : refuse URL invalide', async () => {
      validator.isURL.mockReturnValueOnce(false);

      await expect(service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, 'Abcdef1!',
        baseArgs.address, baseArgs.phone, 'pro', { name: 'ACME', description: 'desc', website: 'http://bad' }
      )).rejects.toThrow('URL du site entreprise invalide (ex: https://exemple.com)');

      expect(validator.isURL).toHaveBeenCalledWith('http://bad', { require_protocol: true });
    });

    test("refuse si l'email existe déjà", async () => {
      authModel.findByEmail.mockResolvedValueOnce({ id: 1 });

      await expect(service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, 'Abcdef1!',
        baseArgs.address, baseArgs.phone, baseArgs.role, baseArgs.company
      )).rejects.toThrow('Email already exists');
    });

    test('crée user (role=user), hash mdp, email de validation envoyé', async () => {
      authModel.findByEmail.mockResolvedValueOnce(null);
      authModel.createUser.mockResolvedValueOnce({ id: 42 });
      // role=user -> pas de createCompany

      await service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, 'Abcdef1!',
        baseArgs.address, baseArgs.phone, 'user', undefined
      );

      expect(bcrypt.hash).toHaveBeenCalledWith('Abcdef1!', 10);
      expect(authModel.createUser).toHaveBeenCalled();

      // crypto.randomBytes -> "a1b2" (hex)
      const expectedUrl = 'https://auth.example.com/verify-email?token=a1b2';
      expect(mailer.sendValidationEmail).toHaveBeenCalledWith('ada@example.com', expectedUrl);

      // On a bien hashé le token email via createHash/update/digest
      expect(crypto.createHash).toHaveBeenCalledWith('sha256');
      expect(mockUpdate).toHaveBeenCalled(); // argument = "a1b2"
      expect(mockDigest).toHaveBeenCalledWith('hex');
    });

    test('crée user + company (role=pro)', async () => {
      authModel.findByEmail.mockResolvedValueOnce(null);
      authModel.createUser.mockResolvedValueOnce({ id: 99 });
      authModel.createCompany.mockResolvedValueOnce({ id: 7 });
      validator.isURL.mockReturnValueOnce(true);

      await service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, 'Abcdef1!',
        baseArgs.address, baseArgs.phone, 'pro',
        { name: 'ACME', description: 'desc', website: 'https://acme.com' }
      );

      expect(authModel.createCompany).toHaveBeenCalledWith(99, { name: 'ACME', description: 'desc', website: 'https://acme.com' });
      expect(mailer.sendValidationEmail).toHaveBeenCalled();
    });

    test('erreur si createUser échoue', async () => {
      authModel.findByEmail.mockResolvedValueOnce(null);
      authModel.createUser.mockResolvedValueOnce(null);

      await expect(service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, 'Abcdef1!',
        baseArgs.address, baseArgs.phone, 'user', undefined
      )).rejects.toThrow('Error while creating user');
    });

    test('erreur si createCompany échoue (role=pro)', async () => {
      authModel.findByEmail.mockResolvedValueOnce(null);
      authModel.createUser.mockResolvedValueOnce({ id: 1 });
      authModel.createCompany.mockResolvedValueOnce(null);
      validator.isURL.mockReturnValueOnce(true);

      await expect(service.registerUser(
        baseArgs.first_name, baseArgs.last_name, baseArgs.email, 'Abcdef1!',
        baseArgs.address, baseArgs.phone, 'pro',
        { name: 'ACME', description: 'desc', website: 'https://acme.com' }
      )).rejects.toThrow('Error while creating company');
    });
  });

  // ---------------- LOGIN USER ----------------
  describe('loginUser', () => {
    test('refuse si user inexistant', async () => {
      authModel.findByEmail.mockResolvedValueOnce(null);

      await expect(service.loginUser('a@b.c', 'x')).rejects.toThrow('Cannot find user');
    });

    test('refuse si mauvais mot de passe', async () => {
      authModel.findByEmail.mockResolvedValueOnce({ id: 1, password_hash: 'h', is_verified: true });
      bcrypt.compare.mockResolvedValueOnce(false);

      await expect(service.loginUser('a@b.c', 'bad')).rejects.toThrow('Invalid credentials');
    });

    test('refuse si email non vérifié', async () => {
      authModel.findByEmail.mockResolvedValueOnce({ id: 1, password_hash: 'h', is_verified: false });

      await expect(service.loginUser('a@b.c', 'ok')).rejects.toThrow('Email not verified');
    });

    test('succès : génère tokens, stocke refresh hash et renvoie tokens', async () => {
      authModel.findByEmail.mockResolvedValueOnce({ id: 42, password_hash: 'h', is_verified: true });
      authModel.insertRefreshToken.mockResolvedValueOnce(1);

      const res = await service.loginUser('a@b.c', 'ok');

      expect(authToken.generateAccessToken).toHaveBeenCalled();
      expect(authToken.generateRefreshToken).toHaveBeenCalled();

      // refresh hash via createHash/update/digest
      expect(crypto.createHash).toHaveBeenCalledWith('sha256');
      expect(authModel.insertRefreshToken).toHaveBeenCalledWith('sha256(<input>)', 42);

      expect(res).toEqual({ accessToken: 'access.jwt', refreshToken: 'refresh.jwt' });
    });

    test('erreur si insertRefreshToken échoue', async () => {
      authModel.findByEmail.mockResolvedValueOnce({ id: 42, password_hash: 'h', is_verified: true });
      authModel.insertRefreshToken.mockResolvedValueOnce(0);

      await expect(service.loginUser('a@b.c', 'ok')).rejects.toThrow('Error while updating refresh token');
    });
  });

  // ---------------- VERIFY EMAIL TOKEN ----------------
  describe('verifyEmailToken', () => {
    test('refuse token invalide/expiré', async () => {
      authModel.findByEmailToken.mockResolvedValueOnce(null);

      await expect(service.verifyEmailToken('tok')).rejects.toThrow('Invalid or expired token');
    });

    test('succès : set user verified + delete token', async () => {
      authModel.findByEmailToken.mockResolvedValueOnce({ id: 7 });

      await service.verifyEmailToken('tok');

      expect(crypto.createHash).toHaveBeenCalledWith('sha256');
      expect(mockUpdate).toHaveBeenCalledWith('tok');
      expect(mockDigest).toHaveBeenCalledWith('hex');
      expect(authModel.setUserAsVerified).toHaveBeenCalledWith(7);
      expect(authModel.deleteEmailToken).toHaveBeenCalledWith(7);
    });
  });

  // ---------------- REQUEST PASSWORD RESET ----------------
  describe('requestPasswordReset', () => {
    test('ne fait rien si user introuvable (pas d’erreur)', async () => {
      authModel.findByEmail.mockResolvedValueOnce(null);

      await service.requestPasswordReset('unknown@example.com');

      expect(authModel.setResetToken).not.toHaveBeenCalled();
      expect(mailer.sendResetPasswordEmail).not.toHaveBeenCalled();
    });

    test('succès : set reset token + envoi email', async () => {
      authModel.findByEmail.mockResolvedValueOnce({ id: 5, email: 'ada@example.com' });

      await service.requestPasswordReset('ada@example.com');

      // randomBytes -> "a1b2" ; URL construit avec ce token
      const expectedUrl = 'https://auth.example.com/reset-password?token=a1b2';
      expect(authModel.setResetToken).toHaveBeenCalled();
      expect(mailer.sendResetPasswordEmail).toHaveBeenCalledWith('ada@example.com', expectedUrl);
    });
  });

  // ---------------- RESET PASSWORD ----------------
  describe('resetPassword', () => {
    test('refuse si token inexistant ou expiré', async () => {
      // Cas 1: aucun user
      authModel.findByResetToken.mockResolvedValueOnce(null);
      await expect(service.resetPassword('tok', 'NewPass1!')).rejects.toThrow('Token invalide ou expiré');

      // Cas 2: expiré
      authModel.findByResetToken.mockResolvedValueOnce({ id: 1, reset_password_expires_at: new Date(Date.now() - 1000) });
      await expect(service.resetPassword('tok', 'NewPass1!')).rejects.toThrow('Token invalide ou expiré');
    });

    test('succès : hash le nouveau mdp et met à jour', async () => {
      authModel.findByResetToken.mockResolvedValueOnce({
        id: 10,
        reset_password_expires_at: new Date(Date.now() + 60_000),
      });

      await service.resetPassword('tok', 'NewPass1!');

      expect(crypto.createHash).toHaveBeenCalledWith('sha256');
      expect(bcrypt.hash).toHaveBeenCalledWith('NewPass1!', 10);
      expect(authModel.updateUserPassword).toHaveBeenCalledWith(10, 'hashed(NewPass1!)');
    });
  });

  // ---------------- REFRESH TOKEN ----------------
  describe('refreshToken (service)', () => {
    const TOKEN_IN = 'ref.token.any';
    const HASHED = 'sha256(<input>)'; // cohérent avec le mock de crypto

    afterEach(() => {
      jest.clearAllMocks();
    });

    test('succès : vérifie, match le hash, génère & rotate', async () => {
      // verify OK
      authToken.verifyRefreshToken.mockReturnValueOnce({ sub: 123, typ: 'refresh' });
      // user avec hash en base qui matche
      authModel.findById.mockResolvedValueOnce({ id: 123, jwt_token: HASHED, role: 'user' });
      // update OK
      authModel.updateUserJwtToken.mockResolvedValueOnce(1);

      const out = await service.refreshToken(TOKEN_IN);

      // vérifications
      expect(authToken.verifyRefreshToken).toHaveBeenCalledWith(TOKEN_IN);
      expect(authModel.findById).toHaveBeenCalledWith(123);
      // on a bien re-hashé l'ancien token reçu
      const crypto = require('crypto');
      expect(crypto.createHash).toHaveBeenCalledWith('sha256');

      expect(authToken.generateAccessToken).toHaveBeenCalled();
      expect(authToken.generateRefreshToken).toHaveBeenCalled();

      // rotation : nouveau hash persisté
      expect(authModel.updateUserJwtToken).toHaveBeenCalledWith(123, HASHED);

      expect(out).toEqual({ accessToken: 'access.jwt', refreshToken: 'refresh.jwt' });
    });

    test('REFRESH_EXPIRED : verify lève TokenExpiredError', async () => {
      const e = new Error('jwt expired');
      e.name = 'TokenExpiredError';
      authToken.verifyRefreshToken.mockImplementationOnce(() => { throw e; });

      await expect(service.refreshToken(TOKEN_IN)).rejects.toMatchObject({
        message: 'RefreshExpired',
        code: 'REFRESH_EXPIRED',
      });
    });

    test('REFRESH_INVALID : verify lève autre erreur', async () => {
      authToken.verifyRefreshToken.mockImplementationOnce(() => { throw new Error('bad'); });

      await expect(service.refreshToken(TOKEN_IN)).rejects.toMatchObject({
        message: 'Invalid refresh token',
        code: 'REFRESH_INVALID',
      });
    });

    test('REFRESH_INVALID : payload typ != refresh', async () => {
      authToken.verifyRefreshToken.mockReturnValueOnce({ sub: 1, typ: 'access' });

      await expect(service.refreshToken(TOKEN_IN)).rejects.toMatchObject({
        message: 'Invalid refresh token',
        code: 'REFRESH_INVALID',
      });
    });

    test('REFRESH_INVALID : user introuvable', async () => {
      authToken.verifyRefreshToken.mockReturnValueOnce({ sub: 999, typ: 'refresh' });
      authModel.findById.mockResolvedValueOnce(null);

      await expect(service.refreshToken(TOKEN_IN)).rejects.toMatchObject({
        message: 'Invalid refresh token',
        code: 'REFRESH_INVALID',
      });
    });

    test('REFRESH_MISMATCH : hash différent', async () => {
      authToken.verifyRefreshToken.mockReturnValueOnce({ sub: 7, typ: 'refresh' });
      // hash en base ≠ hash(token entrant)
      authModel.findById.mockResolvedValueOnce({ id: 7, jwt_token: 'not-matching' });

      await expect(service.refreshToken(TOKEN_IN)).rejects.toMatchObject({
        message: 'Invalid refresh token',
        code: 'REFRESH_MISMATCH',
      });
    });

    test('ROTATE_FAILED : updateUserJwtToken échoue', async () => {
      authToken.verifyRefreshToken.mockReturnValueOnce({ sub: 1, typ: 'refresh' });
      authModel.findById.mockResolvedValueOnce({ id: 1, jwt_token: HASHED });
      authModel.updateUserJwtToken.mockResolvedValueOnce(0); // falsy

      await expect(service.refreshToken(TOKEN_IN)).rejects.toMatchObject({
        message: 'Failed to rotate refresh',
        code: 'ROTATE_FAILED',
      });
    });
  });
});
