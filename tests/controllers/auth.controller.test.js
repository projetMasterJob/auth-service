// tests/unit/controllers/auth.controller.test.js
// Hypothèses de chemins :
// - Controller: src/controllers/authController.js
// - Service   : src/services/authService.js
// Adapte les chemins si besoin.

jest.mock('../../src/services/authService', () => ({
  registerUser: jest.fn(),
  loginUser: jest.fn(),
  verifyEmailToken: jest.fn(),
  requestPasswordReset: jest.fn(),
  resetPassword: jest.fn(),
}));

const authService = require('../../src/services/authService');
const controller = require('../../src/controllers/authController');

const makeRes = () => {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  return res;
};

beforeEach(() => {
  jest.clearAllMocks();
});

describe('authController.register', () => {
  test('201 + message si inscription ok', async () => {
    const req = {
      body: {
        first_name: 'Ada',
        last_name: 'Lovelace',
        email: 'ada@example.com',
        password: 'Secret123!',
        address: '10 Downing St',
        phone: '0102030405',
        role: 'user',
        company: 'Analytical Inc',
      },
    };
    const res = makeRes();

    await controller.register(req, res);

    expect(authService.registerUser).toHaveBeenCalledWith(
      'Ada',
      'Lovelace',
      'ada@example.com',
      'Secret123!',
      '10 Downing St',
      '0102030405',
      'user',
      'Analytical Inc'
    );
    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({ message: 'User registered successfully' });
  });

  test('400 + message si service lève une erreur', async () => {
    authService.registerUser.mockRejectedValue(new Error('Email already used'));
    const req = { body: { first_name: 'A', last_name: 'B', email: 'a@b.c', password: 'x' } };
    const res = makeRes();

    await controller.register(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ message: 'Email already used' });
  });
});

describe('authController.login', () => {
  test('200 + accessToken si login ok', async () => {
    authService.loginUser.mockResolvedValue({ accessToken: 'acc123', refreshToken: 'ref456' });
    const req = { body: { email: 'ada@example.com', password: 'Secret123!' } };
    const res = makeRes();

    await controller.login(req, res);

    expect(authService.loginUser).toHaveBeenCalledWith('ada@example.com', 'Secret123!');
    expect(res.status).toHaveBeenCalledWith(200);
    // le controller ne renvoie que accessToken (pas le refreshToken)
    expect(res.json).toHaveBeenCalledWith({ accessToken: 'acc123' });
  });

  test('400 + message si service lève une erreur', async () => {
    authService.loginUser.mockRejectedValue(new Error('Invalid credentials'));
    const req = { body: { email: 'x@y.z', password: 'bad' } };
    const res = makeRes();

    await controller.login(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ message: 'Invalid credentials' });
  });
});

describe('authController.verifyEmail', () => {
  test('200 + message si vérification ok', async () => {
    const req = { query: { token: 'tok-verify' } };
    const res = makeRes();

    await controller.verifyEmail(req, res);

    expect(authService.verifyEmailToken).toHaveBeenCalledWith('tok-verify');
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ message: 'Email verified successfully!' });
  });

  test('400 + message si token invalide', async () => {
    authService.verifyEmailToken.mockRejectedValue(new Error('Invalid or expired token'));
    const req = { query: { token: 'bad' } };
    const res = makeRes();

    await controller.verifyEmail(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ message: 'Invalid or expired token' });
  });
});

describe('authController.requestPasswordReset', () => {
  test('200 + message si envoi ok', async () => {
    const req = { body: { email: 'ada@example.com' } };
    const res = makeRes();

    await controller.requestPasswordReset(req, res);

    expect(authService.requestPasswordReset).toHaveBeenCalledWith('ada@example.com');
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ message: 'Password reset request sent successfully!' });
  });

  test('400 + message si service lève une erreur', async () => {
    authService.requestPasswordReset.mockRejectedValue(new Error('User not found'));
    const req = { body: { email: 'unknown@example.com' } };
    const res = makeRes();

    await controller.requestPasswordReset(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ message: 'User not found' });
  });
});

describe('authController.resetPassword', () => {
  test('200 + message si reset ok', async () => {
    const req = { body: { token: 'tok-reset', newPassword: 'NewPass123!' } };
    const res = makeRes();

    await controller.resetPassword(req, res);

    expect(authService.resetPassword).toHaveBeenCalledWith('tok-reset', 'NewPass123!');
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ message: 'Password updated successfully!' });
  });

  test('400 + message si service lève une erreur', async () => {
    authService.resetPassword.mockRejectedValue(new Error('Invalid token'));
    const req = { body: { token: 'bad', newPassword: 'x' } };
    const res = makeRes();

    await controller.resetPassword(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ message: 'Invalid token' });
  });
});
