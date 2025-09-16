// Configuration globale pour les tests
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing';
process.env.JWT_REFRESH_SECRET = 'test-jwt-refresh-secret-key-for-testing';
process.env.URL_AUTH = 'http://localhost:5000';

// Mock console.log pour réduire le bruit pendant les tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: console.error // Garder les erreurs pour le débogage
};

// Configuration des timeouts pour les tests
jest.setTimeout(10000);

// Mock global pour les modules externes qui pourraient causer des problèmes
jest.mock('node-mailjet', () => ({
  apiConnect: jest.fn(() => ({
    post: jest.fn(() => ({
      request: jest.fn().mockResolvedValue({ body: { Messages: [{ Status: 'success' }] } })
    }))
  }))
}));

// Nettoyage après chaque test
afterEach(() => {
  jest.clearAllMocks();
});

// Nettoyage après tous les tests
afterAll(() => {
  jest.restoreAllMocks();
});
