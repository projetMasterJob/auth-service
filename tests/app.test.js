const request = require('supertest');
const app = require('../src/app');

// Mock des routes d'authentification
jest.mock('../src/routes/authRoutes', () => {
  const express = require('express');
  const router = express.Router();
  
  router.get('/test', (req, res) => {
    res.json({ message: 'Test route works' });
  });
  
  return router;
});

describe('App.js', () => {
  it('should be defined', () => {
    expect(app).toBeDefined();
  });

  it('should handle JSON requests', async () => {
    const response = await request(app)
      .get('/api/auth/test')
      .expect(200);

    expect(response.body).toEqual({ message: 'Test route works' });
  });

  it('should return 404 for unknown routes', async () => {
    await request(app)
      .get('/unknown-route')
      .expect(404);
  });

  it('should handle POST requests with JSON body', async () => {
    // Même si la route n'existe pas, l'app devrait pouvoir traiter le JSON
    await request(app)
      .post('/api/auth/test')
      .send({ test: 'data' })
      .expect(404); // 404 car la route POST n'existe pas dans notre mock
  });

  it('should have express middleware configured', () => {
    // Vérifier que l'app est une instance d'Express
    expect(app).toHaveProperty('use');
    expect(app).toHaveProperty('get');
    expect(app).toHaveProperty('post');
    expect(app).toHaveProperty('listen');
  });
});
