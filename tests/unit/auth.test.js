const request = require('supertest');
const app = require('../../src/app');

describe('Auth Module', () => {
    describe('POST /api/auth/register', () => {
        it('should return 400 if required fields are missing', async () => {
            const res = await request(app)
                .post('/api/auth/register')
                .send({ username: 'test' }); // missing email & password
            expect(res.statusCode).toBe(400);
        });
    });

    describe('POST /api/auth/login', () => {
        it('should return 401 for invalid credentials', async () => {
            const res = await request(app)
                .post('/api/auth/login')
                .send({ email: 'nonexistent@test.com', password: 'wrongpass' });
            expect(res.statusCode).toBe(401);
        });
    });

    describe('GET /health', () => {
        it('should return 200 with healthy status', async () => {
            const res = await request(app).get('/health');
            expect(res.statusCode).toBe(200);
            expect(res.body.status).toBe('healthy');
        });
    });
});