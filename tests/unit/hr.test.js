const request = require('supertest');
const app = require('../../src/app');

describe('HR Module', () => {
    describe('GET /api/hr/employees', () => {
        it('should return 401 without authentication', async () => {
            const res = await request(app).get('/api/hr/employees');
            expect(res.statusCode).toBe(401);
        });

        it('should return 403 with invalid token', async () => {
            const res = await request(app)
                .get('/api/hr/employees')
                .set('Authorization', 'Bearer invalid-token');
            expect(res.statusCode).toBe(403);
        });
    });
});