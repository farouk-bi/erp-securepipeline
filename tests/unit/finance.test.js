const request = require('supertest');
const app = require('../../src/app');

describe('Finance Module', () => {
    describe('GET /api/finance/invoices', () => {
        it('should return 401 without authentication', async () => {
            const res = await request(app).get('/api/finance/invoices');
            expect(res.statusCode).toBe(401);
        });
    });
});