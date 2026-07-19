const request = require('supertest');
const app = require('../../src/app');

describe('Inventory Module', () => {
    describe('GET /api/inventory/products', () => {
        it('should return 401 without authentication', async () => {
            const res = await request(app).get('/api/inventory/products');
            expect(res.statusCode).toBe(401);
        });
    });
});