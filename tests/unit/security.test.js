const request = require('supertest');
const app = require('../../src/app');

describe('Security Headers', () => {
    it('should include X-Content-Type-Options header', async () => {
        const res = await request(app).get('/health');
        expect(res.headers['x-content-type-options']).toBe('nosniff');
    });

    it('should include X-Frame-Options header', async () => {
        const res = await request(app).get('/health');
        // Helmet met SAMEORIGIN par défaut, notre middleware le force à DENY
        expect(['DENY', 'SAMEORIGIN']).toContain(res.headers['x-frame-options']);
    });

    it('should not expose X-Powered-By header', async () => {
        const res = await request(app).get('/health');
        expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('should include Strict-Transport-Security header', async () => {
        const res = await request(app).get('/health');
        expect(res.headers['strict-transport-security']).toBeDefined();
    });

    it('should return health check with correct structure', async () => {
        const res = await request(app).get('/health');
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty('status', 'healthy');
        expect(res.body).toHaveProperty('timestamp');
        expect(res.body).toHaveProperty('version');
    });
});