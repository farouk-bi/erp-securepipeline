const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const securityMiddleware = require('./middlewares/security.middleware');

const authRoutes = require('./routes/auth.routes');
const hrRoutes = require('./routes/hr.routes');
const financeRoutes = require('./routes/finance.routes');
const inventoryRoutes = require('./routes/inventory.routes');

const app = express();

// --- Middlewares de sécurité ---
app.use(helmet());                          // Security headers
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(securityMiddleware);

// --- Routes ---
app.use('/api/auth', authRoutes);
app.use('/api/hr', hrRoutes);
app.use('/api/finance', financeRoutes);
app.use('/api/inventory', inventoryRoutes);

// --- Health Check (pour K8s probes) ---
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: process.env.APP_VERSION || '1.0.0'
    });
});

app.get('/ready', async (req, res) => {
    try {
        const { sequelize } = require('./config/database');
        await sequelize.authenticate();
        res.status(200).json({ status: 'ready', database: 'connected' });
    } catch (error) {
        res.status(503).json({ status: 'not ready', database: 'disconnected' });
    }
});

// --- Gestion d'erreurs globale ---
app.use((err, req, res, next) => {
    console.error(`[ERROR] ${err.message}`);
    res.status(err.status || 500).json({
        error: {
            message: process.env.NODE_ENV === 'production' 
                ? 'Internal Server Error' 
                : err.message,
            code: err.code || 'INTERNAL_ERROR'
        }
    });
});

module.exports = app;