const app = require('./app');
const { sequelize } = require('./config/database');

const PORT = process.env.PORT || 3000;

async function startServer() {
    try {
        // Synchroniser la base de données
        await sequelize.sync({ alter: true });
        console.log('✅ Database synchronized');

        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 ERP Server running on port ${PORT}`);
            console.log(`📊 Health check: http://localhost:${PORT}/health`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error.message);
        process.exit(1);
    }
}

startServer();