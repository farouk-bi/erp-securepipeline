const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'changeme-use-vault-in-production';

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
            error: { message: 'Access denied. No token provided.', code: 'AUTH_NO_TOKEN' }
        });
    }

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ 
            error: { message: 'Invalid or expired token.', code: 'AUTH_INVALID_TOKEN' }
        });
    }
};

// Middleware de vérification de rôle
const requireRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ 
                error: { message: 'Insufficient permissions.', code: 'AUTH_FORBIDDEN' }
            });
        }
        next();
    };
};

module.exports = { authMiddleware, requireRole };