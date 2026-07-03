// Middleware de sécurité personnalisé (complète Helmet)
const securityMiddleware = (req, res, next) => {
    // Supprimer le header X-Powered-By (déjà fait par Helmet, double sécurité)
    res.removeHeader('X-Powered-By');

    // Ajouter des headers de sécurité supplémentaires
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');

    // Log de sécurité (utile pour le monitoring)
    console.log(`[ACCESS] ${req.method} ${req.path} - IP: ${req.ip} - ${new Date().toISOString()}`);

    next();
};

module.exports = securityMiddleware;