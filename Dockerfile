
# Stage 1 : Builder

FROM node:20-alpine AS builder

WORKDIR /app

# Copier les fichiers de dépendances d'abord (cache Docker)
COPY package*.json ./
RUN npm install --omit=dev && mkdir -p node_modules

# Copier le code source
COPY src/ ./src/


# Stage 2 : Production

FROM node:20-alpine AS production

# Sécurité : ne pas exécuter en root
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

WORKDIR /app

# Copier depuis le builder
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/src ./src
COPY --from=builder --chown=appuser:appgroup /app/package*.json ./

# Variables d'environnement par défaut
ENV NODE_ENV=production
ENV PORT=3000

# Exposer le port
EXPOSE 3000

# Utiliser l'utilisateur non-root
USER appuser

# Health check intégré
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Démarrer l'application
CMD ["node", "src/server.js"]