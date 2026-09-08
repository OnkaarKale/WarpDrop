# Production Dockerfile for Secure P2P File Transfer App
FROM node:20-alpine AS runner

WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0

# Copy dependency manifests
COPY package.json package-lock.json ./

# Install only production dependencies
RUN npm ci --omit=dev

# Copy application source code
COPY public/ ./public/
COPY src/ ./src/
COPY server/ ./server/

# Expose signaling port
EXPOSE 3000

# Start server
CMD ["node", "server/index.js"]
