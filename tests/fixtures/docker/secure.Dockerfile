FROM node:20.11.0-slim@sha256:e06aae17c40c7a6b5296ca6f942a43d7e8a0f77d0c7f7f8f7f7f7f7f7f7f7f7f

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && rm -rf /var/lib/apt/lists/*

COPY src ./src

RUN adduser --system --no-create-home --uid 10001 app
USER app

HEALTHCHECK --interval=30s CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000

CMD ["node", "src/server.js"]
