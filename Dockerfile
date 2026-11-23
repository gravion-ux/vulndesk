# VulnDesk — production image. Zero runtime dependencies: plain Node.js.
FROM node:22-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    VULNDESK_DB=/data/vulndesk.sqlite

WORKDIR /app

# Copy source only (no node_modules to install — there are none).
COPY package.json ./
COPY src ./src
COPY public ./public
COPY scripts ./scripts

RUN mkdir -p /data && chown -R node:node /app /data

USER node
EXPOSE 3000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
