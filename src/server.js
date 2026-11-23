'use strict';

const http = require('node:http');
const { createApp } = require('./app');
const { createStore } = require('./store');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

function main() {
  const store = createStore();
  const app = createApp({ store });
  const server = http.createServer(app);
  server.listen(PORT, HOST, () => {
    console.log(`VulnDesk listening on http://${HOST}:${PORT}`);
  });
  const shutdown = () => {
    server.close(() => {
      store.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

if (require.main === module) main();

module.exports = { main };
