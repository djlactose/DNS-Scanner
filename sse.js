'use strict';

const { requireAuth } = require('./middleware');

// SSE clients
const sseClients = new Map();

function broadcastSSE(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  for (const [, client] of sseClients) {
    try { client.write(msg); } catch (e) { /* ignore */ }
  }
}

function setupSSE(app) {
  app.get('/api/events', requireAuth, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const clientId = Date.now() + '_' + req.session.userId;
    sseClients.set(clientId, res);

    const cleanup = () => {
      clearInterval(heartbeat);
      clearTimeout(autoDisconnect);
      sseClients.delete(clientId);
    };

    const heartbeat = setInterval(() => {
      try { res.write(':heartbeat\n\n'); } catch (e) { cleanup(); }
    }, 30000);

    const autoDisconnect = setTimeout(() => {
      cleanup();
      try { res.end(); } catch (e) {}
    }, 60 * 60 * 1000);

    req.on('close', cleanup);
  });
}

module.exports = { sseClients, broadcastSSE, setupSSE };
