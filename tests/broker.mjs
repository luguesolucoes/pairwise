// Local MQTT-over-WebSocket broker for tests (stands in for the public pairing relays).
import { createRequire } from 'node:module';
import http from 'node:http';
import { WebSocketServer, createWebSocketStream } from 'ws';
const require = createRequire(import.meta.url);
const aedes = require('aedes')();
const server = http.createServer();
const wss = new WebSocketServer({ server, handleProtocols: (p) => (p.has('mqtt') ? 'mqtt' : false) });
wss.on('connection', (ws) => aedes.handle(createWebSocketStream(ws)));
let published = 0;
aedes.on('publish', (packet, client) => { if (client) { published++; console.log('PUBLISH', packet.topic, packet.payload.length); } });
server.listen(0, '127.0.0.1', () => console.log('PORT', server.address().port));
