const net = require('net');
const { createTunnelConnection } = require('./payload');

/**
 * Multi-protocol Local Proxy & Hotshare Server:
 *   - Runs a SOCKS5 Server (default port 10808)
 *   - Runs an HTTP/HTTPS CONNECT Proxy Server (default port 8080)
 *   - When Hotshare is enabled, binds to 0.0.0.0 so any PC connected to the phone's
 *     Wi-Fi Hotspot or USB Tethering (or vice-versa) can share the tunnel without root.
 *   - Routes every outbound stream through the active Payload / Split-TLS / SNI engine.
 */
class TunnelProxyServer {
  constructor(onLog = () => {}) {
    this.onLog = onLog;
    this.socksServer = null;
    this.httpProxyServer = null;
    this.running = false;
    this.activeConnections = new Set();
    this.profile = {
      mode: 'direct_split',
      sni: 'www.googleapis.com',
      payload: '',
      tlsFragment: true,
      fragmentSize: 16,
      fragmentDelayMs: 10,
      hotshare: true,
      socksPort: 10808,
      httpPort: 8080
    };
    this.stats = {
      startedAt: null,
      totalConnections: 0,
      activeCount: 0,
      bytesUp: 0,
      bytesDown: 0
    };
  }

  trackPipe(clientSocket, remoteSocket) {
    this.activeConnections.add(clientSocket);
    this.activeConnections.add(remoteSocket);
    this.stats.totalConnections++;
    this.stats.activeCount = Math.floor(this.activeConnections.size / 2);

    clientSocket.on('data', (chunk) => {
      this.stats.bytesUp += chunk.length;
    });
    remoteSocket.on('data', (chunk) => {
      this.stats.bytesDown += chunk.length;
    });

    const cleanup = () => {
      this.activeConnections.delete(clientSocket);
      this.activeConnections.delete(remoteSocket);
      this.stats.activeCount = Math.floor(this.activeConnections.size / 2);
      if (!clientSocket.destroyed) clientSocket.destroy();
      if (!remoteSocket.destroyed) remoteSocket.destroy();
    };

    clientSocket.pipe(remoteSocket);
    remoteSocket.pipe(clientSocket);

    clientSocket.on('error', cleanup);
    remoteSocket.on('error', cleanup);
    clientSocket.on('close', cleanup);
    remoteSocket.on('close', cleanup);
  }

  /**
   * Starts both SOCKS5 (10808) and HTTP CONNECT (8080) proxy servers.
   */
  async start(customProfile = {}) {
    await this.stop();
    this.profile = { ...this.profile, ...customProfile };

    const bindHost = this.profile.hotshare ? '0.0.0.0' : '127.0.0.1';
    const socksPort = Number(this.profile.socksPort) || 10808;
    const httpPort = Number(this.profile.httpPort) || 8080;

    // 1. SOCKS5 Server (RFC 1928)
    this.socksServer = net.createServer((client) => {
      client.once('data', (greeting) => {
        if (!greeting || greeting[0] !== 0x05) {
          client.destroy();
          return;
        }
        // No authentication required (0x05, 0x00)
        client.write(Buffer.from([0x05, 0x00]));

        client.once('data', async (req) => {
          try {
            if (!req || req[0] !== 0x05 || req[1] !== 0x01) {
              client.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
              client.destroy();
              return;
            }

            const atyp = req[3];
            let targetHost = '';
            let targetPort = 0;

            if (atyp === 0x01) {
              // IPv4
              targetHost = `${req[4]}.${req[5]}.${req[6]}.${req[7]}`;
              targetPort = req.readUInt16BE(8);
            } else if (atyp === 0x03) {
              // Domain name
              const len = req[4];
              targetHost = req.subarray(5, 5 + len).toString('utf8');
              targetPort = req.readUInt16BE(5 + len);
            } else {
              client.destroy();
              return;
            }

            const remote = await createTunnelConnection(
              targetHost,
              targetPort,
              this.profile,
              this.onLog
            );

            // Send SOCKS5 success reply
            client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
            this.trackPipe(client, remote);
          } catch (err) {
            this.onLog(`[SOCKS5] Erro conectando: ${err.message}`);
            if (!client.destroyed) {
              client.write(Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
              client.destroy();
            }
          }
        });
      });
      client.on('error', () => client.destroy());
    });

    // 2. HTTP / HTTPS CONNECT Proxy Server (for Android Wi-Fi Hotshare & Windows System Proxy)
    this.httpProxyServer = net.createServer((client) => {
      client.once('data', async (firstChunk) => {
        try {
          const text = firstChunk.toString('latin1');
          const firstLine = (text.split('\r\n')[0] || '').trim();
          const parts = firstLine.split(' ');
          const method = (parts[0] || '').toUpperCase();
          const target = parts[1] || '';

          if (method === 'CONNECT') {
            const [hostPart, portPart] = target.split(':');
            const targetHost = hostPart;
            const targetPort = Number(portPart) || 443;

            const remote = await createTunnelConnection(
              targetHost,
              targetPort,
              this.profile,
              this.onLog
            );
            client.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: VortexTunnel/1.0\r\n\r\n');
            this.trackPipe(client, remote);
          } else if (target.startsWith('http://')) {
            const urlObj = new URL(target);
            const targetHost = urlObj.hostname;
            const targetPort = Number(urlObj.port) || 80;

            const remote = await createTunnelConnection(
              targetHost,
              targetPort,
              this.profile,
              this.onLog
            );
            remote.write(firstChunk);
            this.trackPipe(client, remote);
          } else {
            client.end('HTTP/1.1 400 Bad Request\r\n\r\nVortex Proxy Ready');
          }
        } catch (err) {
          this.onLog(`[HTTP-Proxy] Erro: ${err.message}`);
          if (!client.destroyed) {
            client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
          }
        }
      });
      client.on('error', () => client.destroy());
    });

    await new Promise((resolve, reject) => {
      this.socksServer.once('error', reject);
      this.socksServer.listen(socksPort, bindHost, resolve);
    });

    await new Promise((resolve, reject) => {
      this.httpProxyServer.once('error', reject);
      this.httpProxyServer.listen(httpPort, bindHost, resolve);
    });

    this.running = true;
    this.stats.startedAt = new Date().toISOString();
    this.onLog(
      `[Túnel Ativo] SOCKS5 em ${bindHost}:${socksPort} | HTTP Hotshare em ${bindHost}:${httpPort} | Modo: ${this.profile.mode}`
    );

    return this.getStatus();
  }

  async stop() {
    for (const sock of this.activeConnections) {
      if (!sock.destroyed) sock.destroy();
    }
    this.activeConnections.clear();

    if (this.socksServer) {
      await new Promise((r) => this.socksServer.close(r));
      this.socksServer = null;
    }
    if (this.httpProxyServer) {
      await new Promise((r) => this.httpProxyServer.close(r));
      this.httpProxyServer = null;
    }

    if (this.running) {
      this.onLog('[Túnel] Servidor SOCKS5 / Hotshare encerrado.');
    }
    this.running = false;
    this.stats.activeCount = 0;
    return this.getStatus();
  }

  getStatus() {
    return {
      running: this.running,
      profile: this.profile,
      stats: this.stats
    };
  }
}

module.exports = { TunnelProxyServer };
