const http2 = require('http2');
const tls = require('tls');
const https = require('https');

/**
 * Replicates the Google / Antigravity persistent connection pattern (AS15169)
 * that triggers and holds open the 3GPP Diameter Gy Fail-Open / RRC NAT session:
 *   1. Opens HTTP/2 (ALPN 'h2') streams to Google API & Gstatic endpoints
 *   2. Opens a TLS 1.3 persistent socket to mtalk.google.com:5228 (Google FCM / Play Services control channel)
 *   3. Sends periodic HTTP/2 PING frames and 204 keep-alive probes every N seconds so the cellular
 *      radio bearer (10.76.x.x -> 179.68.107.x) never hits the RRC idle inactivity teardown.
 */
class SessionKeepAliveEngine {
  constructor(onLog = () => {}) {
    this.onLog = onLog;
    this.active = false;
    this.intervalId = null;
    this.intervalSec = 20;
    this.h2Client = null;
    this.mtalkSocket = null;
    this.stats = {
      startedAt: null,
      totalPulses: 0,
      successfulPulses: 0,
      lastPulseAt: null,
      lastLatencyMs: null,
      mtalkConnected: false,
      h2Connected: false,
      lastStatus: 'Parado'
    };
  }

  /**
   * Fires an immediate Google Handshake Burst (HTTP/2 + TLS 5228 + Gstatic 204)
   * to wake up the bearer and keep the PCRF session alive.
   */
  async fireGoogleHandshakeBurst() {
    const start = Date.now();
    const results = [];

    // 1. HTTP/2 ALPN session to www.googleapis.com
    const h2Promise = new Promise((resolve) => {
      try {
        const client = http2.connect('https://www.googleapis.com', {
          timeout: 6000
        });
        client.on('error', (err) => {
          client.close();
          resolve({ endpoint: 'www.googleapis.com (HTTP/2)', ok: false, error: err.message });
        });
        client.on('connect', () => {
          this.stats.h2Connected = true;
          client.ping((err, duration) => {
            client.close();
            if (err) {
              resolve({ endpoint: 'www.googleapis.com (HTTP/2)', ok: false, error: err.message });
            } else {
              resolve({
                endpoint: 'www.googleapis.com (HTTP/2 PING)',
                ok: true,
                latencyMs: Math.round(duration)
              });
            }
          });
        });
      } catch (e) {
        resolve({ endpoint: 'www.googleapis.com (HTTP/2)', ok: false, error: e.message });
      }
    });

    // 2. ConnectivityCheck Gstatic 204 (Standard Android Zero-Rating / Captive check)
    const gstaticPromise = new Promise((resolve) => {
      const t0 = Date.now();
      const req = https.get(
        'https://connectivitycheck.gstatic.com/generate_204',
        { timeout: 6000 },
        (res) => {
          res.resume();
          resolve({
            endpoint: 'connectivitycheck.gstatic.com/generate_204',
            ok: res.statusCode === 204 || res.statusCode === 200,
            statusCode: res.statusCode,
            latencyMs: Date.now() - t0
          });
        }
      );
      req.on('timeout', () => {
        req.destroy();
        resolve({ endpoint: 'connectivitycheck.gstatic.com', ok: false, error: 'Timeout' });
      });
      req.on('error', (e) => {
        resolve({ endpoint: 'connectivitycheck.gstatic.com', ok: false, error: e.message });
      });
    });

    // 3. Google Mobile Talk / FCM Control Channel (mtalk.google.com:5228 TLS 1.3)
    const mtalkPromise = new Promise((resolve) => {
      const t0 = Date.now();
      const sock = tls.connect(
        {
          host: 'mtalk.google.com',
          port: 5228,
          servername: 'mtalk.google.com',
          timeout: 5000
        },
        () => {
          const proto = sock.getProtocol();
          this.stats.mtalkConnected = true;
          sock.end();
          resolve({
            endpoint: `mtalk.google.com:5228 (${proto})`,
            ok: true,
            latencyMs: Date.now() - t0
          });
        }
      );
      sock.on('timeout', () => {
        sock.destroy();
        resolve({ endpoint: 'mtalk.google.com:5228', ok: false, error: 'Timeout' });
      });
      sock.on('error', (e) => {
        resolve({ endpoint: 'mtalk.google.com:5228', ok: false, error: e.message });
      });
    });

    const [r1, r2, r3] = await Promise.all([h2Promise, gstaticPromise, mtalkPromise]);
    results.push(r1, r2, r3);

    const anyOk = results.some((r) => r.ok);
    const elapsed = Date.now() - start;

    this.stats.totalPulses++;
    if (anyOk) this.stats.successfulPulses++;
    this.stats.lastPulseAt = new Date().toISOString();
    this.stats.lastLatencyMs = elapsed;
    this.stats.lastStatus = anyOk ? 'Sessão Ativa (Keep-Alive OK)' : 'Falha no Pulso';

    this.onLog(
      `[Keep-Alive] Pulso #${this.stats.totalPulses}: ${
        results.filter((r) => r.ok).length
      }/3 canais Google responderam (${elapsed}ms)`
    );

    return {
      ok: anyOk,
      elapsedMs: elapsed,
      channels: results,
      stats: this.getStatus()
    };
  }

  start(intervalSec = 20) {
    this.stop();
    this.intervalSec = Math.max(5, Math.min(120, Number(intervalSec) || 20));
    this.active = true;
    this.stats.startedAt = new Date().toISOString();
    this.stats.lastStatus = `Ativo (a cada ${this.intervalSec}s)`;
    this.onLog(`[Keep-Alive] Motor iniciado — enviando pulso Google AS15169 a cada ${this.intervalSec}s para segurar sessão 10.76.x.x`);

    // Immediate first burst
    this.fireGoogleHandshakeBurst();

    this.intervalId = setInterval(() => {
      if (this.active) {
        this.fireGoogleHandshakeBurst();
      }
    }, this.intervalSec * 1000);

    return this.getStatus();
  }

  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.active = false;
    this.stats.lastStatus = 'Parado';
    return this.getStatus();
  }

  getStatus() {
    return {
      active: this.active,
      intervalSec: this.intervalSec,
      ...this.stats
    };
  }
}

module.exports = { SessionKeepAliveEngine };
