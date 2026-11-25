const http = require('http');
const fs = require('fs');
const path = require('path');

const { PRESET_PAYLOADS, parsePayloadTemplate } = require('./engine/payload');
const { CARRIER_SIGNATURES, runIpHuntCheck } = require('./engine/iphunter');
const { SessionKeepAliveEngine } = require('./engine/keepalive');
const { DEFAULT_SCAN_HOSTS, scanHostList } = require('./engine/scanner');
const { TunnelProxyServer } = require('./engine/proxy');
const { runMultiVectorBreachAudit } = require('./engine/breach_hunter');

const logs = [];
function addLog(msg) {
  const time = new Date().toLocaleTimeString('pt-BR');
  const entry = `[${time}] ${msg}`;
  logs.push(entry);
  if (logs.length > 250) logs.shift();
  console.log(entry);
}

const proxyServer = new TunnelProxyServer(addLog);
const keepAlive = new SessionKeepAliveEngine(addLog);

addLog('Vortex Tunnel Pro v2.0 inicializado.');
addLog('14 Perfis Multi-Operadora (Claro, TIM, Vivo, Universal) + Auto-Hunter 6 Vetores prontos.');

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(body);
}

function readJsonBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        resolve({});
      }
    });
  });
}

function createControlServer() {
  return http.createServer(async (req, res) => {
    const urlObj = new URL(req.url, 'http://localhost');
    const pathname = urlObj.pathname;

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      });
      return res.end();
    }

    // API Routes
    if (pathname === '/api/status' && req.method === 'GET') {
      return sendJson(res, 200, {
        tunnel: proxyServer.getStatus(),
        keepAlive: keepAlive.getStatus(),
        presets: PRESET_PAYLOADS,
        signatures: CARRIER_SIGNATURES,
        defaultScanHosts: DEFAULT_SCAN_HOSTS,
        logs: logs.slice(-80)
      });
    }

    if (pathname === '/api/tunnel/start' && req.method === 'POST') {
      try {
        const body = await readJsonBody(req);
        const status = await proxyServer.start(body);
        return sendJson(res, 200, { ok: true, status });
      } catch (err) {
        addLog(`[Erro Túnel] ${err.message}`);
        return sendJson(res, 500, { ok: false, error: err.message });
      }
    }

    if (pathname === '/api/tunnel/stop' && req.method === 'POST') {
      const status = await proxyServer.stop();
      return sendJson(res, 200, { ok: true, status });
    }

    if (pathname === '/api/payload/preview' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const steps = parsePayloadTemplate(body.payload, {
        targetHost: body.targetHost || '179.68.107.236',
        targetPort: body.targetPort || 443
      });
      return sendJson(res, 200, { ok: true, steps });
    }

    if (pathname === '/api/iphunter/check' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const report = await runIpHuntCheck(body);
      addLog(
        `[IP Hunter] IP Local: ${report.local.primaryIpv4} | Público: ${
          report.public.ip || 'Offline'
        } | Score Claro Fail-Open: ${report.claroFailOpenScore}%`
      );
      return sendJson(res, 200, report);
    }

    if (pathname === '/api/breach/audit' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const audit = await runMultiVectorBreachAudit(body.carrier || 'ALL', addLog);
      return sendJson(res, 200, audit);
    }

    if (pathname === '/api/profile/export' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const payloadJson = JSON.stringify({
        v: 2,
        name: body.name || 'Custom Profile',
        carrier: body.carrier || 'Custom',
        mode: body.mode || 'direct_split',
        sni: body.sni || '',
        serverHost: body.serverHost || '',
        serverPort: body.serverPort || 443,
        payload: body.payload || '',
        fragmentSize: body.fragmentSize || 16
      });
      const vtxCode = 'vtx://' + Buffer.from(payloadJson, 'utf8').toString('base64url');
      addLog(`[Perfil .VTX] Configuração exportada (${vtxCode.length} bytes).`);
      return sendJson(res, 200, { ok: true, vtxCode });
    }

    if (pathname === '/api/profile/import' && req.method === 'POST') {
      try {
        const body = await readJsonBody(req);
        const raw = (body.vtxCode || '').trim().replace(/^vtx:\/\//i, '');
        const decoded = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
        addLog(`[Perfil .VTX] Perfil "${decoded.name || 'Custom'}" importado com sucesso.`);
        return sendJson(res, 200, { ok: true, profile: decoded });
      } catch (e) {
        return sendJson(res, 400, { ok: false, error: 'Código .VTX inválido' });
      }
    }

    if (pathname === '/api/keepalive/start' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const status = keepAlive.start(body.intervalSec || 20);
      return sendJson(res, 200, { ok: true, status });
    }

    if (pathname === '/api/keepalive/stop' && req.method === 'POST') {
      const status = keepAlive.stop();
      addLog('[Keep-Alive] Pulso automático desativado.');
      return sendJson(res, 200, { ok: true, status });
    }

    if (pathname === '/api/keepalive/burst' && req.method === 'POST') {
      addLog('[Keep-Alive] Disparando Handshake Google (HTTP/2 + FCM 5228 + Gstatic 204)...');
      const burst = await keepAlive.fireGoogleHandshakeBurst();
      return sendJson(res, 200, burst);
    }

    if (pathname === '/api/scanner/run' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const domains = Array.isArray(body.domains)
        ? body.domains
        : (body.domains || '')
            .split(/[\r\n,;]+/)
            .map((s) => s.trim())
            .filter(Boolean);
      const list = domains.length > 0 ? domains : DEFAULT_SCAN_HOSTS;
      addLog(`[Scanner] Testando ${list.length} hosts (TLS/SNI + CDN Fingerprint)...`);
      const results = await scanHostList(list, 6);
      const aliveCount = results.filter((r) => r.alive).length;
      addLog(`[Scanner] Concluído: ${aliveCount}/${list.length} hosts responderam.`);
      return sendJson(res, 200, { ok: true, results });
    }

    if (pathname === '/api/logs/clear' && req.method === 'POST') {
      logs.length = 0;
      addLog('Logs limpos.');
      return sendJson(res, 200, { ok: true });
    }

    // Static assets (PWA manifest & SVG icon & index.html)
    if (pathname === '/manifest.json') {
      const p = path.join(__dirname, 'public', 'manifest.json');
      fs.readFile(p, (err, content) => {
        if (err) { res.writeHead(404); return res.end(); }
        res.writeHead(200, { 'Content-Type': 'application/manifest+json; charset=utf-8' });
        res.end(content);
      });
      return;
    }

    if (pathname === '/icon.svg') {
      const p = path.join(__dirname, 'public', 'icon.svg');
      fs.readFile(p, (err, content) => {
        if (err) { res.writeHead(404); return res.end(); }
        res.writeHead(200, { 'Content-Type': 'image/svg+xml; charset=utf-8' });
        res.end(content);
      });
      return;
    }

    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (pathname === '/' || pathname === '/index.html') {
      fs.readFile(indexPath, (err, content) => {
        if (err) {
          res.writeHead(500);
          return res.end('UI missing');
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(content);
      });
      return;
    }

    res.writeHead(404);
    res.end('Not Found');
  });
}

if (require.main === module) {
  const PORT = Number(process.env.PORT) || 9090;
  const server = createControlServer();
  server.listen(PORT, '0.0.0.0', () => {
    addLog(`Painel Vortex Tunnel Pro rodando em http://127.0.0.1:${PORT}`);
  });
}

module.exports = {
  createControlServer,
  proxyServer,
  keepAlive
};
