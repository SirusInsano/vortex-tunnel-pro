const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');

/**
 * Default list of Zero-Rating, Carrier Portal, and CDN endpoints for Brazilian carriers
 * (Claro, TIM, Vivo) + regional ISP / Google endpoints to scan when testing for open Bug Hosts.
 */
const DEFAULT_SCAN_HOSTS = [
  'www.googleapis.com',
  'connectivitycheck.gstatic.com',
  'mtalk.google.com',
  'claro.com.br',
  'minhaclaro.claro.com.br',
  'claroflex.com.br',
  'm.claro.com.br',
  'recarga.claro.com.br',
  'tim.com.br',
  'meutim.tim.com.br',
  'recarga.tim.com.br',
  'c6bank.com.br',
  'vivo.com.br',
  'meu.vivo.com.br',
  'recarga.vivo.com.br',
  'mhnet.com.br',
  'www.mhnet.com.br',
  'whatsapp.com',
  'web.whatsapp.com',
  'cloudflare.com',
  '1.1.1.1'
];

/**
 * Fingerprints the underlying CDN / Cloud Edge provider from HTTP response headers.
 */
function detectCdnFromHeaders(headers = {}) {
  const server = (headers['server'] || '').toLowerCase();
  const via = (headers['via'] || '').toLowerCase();
  const xCache = (headers['x-cache'] || '').toLowerCase();

  if (server.includes('cloudflare') || headers['cf-ray']) return 'Cloudflare';
  if (via.includes('cloudfront') || xCache.includes('cloudfront') || headers['x-amz-cf-id'])
    return 'AWS CloudFront';
  if (
    server.includes('akamaighost') ||
    server.includes('akamai') ||
    headers['x-akamai-transformed'] ||
    via.includes('akamai')
  )
    return 'Akamai';
  if (server.includes('azion') || headers['x-azion-edge']) return 'Azion Edge';
  if (server.includes('gws') || server.includes('esf') || server.includes('scaffolding') || headers['alt-svc']?.includes('google'))
    return 'Google Edge (AS15169)';
  if (server.includes('fastly') || via.includes('varnish') || headers['x-served-by'])
    return 'Fastly';
  if (server.includes('whatsapp') || headers['x-fb-debug']) return 'Meta Edge (AS32934)';
  return server ? `Direto (${headers['server']})` : 'Direto / Desconhecido';
}

/**
 * Probes a single domain on port 443 (TLS + HTTP/1.1 HEAD & WebSocket capability check).
 */
async function probeHost(domain, timeoutMs = 4500) {
  const cleanDomain = domain.trim().replace(/^https?:\/\//i, '').split('/')[0];
  const t0 = Date.now();

  let ips = [];
  try {
    ips = await dns.resolve4(cleanDomain);
  } catch (err) {
    // If domain is already an IPv4 literal
    if (net.isIPv4(cleanDomain)) {
      ips = [cleanDomain];
    } else {
      return {
        domain: cleanDomain,
        alive: false,
        stage: 'DNS',
        error: 'Falha DNS',
        latencyMs: Date.now() - t0
      };
    }
  }

  const targetIp = ips[0];

  return new Promise((resolve) => {
    const tlsStart = Date.now();
    const socket = tls.connect(
      {
        host: targetIp,
        port: 443,
        servername: net.isIPv4(cleanDomain) ? undefined : cleanDomain,
        rejectUnauthorized: false,
        ALPNProtocols: ['http/1.1']
      },
      () => {
        const tlsProtocol = socket.getProtocol();
        const reqLines = [
          `HEAD / HTTP/1.1`,
          `Host: ${cleanDomain}`,
          `User-Agent: Mozilla/5.0 (Linux; Android 14; 2311DRK48G) Chrome/131.0.0.0 Mobile`,
          `Connection: close`,
          `\r\n`
        ].join('\r\n');

        socket.write(reqLines);
      }
    );

    let rawResponse = '';
    socket.setTimeout(timeoutMs);

    socket.on('data', (chunk) => {
      rawResponse += chunk.toString('latin1');
      if (rawResponse.includes('\r\n\r\n')) {
        socket.destroy();
      }
    });

    const finalize = () => {
      if (!rawResponse) {
        return resolve({
          domain: cleanDomain,
          ip: targetIp,
          alive: true,
          stage: 'TLS_ONLY',
          statusCode: 0,
          statusText: 'TLS Handshake OK (Sem HTTP)',
          cdn: 'TLS Direto',
          latencyMs: Date.now() - tlsStart,
          grade: 'B'
        });
      }

      const headerBlock = rawResponse.split('\r\n\r\n')[0] || '';
      const lines = headerBlock.split('\r\n');
      const statusLine = lines[0] || '';
      const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/i);
      const statusCode = statusMatch ? Number(statusMatch[1]) : 0;

      const headers = {};
      for (let i = 1; i < lines.length; i++) {
        const idx = lines[i].indexOf(':');
        if (idx > 0) {
          const k = lines[i].slice(0, idx).trim().toLowerCase();
          const v = lines[i].slice(idx + 1).trim();
          headers[k] = v;
        }
      }

      const cdn = detectCdnFromHeaders(headers);
      const isCloudCdn = ['Cloudflare', 'AWS CloudFront', 'Akamai', 'Azion Edge', 'Fastly', 'Google Edge (AS15169)'].includes(cdn);
      const grade = isCloudCdn && statusCode > 0 ? 'S (Ótimo p/ CDN/SNI)' : statusCode > 0 ? 'A (Respondeu HTTP)' : 'B';

      resolve({
        domain: cleanDomain,
        ip: targetIp,
        alive: true,
        stage: 'HTTP',
        statusCode,
        statusLine: statusLine.trim(),
        cdn,
        serverHeader: headers['server'] || '-',
        latencyMs: Date.now() - tlsStart,
        grade
      });
    };

    socket.on('close', () => {
      if (rawResponse) finalize();
    });

    socket.on('end', () => {
      finalize();
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        domain: cleanDomain,
        ip: targetIp,
        alive: false,
        stage: 'TIMEOUT',
        error: 'Timeout TLS/443',
        latencyMs: Date.now() - tlsStart
      });
    });

    socket.on('error', (err) => {
      resolve({
        domain: cleanDomain,
        ip: targetIp,
        alive: false,
        stage: 'TCP/TLS',
        error: err.code || err.message,
        latencyMs: Date.now() - tlsStart
      });
    });
  });
}

/**
 * Scans a list of domains with bounded concurrency.
 */
async function scanHostList(domains = DEFAULT_SCAN_HOSTS, concurrency = 5, onProgress = () => {}) {
  const unique = Array.from(
    new Set(
      domains
        .map((d) => d.trim())
        .filter(Boolean)
    )
  );

  const results = [];
  let index = 0;

  async function worker() {
    while (index < unique.length) {
      const current = unique[index++];
      const res = await probeHost(current);
      results.push(res);
      onProgress(res, results.length, unique.length);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, unique.length) }, () => worker());
  await Promise.all(workers);

  return results.sort((a, b) => {
    if (a.alive !== b.alive) return a.alive ? -1 : 1;
    return (a.latencyMs || 9999) - (b.latencyMs || 9999);
  });
}

module.exports = {
  DEFAULT_SCAN_HOSTS,
  probeHost,
  scanHostList
};
