const net = require('net');
const tls = require('tls');

/**
 * Parses HTTP Injector / SocksLite / Rev Hunter payload syntax into sequential socket write steps.
 * Supported tags:
 *   [host], [port], [host_port], [protocol], [crlf], [lf], [cr], [ua],
 *   [method], [split], [instant_split], [delay_split], [ netData ], [raw]
 */
function parsePayloadTemplate(template, context = {}) {
  const host = context.targetHost || '127.0.0.1';
  const port = context.targetPort || 443;
  const method = context.method || 'CONNECT';
  const userAgent =
    context.userAgent ||
    'Mozilla/5.0 (Linux; Android 14; 2311DRK48G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36';

  if (!template || !template.trim()) {
    return [
      {
        data: `${method} ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\nUser-Agent: ${userAgent}\r\nConnection: keep-alive\r\n\r\n`,
        delayMs: 0
      }
    ];
  }

  let expanded = template
    .replace(/\[host_port\]/gi, `${host}:${port}`)
    .replace(/\[netData\]/gi, `${method} ${host}:${port} HTTP/1.1`)
    .replace(/\[raw\]/gi, `${method} ${host}:${port} HTTP/1.1`)
    .replace(/\[host\]/gi, host)
    .replace(/\[port\]/gi, String(port))
    .replace(/\[protocol\]/gi, 'HTTP/1.1')
    .replace(/\[method\]/gi, method)
    .replace(/\[ua\]/gi, userAgent)
    .replace(/\[crlf\]/gi, '\r\n')
    .replace(/\[lf\]/gi, '\n')
    .replace(/\[cr\]/gi, '\r');

  // Tokenize by split markers: [split], [instant_split], [delay_split]
  const steps = [];
  const regex = /\[(instant_split|delay_split|split)\]/gi;
  let lastIndex = 0;
  let match;
  let pendingDelay = 0;

  while ((match = regex.exec(expanded)) !== null) {
    const chunk = expanded.slice(lastIndex, match.index);
    if (chunk.length > 0) {
      steps.push({ data: chunk, delayMs: pendingDelay });
    }
    const marker = match[1].toLowerCase();
    pendingDelay = marker === 'delay_split' ? 180 : marker === 'split' ? 40 : 0;
    lastIndex = regex.lastIndex;
  }

  const tail = expanded.slice(lastIndex);
  if (tail.length > 0) {
    steps.push({ data: tail, delayMs: pendingDelay });
  }

  return steps;
}

/**
 * Writes payload chunks or fragmented packets across a stream with TCP_NODELAY
 * to bypass simple DPI packet reassembly buffers.
 */
async function writePayloadSteps(socket, steps, fragmentConfig = {}) {
  socket.setNoDelay(true);
  const enableFragment = Boolean(fragmentConfig.enabled);
  const fragSize = Math.max(2, Number(fragmentConfig.chunkSize) || 8);
  const fragDelay = Math.max(1, Number(fragmentConfig.delayMs) || 10);

  for (const step of steps) {
    if (step.delayMs > 0) {
      await new Promise((r) => setTimeout(r, step.delayMs));
    }
    const buf = Buffer.isBuffer(step.data) ? step.data : Buffer.from(step.data, 'utf8');

    if (enableFragment && buf.length > fragSize) {
      for (let offset = 0; offset < buf.length; offset += fragSize) {
        const slice = buf.subarray(offset, Math.min(offset + fragSize, buf.length));
        socket.write(slice);
        if (offset + fragSize < buf.length) {
          await new Promise((r) => setTimeout(r, fragDelay));
        }
      }
    } else {
      socket.write(buf);
    }
  }
}

/**
 * Wraps a raw TCP socket so that the initial TLS ClientHello is automatically
 * split into small TCP segments (TLS Record / TCP Fragmentation for DPI bypass).
 */
class FragmentedSocketWrapper extends net.Socket {
  constructor(rawSocket, fragSize = 12, fragDelayMs = 15) {
    super();
    this.rawSocket = rawSocket;
    this.fragSize = fragSize;
    this.fragDelayMs = fragDelayMs;
    this.firstWriteDone = false;
  }
}

/**
 * Establishes an outbound connection using the configured Tunnel Profile:
 * Modes supported:
 *   1. "direct_split": Direct TCP connection to destination with initial packet / TLS ClientHello fragmentation
 *   2. "http_payload": Connects to Proxy/Server, injects HTTP payload ([split], [crlf]), waits for 200/101
 *   3. "ssl_sni": Connects via TLS with spoofed SNI (Bug Host) to Server
 *   4. "ssl_payload_ws": Connects via TLS with spoofed SNI (CDN/Cloudflare) + injects WebSocket Upgrade payload
 */
async function createTunnelConnection(targetHost, targetPort, profile, onLog = () => {}) {
  const mode = profile.mode || 'direct_split';
  const sniHost = (profile.sni || '').trim() || targetHost;
  const fragment = {
    enabled: profile.tlsFragment !== false,
    chunkSize: Number(profile.fragmentSize) || 16,
    delayMs: Number(profile.fragmentDelayMs) || 12
  };

  // Mode 1: Serverless Direct with Packet / TLS ClientHello Fragmentation
  if (mode === 'direct_split') {
    const connectHost = (profile.bugHost || '').trim() || targetHost;
    const connectPort = Number(profile.bugPort) || targetPort;

    return new Promise((resolve, reject) => {
      const sock = net.connect({ host: connectHost, port: connectPort }, () => {
        sock.setNoDelay(true);
        // Intercept the very first write (e.g. TLS ClientHello from browser/app) and fragment it
        if (fragment.enabled) {
          const origWrite = sock.write.bind(sock);
          let handshakePackets = 0;
          sock.write = function (chunk, encoding, cb) {
            if (handshakePackets < 2 && Buffer.isBuffer(chunk) && chunk.length > fragment.chunkSize) {
              handshakePackets++;
              onLog(`[Split-TLS] Fragmentando handshake para ${ targetHost }:${ targetPort } (${ chunk.length }B em blocos de ${ fragment.chunkSize }B)`);
              const firstPart = chunk.subarray(0, fragment.chunkSize);
              const secondPart = chunk.subarray(fragment.chunkSize);
              origWrite(firstPart);
              setTimeout(() => {
                origWrite(secondPart, encoding, cb);
              }, fragment.delayMs);
              return true;
            }
            return origWrite(chunk, encoding, cb);
          };
        }
        resolve(sock);
      });
      sock.setTimeout(15000);
      sock.on('timeout', () => {
        sock.destroy(new Error('Connection timeout'));
      });
      sock.on('error', reject);
    });
  }

  // Determine physical entry point (Proxy or Server or CDN Bug Host)
  const entryHost = (profile.proxyHost || profile.serverHost || profile.bugHost || targetHost).trim();
  const entryPort = Number(profile.proxyPort || profile.serverPort || profile.bugPort || targetPort);

  // Mode 2: HTTP Proxy + Payload Injection
  if (mode === 'http_payload') {
    return new Promise((resolve, reject) => {
      const sock = net.connect({ host: entryHost, port: entryPort }, async () => {
        try {
          const steps = parsePayloadTemplate(profile.payload, {
            targetHost: profile.serverHost || targetHost,
            targetPort: profile.serverPort || targetPort
          });
          onLog(`[Payload] Enviando ${steps.length} etapa(s) para ${entryHost}:${entryPort}`);
          await writePayloadSteps(sock, steps, fragment);

          // Wait for HTTP 200 / 101 response from proxy/gateway
          const onData = (data) => {
            const text = data.toString('latin1');
            const firstLine = text.split('\r\n')[0] || '';
            if (text.includes('200 ') || text.includes('101 ') || !profile.expectHttp200) {
              sock.removeListener('data', onData);
              onLog(`[Payload] Handshake aceito: ${firstLine.trim()}`);
              resolve(sock);
            } else if (text.startsWith('HTTP/')) {
              sock.removeListener('data', onData);
              onLog(`[Payload] Resposta HTTP: ${firstLine.trim()}`);
              resolve(sock);
            }
          };
          sock.on('data', onData);
        } catch (err) {
          sock.destroy();
          reject(err);
        }
      });
      sock.setTimeout(15000);
      sock.on('error', reject);
    });
  }

  // Mode 3 & 4: SSL/TLS + SNI Spoofing (with optional WebSocket Payload inside TLS)
  if (mode === 'ssl_sni' || mode === 'ssl_payload_ws') {
    return new Promise((resolve, reject) => {
      const rawSock = net.connect({ host: entryHost, port: entryPort }, () => {
        rawSock.setNoDelay(true);
        onLog(`[SSL/SNI] Conectado em ${entryHost}:${entryPort} -> Injetando SNI: ${sniHost}`);

        const tlsSock = tls.connect(
          {
            socket: rawSock,
            servername: sniHost,
            rejectUnauthorized: false,
            ALPNProtocols: ['http/1.1']
          },
          async () => {
            onLog(`[SSL/SNI] Handshake TLS (${tlsSock.getProtocol()}) concluído com SNI ${sniHost}`);
            if (mode === 'ssl_payload_ws' && profile.payload) {
              const steps = parsePayloadTemplate(profile.payload, {
                targetHost: profile.serverHost || targetHost,
                targetPort: profile.serverPort || targetPort
              });
              onLog(`[WS-Payload] Injetando payload WebSocket dentro do túnel TLS...`);
              await writePayloadSteps(tlsSock, steps, { enabled: false });
            }
            resolve(tlsSock);
          }
        );

        tlsSock.on('error', (err) => {
          rawSock.destroy();
          reject(err);
        });
      });

      rawSock.setTimeout(15000);
      rawSock.on('error', reject);
    });
  }

  throw new Error(`Modo desconhecido: ${mode}`);
}

const PRESET_PAYLOADS = [
  // === CLARO BR ===
  {
    id: 'claro_direct_split',
    name: 'Claro Flex / Pré — Sessão 10.76.x.x (Fail-Open Google + Split-TLS 16B)',
    carrier: 'Claro BR',
    badge: 'MAIS RÁPIDO (130~800 Mbps)',
    mode: 'direct_split',
    sni: 'www.googleapis.com',
    payload: '',
    tlsFragment: true,
    fragmentSize: 16,
    fragmentDelayMs: 10
  },
  {
    id: 'claro_tailscale_bridge',
    name: 'Claro — Ponte Peering Regional IX.br / Tailscale Gigabit',
    carrier: 'Claro BR',
    badge: 'PONTE FIBRA CASA',
    mode: 'direct_split',
    sni: 'mhnet.com.br',
    payload: '',
    tlsFragment: true,
    fragmentSize: 12,
    fragmentDelayMs: 8
  },
  {
    id: 'claro_ws_cdn',
    name: 'Claro — CDN Cloudflare WebSocket + SNI Micro-Fragment 8B',
    carrier: 'Claro BR',
    badge: 'CDN FRONTING',
    mode: 'ssl_payload_ws',
    sni: 'm.claro.com.br',
    payload:
      'GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf][crlf]',
    tlsFragment: true,
    fragmentSize: 8,
    fragmentDelayMs: 14
  },
  {
    id: 'claro_flex_portal',
    name: 'Claro — Portal Claro Flex / Minha Claro Zero-Rating SNI',
    carrier: 'Claro BR',
    badge: 'ZERO-RATING',
    mode: 'ssl_sni',
    sni: 'claroflex.com.br',
    payload:
      'CONNECT [host_port] HTTP/1.1[crlf]Host: claroflex.com.br[crlf]X-Online-Host: claroflex.com.br[crlf][crlf]',
    tlsFragment: true,
    fragmentSize: 14,
    fragmentDelayMs: 12
  },
  {
    id: 'claro_akamai_music',
    name: 'Claro — Claro Música / Claro TV+ (Akamai / CloudFront Split)',
    carrier: 'Claro BR',
    badge: 'AKAMAI / AWS',
    mode: 'http_payload',
    sni: 'claromusica.com',
    payload:
      'GET http://claromusica.com/ HTTP/1.1[crlf]Host: claromusica.com[crlf][split]CONNECT [host_port] HTTP/1.1[crlf]Host: [host][crlf]Connection: keep-alive[crlf][crlf]',
    tlsFragment: true,
    fragmentSize: 12,
    fragmentDelayMs: 15
  },

  // === TIM BR ===
  {
    id: 'tim_cloudflare_split',
    name: 'TIM — Cloudflare Instant-Split ACL/GET (tim.com.br)',
    carrier: 'TIM BR',
    badge: 'CLÁSSICO TIM',
    mode: 'http_payload',
    sni: 'tim.com.br',
    payload:
      'ACL / HTTP/1.1[crlf]Host: [host][crlf][instant_split]GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf][crlf]',
    tlsFragment: true,
    fragmentSize: 16,
    fragmentDelayMs: 10
  },
  {
    id: 'tim_c6bank_sni',
    name: 'TIM — Parceria C6 Bank Zero-Rating (SSL/TLS + WebSocket)',
    carrier: 'TIM BR',
    badge: 'PARCEIRO ZERO-RATING',
    mode: 'ssl_payload_ws',
    sni: 'c6bank.com.br',
    payload:
      'GET / HTTP/1.1[crlf]Host: [host][crlf]X-Forwarded-Host: c6bank.com.br[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]',
    tlsFragment: true,
    fragmentSize: 12,
    fragmentDelayMs: 10
  },
  {
    id: 'tim_recarga_portal',
    name: 'TIM — Portal Recarga / Meu TIM (Delay-Split Bypass)',
    carrier: 'TIM BR',
    badge: 'PORTAL CATIVO',
    mode: 'http_payload',
    sni: 'recarga.tim.com.br',
    payload:
      'PATCH / HTTP/1.1[crlf]Host: recarga.tim.com.br[crlf][delay_split]GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]',
    tlsFragment: true,
    fragmentSize: 16,
    fragmentDelayMs: 12
  },
  {
    id: 'tim_ampli_edu',
    name: 'TIM — Ampli / Descomplica Educação SNI Fronting',
    carrier: 'TIM BR',
    badge: 'SNI EDUCAÇÃO',
    mode: 'ssl_sni',
    sni: 'ampli.com.br',
    payload: '',
    tlsFragment: true,
    fragmentSize: 16,
    fragmentDelayMs: 10
  },

  // === VIVO BR ===
  {
    id: 'vivo_front_ws',
    name: 'Vivo — AWS CloudFront / Meu Vivo WebSocket Upgrade',
    carrier: 'Vivo BR',
    badge: 'CLOUDFRONT',
    mode: 'http_payload',
    sni: 'meu.vivo.com.br',
    payload:
      'GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][split]User-Agent: [ua][crlf][crlf]',
    tlsFragment: true,
    fragmentSize: 16,
    fragmentDelayMs: 10
  },
  {
    id: 'vivo_azion_recarga',
    name: 'Vivo — Azion Edge Portal Recarga (Split-Header)',
    carrier: 'Vivo BR',
    badge: 'AZION EDGE',
    mode: 'http_payload',
    sni: 'recarga.vivo.com.br',
    payload:
      'HEAD http://recarga.vivo.com.br/ HTTP/1.1[crlf]Host: recarga.vivo.com.br[crlf][instant_split]GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]',
    tlsFragment: true,
    fragmentSize: 12,
    fragmentDelayMs: 10
  },
  {
    id: 'vivo_easy_tls',
    name: 'Vivo — Vivo Easy Zero-Rating + Split-TLS 10B',
    carrier: 'Vivo BR',
    badge: 'VIVO EASY',
    mode: 'ssl_payload_ws',
    sni: 'vivoeasy.com.br',
    payload:
      'GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]',
    tlsFragment: true,
    fragmentSize: 10,
    fragmentDelayMs: 12
  },

  // === UNIVERSAL / MULTI-OPERADORA ===
  {
    id: 'universal_whatsapp_meta',
    name: 'Universal — WhatsApp Zero-Rating SNI + Fragmentação 8B',
    carrier: 'Multi-Operadora',
    badge: 'WHATSAPP BYPASS',
    mode: 'direct_split',
    sni: 'g.whatsapp.net',
    payload: '',
    tlsFragment: true,
    fragmentSize: 8,
    fragmentDelayMs: 12
  },
  {
    id: 'universal_slowdns_doh',
    name: 'Universal — DoH / DNS Tunnel Keep-Alive Fallback',
    carrier: 'Multi-Operadora',
    badge: 'CONTINGÊNCIA DNS',
    mode: 'ssl_sni',
    sni: 'dns.google',
    payload: '',
    tlsFragment: true,
    fragmentSize: 12,
    fragmentDelayMs: 15
  }
];

module.exports = {
  parsePayloadTemplate,
  writePayloadSteps,
  createTunnelConnection,
  PRESET_PAYLOADS
};
