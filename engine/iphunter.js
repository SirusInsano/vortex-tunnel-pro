const os = require('os');
const https = require('https');
const dns = require('dns');

/**
 * Pre-configured carrier unlock signatures, starting with yonsko's captured
 * Claro BR (Curitiba / PR) Fail-Open session:
 *   Internal CG-NAT IP : 10.76.111.50 (10.76.0.0/16)
 *   Stack posture      : IPv4-Only (No 2804:: global IPv6 assigned)
 *   Public Gateway     : 179.68.107.236 (179.68.0.0/16 - AS4230 CLARO S.A., No PTR)
 */
const CARRIER_SIGNATURES = [
  {
    id: 'claro_pr_failopen',
    name: 'Claro BR — Rota Fail-Open PR (10.76.x.x / 179.68.107.x)',
    carrier: 'Claro BR',
    internalPrefixes: ['10.76.111.', '10.76.'],
    publicPrefixes: ['179.68.107.', '179.68.'],
    requireIpv4Only: true,
    expectedAsn: 'AS4230',
    notes: 'Sessão IPv4 puro sem IPv6 (2804:) saindo pelo gateway 179.68.107.x sem PTR em Curitiba/PR.'
  },
  {
    id: 'tim_cgnat_hunter',
    name: 'TIM BR — Rota Portal / CDN Aberta (100.64.x - 100.90.x)',
    carrier: 'TIM BR',
    internalPrefixes: ['100.64.', '100.68.', '100.72.', '10.18.'],
    publicPrefixes: [],
    requireIpv4Only: false,
    expectedAsn: 'AS26615',
    notes: 'Faixas internas de PGW da TIM que permitem handshake SNI/WebSocket Cloudflare.'
  },
  {
    id: 'vivo_cgnat_hunter',
    name: 'Vivo BR — Rota 10.x / 177.x',
    carrier: 'Vivo BR',
    internalPrefixes: ['10.115.', '10.120.', '100.112.'],
    publicPrefixes: ['177.'],
    requireIpv4Only: false,
    expectedAsn: 'AS26599',
    notes: 'Faixa interna para injeção WebSocket CloudFront/Azion.'
  }
];

/**
 * Enumerates all local network interfaces and detects active cellular/LAN IPs and IPv6 presence.
 */
function inspectLocalInterfaces() {
  const interfaces = os.networkInterfaces();
  const list = [];
  let hasGlobalIpv6 = false;
  let primaryIpv4 = null;

  for (const [name, addrs] of Object.entries(interfaces)) {
    if (!addrs) continue;
    for (const addr of addrs) {
      if (addr.internal) continue;
      const isGlobalV6 =
        addr.family === 'IPv6' &&
        !addr.address.toLowerCase().startsWith('fe80:') &&
        !addr.address.toLowerCase().startsWith('::1');

      if (isGlobalV6) {
        hasGlobalIpv6 = true;
      }

      if (addr.family === 'IPv4' && !primaryIpv4) {
        primaryIpv4 = addr.address;
      }

      list.push({
        interface: name,
        family: addr.family,
        address: addr.address,
        netmask: addr.netmask,
        mac: addr.mac,
        cidr: addr.cidr || `${addr.address}`,
        isGlobalIpv6: isGlobalV6
      });
    }
  }

  return {
    primaryIpv4: primaryIpv4 || '0.0.0.0',
    hasGlobalIpv6,
    ipv4OnlySession: !hasGlobalIpv6,
    interfaces: list
  };
}

/**
 * Fetches public IP, ASN, City, Region, and checks Reverse DNS (PTR) absence.
 */
function fetchPublicIpTelemetry(timeoutMs = 5000) {
  return new Promise((resolve) => {
    const req = https.get(
      'https://ipinfo.io/json',
      {
        headers: {
          'User-Agent': 'curl/8.5.0',
          Accept: 'application/json'
        },
        timeout: timeoutMs
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          try {
            const parsed = JSON.parse(raw);
            const publicIp = parsed.ip || null;
            if (!publicIp) {
              return resolve({ reachable: false, error: 'Sem resposta de IP' });
            }
            // Check Reverse DNS PTR just like meuip.com.br showed ("Não identificado (DNS PTR ausente)")
            dns.reverse(publicIp, (err, hostnames) => {
              resolve({
                reachable: true,
                ip: publicIp,
                city: parsed.city || '',
                region: parsed.region || '',
                country: parsed.country || '',
                org: parsed.org || '',
                loc: parsed.loc || '',
                ptr: err || !hostnames || hostnames.length === 0 ? null : hostnames[0],
                ptrMissing: Boolean(err || !hostnames || hostnames.length === 0)
              });
            });
          } catch (e) {
            resolve({ reachable: false, error: e.message });
          }
        });
      }
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ reachable: false, error: 'Timeout consultando ipinfo.io' });
    });
    req.on('error', (err) => {
      resolve({ reachable: false, error: err.message });
    });
  });
}

/**
 * Runs a complete IP Hunter check against target prefixes and carrier signature.
 */
async function runIpHuntCheck(customTarget = {}) {
  const local = inspectLocalInterfaces();
  const pub = await fetchPublicIpTelemetry();

  const targetPrefixes = (customTarget.prefixes || '10.76.111.;10.76.;179.68.107.')
    .split(/[;,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const allObservedIps = [
    ...local.interfaces.map((i) => i.address),
    ...(pub.ip ? [pub.ip] : [])
  ];

  // Also allow user to test/simulate a specific mobile IP if running from PC while inspecting phone
  if (customTarget.simulatedInternalIp) {
    allObservedIps.push(customTarget.simulatedInternalIp.trim());
  }
  if (customTarget.simulatedPublicIp) {
    allObservedIps.push(customTarget.simulatedPublicIp.trim());
  }

  const matchedPrefixes = [];
  for (const prefix of targetPrefixes) {
    for (const ip of allObservedIps) {
      if (ip.startsWith(prefix)) {
        matchedPrefixes.push({ prefix, matchedIp: ip });
      }
    }
  }

  // Evaluate against Claro PR Fail-Open signature
  const internalMatch1076 = allObservedIps.some((ip) => ip.startsWith('10.76.'));
  const publicMatch17968 = allObservedIps.some((ip) => ip.startsWith('179.68.107.') || ip.startsWith('179.68.'));
  const isClaroAsn = (pub.org || '').includes('AS4230');

  let signatureScore = 0;
  const reasons = [];

  if (internalMatch1076) {
    signatureScore += 40;
    reasons.push('IP Interno na sub-rede 10.76.x.x detectado');
  }
  if (local.ipv4OnlySession) {
    signatureScore += 20;
    reasons.push('Sessão IPv4 Puro (sem IPv6 global 2804:: ativo)');
  }
  if (publicMatch17968) {
    signatureScore += 25;
    reasons.push('Gateway Público no bloco 179.68.x.x (Backbone Claro PR)');
  }
  if (pub.ptrMissing && pub.reachable) {
    signatureScore += 15;
    reasons.push('DNS Reverso (PTR) ausente no Gateway público (assinatura de rota destravada)');
  }

  return {
    timestamp: new Date().toISOString(),
    matched: matchedPrefixes.length > 0,
    matchedPrefixes,
    targetPrefixes,
    local,
    public: pub,
    claroFailOpenScore: signatureScore,
    isClaroAsn,
    reasons,
    signatures: CARRIER_SIGNATURES
  };
}

module.exports = {
  CARRIER_SIGNATURES,
  inspectLocalInterfaces,
  fetchPublicIpTelemetry,
  runIpHuntCheck
};
