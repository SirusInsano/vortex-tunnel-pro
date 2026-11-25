const https = require('https');
const { scanHostList } = require('./scanner');

/**
 * Certificate Transparency (crt.sh) Subdomain Bug Host Crawler
 * Queries crt.sh for recently issued SSL certificates on a root domain
 * (e.g., claro.com.br, tim.com.br, vivo.com.br, c6bank.com.br),
 * deduplicates valid hostnames, and probes them on port 443 to find
 * open Cloudflare / CloudFront / Azion / Akamai / Google Bug Hosts.
 */
function fetchCrtShSubdomains(rootDomain, maxHosts = 25, timeoutMs = 8000) {
  const cleanRoot = (rootDomain || 'claro.com.br')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^\*\./, '')
    .split('/')[0];

  const url = `https://crt.sh/?q=%25.${encodeURIComponent(cleanRoot)}&output=json`;

  return new Promise((resolve) => {
    const req = https.get(
      url,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VortexPro/2.3',
          Accept: 'application/json'
        },
        timeout: timeoutMs
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => {
          if (raw.length < 1024 * 512) raw += chunk;
        });
        res.on('end', () => {
          try {
            const entries = JSON.parse(raw);
            const set = new Set([cleanRoot]);
            for (const item of entries) {
              const names = String(item.name_value || '').split(/[\r\n]+/);
              for (const n of names) {
                const sub = n.trim().toLowerCase();
                if (
                  sub &&
                  !sub.includes('*') &&
                  !sub.includes(' ') &&
                  sub.endsWith(cleanRoot) &&
                  /^[a-z0-9.-]+$/.test(sub)
                ) {
                  set.add(sub);
                  if (set.size >= maxHosts) break;
                }
              }
              if (set.size >= maxHosts) break;
            }
            resolve(Array.from(set));
          } catch {
            resolve(getFallbackSubdomains(cleanRoot));
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve(getFallbackSubdomains(cleanRoot));
    });
    req.on('error', () => {
      resolve(getFallbackSubdomains(cleanRoot));
    });
  });
}

function getFallbackSubdomains(root) {
  const prefixes = [
    '',
    'm.',
    'www.',
    'api.',
    'app.',
    'portal.',
    'recarga.',
    'minha.',
    'meu.',
    'auth.',
    'login.',
    'cdn.',
    'static.',
    'pagamentos.',
    'fatura.',
    'flex.'
  ];
  return prefixes.map((p) => (p ? `${p}${root}` : root));
}

async function crawlAndProbeSubdomains(rootDomain, maxHosts = 20, onLog = () => {}) {
  onLog(`[SubFinder] Buscando subdomínios de *.${rootDomain} nos certificados SSL (crt.sh)...`);
  const subdomains = await fetchCrtShSubdomains(rootDomain, maxHosts);
  onLog(`[SubFinder] Encontrados ${subdomains.length} subdomínios. Testando CDN e porta 443...`);
  const results = await scanHostList(subdomains, 8);
  const alive = results.filter((r) => r.alive);
  onLog(`[SubFinder] Varredura concluída: ${alive.length}/${subdomains.length} subdomínios vivos!`);
  return {
    rootDomain,
    totalFound: subdomains.length,
    aliveCount: alive.length,
    results
  };
}

module.exports = {
  fetchCrtShSubdomains,
  crawlAndProbeSubdomains
};
