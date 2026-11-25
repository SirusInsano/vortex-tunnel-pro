const assert = require('assert');
const net = require('net');
const { parsePayloadTemplate } = require('./engine/payload');
const { runIpHuntCheck } = require('./engine/iphunter');
const { TunnelProxyServer } = require('./engine/proxy');

async function runTests() {
  console.log('=== 1. Testando Parser de Payload ([crlf], [split], [host_port]) ===');
  const steps = parsePayloadTemplate(
    'CONNECT [host_port] [protocol][crlf][split]Host: [host][crlf]User-Agent: [ua][crlf][crlf]',
    { targetHost: 'm.claro.com.br', targetPort: 443 }
  );
  assert.strictEqual(steps.length, 2, 'Deve dividir a payload em 2 etapas no [split]');
  assert(steps[0].data.includes('CONNECT m.claro.com.br:443 HTTP/1.1\r\n'));
  assert(steps[1].data.includes('Host: m.claro.com.br\r\n'));
  console.log('OK: Payload dividida corretamente em', steps.length, 'etapas.');

  console.log('\n=== 2. Testando Assinatura IP Hunter Claro PR (10.76.111.50 / 179.68.107.236) ===');
  const report = await runIpHuntCheck({
    prefixes: '10.76.111.;179.68.107.',
    simulatedInternalIp: '10.76.111.50',
    simulatedPublicIp: '179.68.107.236'
  });
  assert.strictEqual(report.matched, true, 'Deve detectar match nas faixas 10.76.111. e 179.68.107.');
  assert(report.claroFailOpenScore >= 65, 'Score Claro Fail-Open deve ser alto para a rota 10.76.111.50');
  console.log(
    'OK: IP Hunter reconheceu a rota destravada! Matches:',
    report.matchedPrefixes.map((m) => m.matchedIp).join(', '),
    '| Score:',
    report.claroFailOpenScore + '%'
  );

  console.log('\n=== 3. Testando Servidor Local SOCKS5 + HTTP Hotshare + Split-TLS ===');
  // Create a local echo target server to verify end-to-end proxy tunneling
  const echoServer = net.createServer((sock) => {
    sock.on('data', (d) => {
      sock.write(Buffer.concat([Buffer.from('ECHO:'), d]));
    });
  });
  await new Promise((r) => echoServer.listen(0, '127.0.0.1', r));
  const echoPort = echoServer.address().port;

  const proxy = new TunnelProxyServer(() => {});
  await proxy.start({
    mode: 'direct_split',
    tlsFragment: true,
    fragmentSize: 6,
    fragmentDelayMs: 5,
    hotshare: false,
    socksPort: 19808,
    httpPort: 18080
  });

  // Test HTTP CONNECT through Hotshare Proxy with packet fragmentation
  const response = await new Promise((resolve, reject) => {
    const client = net.connect(18080, '127.0.0.1', () => {
      client.write(`CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: 127.0.0.1:${echoPort}\r\n\r\n`);
    });
    let stage = 0;
    let receivedAfterConnect = '';
    let packetChunks = 0;
    client.on('data', (chunk) => {
      const txt = chunk.toString('utf8');
      if (stage === 0 && txt.includes('200 Connection Established')) {
        stage = 1;
        client.write('CLIENT_HELLO_FRAGMENT_TEST_PAYLOAD');
      } else if (stage === 1) {
        packetChunks++;
        receivedAfterConnect += txt.replace(/^ECHO:/, '');
        if (receivedAfterConnect.length >= 'CLIENT_HELLO_FRAGMENT_TEST_PAYLOAD'.length) {
          resolve({ fullText: receivedAfterConnect, packetChunks });
          client.destroy();
        }
      }
    });
    client.on('error', reject);
  });

  assert.strictEqual(response.fullText, 'CLIENT_HELLO_FRAGMENT_TEST_PAYLOAD');
  assert(response.packetChunks >= 2, 'O Split-TLS deve ter fragmentado o pacote em 2+ segmentos TCP');
  console.log(
    `OK: Túnel HTTP CONNECT + Fragmentação Split-TLS dividiu o handshake em ${response.packetChunks} pacotes TCP e entregou 100% dos dados.`
  );

  await proxy.stop();
  echoServer.close();
  console.log('\n=== TODOS OS TESTES PASSARAM COM SUCESSO ===');
}

runTests().catch((err) => {
  console.error('FALHA NOS TESTES:', err);
  process.exit(1);
});
