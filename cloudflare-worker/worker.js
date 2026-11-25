/**
 * VORTEX PRO - CLOUDFLARE WORKER SERVERLESS TUNNEL (100% GRÁTIS)
 * --------------------------------------------------------------
 * Como usar sem gastar R$ 1 com VPS:
 * 1. Crie uma conta gratuita em https://dash.cloudflare.com
 * 2. Vá em "Workers & Pages" -> "Create Worker"
 * 3. Cole este código abaixo e clique em "Deploy"
 * 4. Você vai ganhar um domínio grátis: seu-worker.seu-nome.workers.dev
 * 5. No Vortex Pro, coloque esse domínio em "Servidor" e use qualquer
 *    Bug Host da Claro/TIM/Vivo que passe pela Cloudflare (ex: m.claro.com.br, tim.com.br, c6bank.com.br)!
 */

export default {
  async fetch(request, env, ctx) {
    const upgradeHeader = request.headers.get('Upgrade');

    // Se não for conexão de túnel WebSocket, exibe página normal de disfarce
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response(
        JSON.stringify({
          status: 'online',
          edge: request.cf ? request.cf.colo : 'CF-Edge',
          service: 'Vortex Cloud Edge Relay v2.3'
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json; charset=utf-8' }
        }
      );
    }

    // Abre par de WebSockets na borda da Cloudflare
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    server.accept();

    let remoteSocket = null;
    let remoteWriter = null;

    server.addEventListener('message', async (event) => {
      try {
        const data = event.data;

        // Primeiro pacote define o destino (Formato: "HOST:PORT\n" ou tráfego direto)
        if (!remoteSocket) {
          let targetHost = request.headers.get('X-Target-Host') || 'www.google.com';
          let targetPort = Number(request.headers.get('X-Target-Port')) || 443;

          if (typeof data === 'string' && data.startsWith('CONNECT:')) {
            const parts = data.replace('CONNECT:', '').trim().split(':');
            targetHost = parts[0];
            targetPort = Number(parts[1]) || 443;
          }

          const { connect } = await import('cloudflare:sockets');
          remoteSocket = connect({ hostname: targetHost, port: targetPort });
          remoteWriter = remoteSocket.writable.getWriter();

          if (typeof data !== 'string' || !data.startsWith('CONNECT:')) {
            const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
            await remoteWriter.write(buf);
          }

          // Redireciona resposta do destino de volta para o celular via WebSocket Cloudflare
          const reader = remoteSocket.readable.getReader();
          (async () => {
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                server.send(value);
              }
            } catch (_) {
            } finally {
              try { server.close(); } catch (_) {}
            }
          })();
          return;
        }

        if (remoteWriter) {
          const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
          await remoteWriter.write(buf);
        }
      } catch (err) {
        try { server.close(); } catch (_) {}
      }
    });

    server.addEventListener('close', () => {
      try { if (remoteWriter) remoteWriter.close(); } catch (_) {}
    });

    return new Response(null, {
      status: 101,
      webSocket: client
    });
  }
};
