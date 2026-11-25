# Vortex Tunnel (`F:\vortex-tunnel`)

Aplicativo completo de **Túnel (Payload HTTP, Split-TLS, SSL/SNI, WebSocket)**, **Segurador de Sessão Claro Flex (Google AS15169 Keep-Alive)**, **IP Hunter (pré-configurado com a rota destravada `10.76.111.x` / `179.68.107.x`)**, **Scanner de Bug Hosts/CDN** e **Hotshare para PC**.

---

## 1. Como abrir no PC quando chegar em casa
Dê dois cliques em:
- [`INICIAR_VORTEX.bat`](file:///F:/vortex-tunnel/INICIAR_VORTEX.bat)
*(ou rode `node F:\vortex-tunnel\server.js` e abra `http://127.0.0.1:9090`)*

---

## 2. Como rodar direto no seu celular (POCO X6 Pro) sem precisar do PC
Você pode rodar esse mesmo painel 100% dentro do seu Android usando o **Termux**:
```bash
pkg update && pkg install nodejs -y
cd /sdcard/vortex-tunnel   # (ou copie a pasta para o celular)
node server.js
```
Depois é só abrir **`http://127.0.0.1:9090`** no navegador do celular (e o código nativo do serviço VPN Android também está em `android/app/src/main/java/com/vortex/tunnel/VortexVpnService.kt`).

---

## 3. O que cada aba do seu aplicativo faz

1. **Aba 1 — Túnel & Payload (`engine/payload.js` + `engine/proxy.js`)**
   - **Modo Split-TLS Direto (Sem precisar de VPS paga):** Fragmenta o pacote inicial do handshake TLS (`ClientHello`) em blocos pequenos (ex: 16 bytes) para passar por filtros de DPI.
   - **Modo HTTP Payload / SSL+SNI / WebSocket CDN:** Suporta tags `[crlf]`, `[split]`, `[instant_split]`, `[delay_split]`, `[host_port]`, `[ua]`, igual ao HTTP Injector e SocksLite.
   - **Hotshare Embutido:** Abre automaticamente um proxy **SOCKS5 na porta `10808`** e **HTTP/HTTPS na porta `8080`** na rede local (`0.0.0.0`) para compartilhar o túnel entre celular e PC via Wi-Fi ou Cabo USB sem Root.

2. **Aba 2 — Segurar Sessão Claro Flex (`engine/keepalive.js`)**
   - Reproduz exatamente o handshake que o **Antigravity (Google)** fez quando destravou sua linha com `0.0 GB` e bateu 130 Mbps:
     - Abre sessão **HTTP/2 (`h2` PING)** em `www.googleapis.com`
     - Abre canal de controle **TLS 1.3** em `mtalk.google.com:5228`
     - Dispara verificação `204` em `connectivitycheck.gstatic.com`
   - Mantém um pulso automático a cada **20 segundos** para a torre da Claro não derrubar seu IP `10.76.111.50` por inatividade.

3. **Aba 3 — IP Hunter (`engine/iphunter.js`)**
   - Já vem gravado com a assinatura exata que você capturou nos prints:
     - **IP Interno Alvo:** `10.76.111.` / `10.76.`
     - **Verificador de Pilha:** Confirma se a conexão está em **IPv4 Puro (Sem IPv6 `2804:`)**
     - **Gateway Público Alvo:** `179.68.107.` (`AS4230 CLARO S.A.` Curitiba/PR) + verificação de **DNS Reverso (PTR) ausente**.

4. **Aba 4 — Scanner de Bug Host & CDN (`engine/scanner.js`)**
   - Testa uma lista de domínios na porta 443 e descobre automaticamente qual **CDN** está por trás (`Cloudflare`, `AWS CloudFront`, `Akamai`, `Azion`, `Google Edge`, `Fastly`) e se responde na sua rede atual.
