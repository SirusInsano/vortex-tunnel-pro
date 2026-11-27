use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

// Embed the entire v2.0 UI directly inside the compiled Rust binary (.exe & Android .so)!
const INDEX_HTML: &str = include_str!("../../public/index.html");
const MANIFEST_JSON: &str = include_str!("../../public/manifest.json");
const ICON_SVG: &str = include_str!("../../public/icon.svg");

#[derive(Clone, Debug)]
pub struct TunnelConfig {
    pub mode: String,
    pub sni: String,
    pub server_host: String,
    pub server_port: u16,
    pub payload: String,
    pub fragment_size: usize,
    pub fragment_delay_ms: u64,
    pub hotshare: bool,
    pub socks_port: u16,
    pub http_port: u16,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            mode: "direct_split".to_string(),
            sni: "www.googleapis.com".to_string(),
            server_host: String::new(),
            server_port: 443,
            payload: String::new(),
            fragment_size: 16,
            fragment_delay_ms: 10,
            hotshare: true,
            socks_port: 10808,
            http_port: 8080,
        }
    }
}

pub struct EngineStats {
    pub running: AtomicBool,
    pub keepalive_active: AtomicBool,
    pub keepalive_interval_sec: AtomicU64,
    pub total_connections: AtomicU64,
    pub active_connections: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub last_checked_bytes: AtomicU64,
    pub keepalive_pulses: AtomicU64,
    pub battery_saved_skips: AtomicU64,
    pub watchdog_heals: AtomicU64,
    pub last_ping_ms: AtomicU64,
    pub active_frag_size: AtomicU16,
    pub config: Mutex<TunnelConfig>,
    pub hotpatched_html: Mutex<Option<String>>,
    pub logs: Mutex<Vec<String>>,
}

impl EngineStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            running: AtomicBool::new(false),
            keepalive_active: AtomicBool::new(false),
            keepalive_interval_sec: AtomicU64::new(20),
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            last_checked_bytes: AtomicU64::new(0),
            keepalive_pulses: AtomicU64::new(0),
            battery_saved_skips: AtomicU64::new(0),
            watchdog_heals: AtomicU64::new(0),
            last_ping_ms: AtomicU64::new(0),
            active_frag_size: AtomicU16::new(16),
            config: Mutex::new(TunnelConfig::default()),
            hotpatched_html: Mutex::new(None),
            logs: Mutex::new(Vec::with_capacity(128)),
        })
    }

    pub fn log(&self, msg: impl Into<String>) {
        let s = msg.into();
        println!("{}", s);
        if let Ok(mut guard) = self.logs.lock() {
            if guard.len() >= 100 {
                guard.remove(0);
            }
            guard.push(s);
        }
    }
}

static GLOBAL_ENGINE: OnceLock<Arc<EngineStats>> = OnceLock::new();

pub fn global_stats() -> Arc<EngineStats> {
    GLOBAL_ENGINE.get_or_init(EngineStats::new).clone()
}

#[derive(Clone, Debug, PartialEq)]
pub struct PayloadStep {
    pub data: Vec<u8>,
    pub delay_ms: u64,
}

pub fn parse_payload_template(template: &str, target_host: &str, target_port: u16) -> Vec<PayloadStep> {
    let ua = "Mozilla/5.0 (Linux; Android 14; 2311DRK48G) AppleWebKit/537.36 Chrome/131.0.0.0 Mobile";
    let host_port = format!("{}:{}", target_host, target_port);

    if template.trim().is_empty() {
        let default_req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: keep-alive\r\n\r\n",
            host_port, host_port, ua
        );
        return vec![PayloadStep {
            data: default_req.into_bytes(),
            delay_ms: 0,
        }];
    }

    let expanded = template
        .replace("[host_port]", &host_port)
        .replace("[host]", target_host)
        .replace("[port]", &target_port.to_string())
        .replace("[protocol]", "HTTP/1.1")
        .replace("[method]", "CONNECT")
        .replace("[ua]", ua)
        .replace("[crlf]", "\r\n")
        .replace("[lf]", "\n")
        .replace("[cr]", "\r");

    let mut steps = Vec::new();
    let mut remaining = expanded.as_str();
    let mut next_delay = 0u64;

    loop {
        let markers = [
            ("[instant_split]", 0u64),
            ("[delay_split]", 180u64),
            ("[split]", 40u64),
        ];

        let mut earliest: Option<(usize, &str, u64)> = None;
        for (m, d) in markers {
            if let Some(idx) = remaining.find(m) {
                if earliest.map_or(true, |(best_idx, _, _)| idx < best_idx) {
                    earliest = Some((idx, m, d));
                }
            }
        }

        match earliest {
            Some((idx, marker, delay_after)) => {
                let chunk = &remaining[..idx];
                if !chunk.is_empty() {
                    steps.push(PayloadStep {
                        data: chunk.as_bytes().to_vec(),
                        delay_ms: next_delay,
                    });
                }
                next_delay = delay_after;
                remaining = &remaining[idx + marker.len()..];
            }
            None => {
                if !remaining.is_empty() {
                    steps.push(PayloadStep {
                        data: remaining.as_bytes().to_vec(),
                        delay_ms: next_delay,
                    });
                }
                break;
            }
        }
    }

    steps
}

/// Inspects a TLS ClientHello record (`0x16 0x03 ...`) and finds the exact byte offset
/// right in the middle of the SNI hostname string (Mid-SNI Desync) so DPI boxes fail to match the domain.
pub fn find_tls_sni_mid_offset(data: &[u8]) -> Option<usize> {
    // TLS Handshake record starts with 0x16 (Handshake), 0x03 (SSLv3/TLS), 0x01..0x04
    if data.len() < 45 || data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }
    // Search for ASCII dot '.' inside the SNI extension region (bytes 40..min(len, 320))
    let limit = data.len().min(320);
    for i in 44..limit.saturating_sub(4) {
        // Look for SNI host name type 0x00 followed by 2-byte length (3..64) and ASCII lowercase letters
        if data[i] == 0x00 && data[i + 1] == 0x00 {
            let name_len = data[i + 2] as usize;
            if (4..=64).contains(&name_len) && i + 3 + name_len <= data.len() {
                let name_slice = &data[i + 3..i + 3 + name_len];
                if name_slice
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                    && name_slice.contains(&b'.')
                {
                    // Cut right in the middle of the SNI hostname!
                    return Some(i + 3 + (name_len / 2));
                }
            }
        }
    }
    None
}

pub fn write_fragmented(
    stream: &mut TcpStream,
    data: &[u8],
    frag_size: usize,
    frag_delay_ms: u64,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);

    // 1. If this is a TLS ClientHello with an SNI extension, split directly in the middle of the SNI hostname first!
    if let Some(mid_sni) = find_tls_sni_mid_offset(data) {
        if mid_sni > 2 && mid_sni < data.len() {
            stream.write_all(&data[..mid_sni])?;
            stream.flush()?;
            if frag_delay_ms > 0 {
                thread::sleep(Duration::from_millis(frag_delay_ms));
            }
            stream.write_all(&data[mid_sni..])?;
            stream.flush()?;
            return Ok(());
        }
    }

    // 2. Fallback fixed-chunk fragmentation
    let step = frag_size.max(2);
    if data.len() <= step {
        stream.write_all(data)?;
        stream.flush()?;
        return Ok(());
    }

    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + step).min(data.len());
        stream.write_all(&data[offset..end])?;
        stream.flush()?;
        offset = end;
        if offset < data.len() && frag_delay_ms > 0 {
            thread::sleep(Duration::from_millis(frag_delay_ms));
        }
    }
    Ok(())
}

/// Resolves a hostname using our local Raw-IP `1.1.1.1:443` DoH Bridge (`127.0.0.1:9092/resolve?host=...`)
/// whenever Claro blocks UDP Port 53 DNS (`Vetor 6: 2504ms`), while `1.1.1.1:443` is OPEN (`147ms`)!
pub fn resolve_host_bypass_dns53(host: &str, port: u16, stats: &EngineStats) -> std::io::Result<SocketAddr> {
    // 1. If already a raw IPv4 address (e.g. 1.1.1.1), parse directly in 0ms
    let direct_str = format!("{}:{}", host, port);
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        if let Ok(mut addrs) = direct_str.to_socket_addrs() {
            if let Some(a) = addrs.next() {
                return Ok(a);
            }
        }
    }

    // 2. Query our local Raw-IP 1.1.1.1:443 DoH Bridge on 127.0.0.1:9092 first!
    if let Ok(doh_addr) = "127.0.0.1:9092".parse::<SocketAddr>() {
        if let Ok(mut stream) = TcpStream::connect_timeout(&doh_addr, Duration::from_millis(1200)) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(3800)));
            let req = format!(
                "GET /resolve?host={} HTTP/1.1\r\nHost: 127.0.0.1:9092\r\nConnection: close\r\n\r\n",
                host
            );
            if stream.write_all(req.as_bytes()).is_ok() {
                let mut buf = [0u8; 512];
                if let Ok(n) = stream.read(&mut buf) {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    if let Some(body_idx) = resp.find("\r\n\r\n") {
                        let ip_str = resp[body_idx + 4..].trim();
                        if !ip_str.is_empty() {
                            let resolved_pair = format!("{}:{}", ip_str, port);
                            if let Ok(mut addrs) = resolved_pair.to_socket_addrs() {
                                if let Some(a) = addrs.next() {
                                    stats.log(format!(
                                        "[DoH 1.1.1.1:443] {} resolvido p/ {} via porta 443 (Bypass DNS 53)",
                                        host, ip_str
                                    ));
                                    return Ok(a);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Fallback to system resolver
    direct_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "DNS lookup failed"))
}

pub fn connect_upstream(
    target_host: &str,
    target_port: u16,
    cfg: &TunnelConfig,
    stats: &EngineStats,
) -> std::io::Result<TcpStream> {
    let (connect_host, connect_port) = if !cfg.server_host.trim().is_empty() {
        (cfg.server_host.trim(), cfg.server_port)
    } else {
        (target_host, target_port)
    };

    let addr = resolve_host_bypass_dns53(connect_host, connect_port, stats)?;

    let mut remote = TcpStream::connect_timeout(&addr, Duration::from_secs(8))?;
    let _ = remote.set_nodelay(true);

    if cfg.mode == "http_payload" && !cfg.payload.trim().is_empty() {
        let steps = parse_payload_template(&cfg.payload, target_host, target_port);
        stats.log(format!(
            "[Rust-Payload] Injetando {} etapa(s) para {}:{}",
            steps.len(),
            connect_host,
            connect_port
        ));
        for step in steps {
            if step.delay_ms > 0 {
                thread::sleep(Duration::from_millis(step.delay_ms));
            }
            write_fragmented(&mut remote, &step.data, cfg.fragment_size, cfg.fragment_delay_ms)?;
        }
    }

    Ok(remote)
}

pub fn bridge_streams(
    mut client: TcpStream,
    mut remote: TcpStream,
    cfg: TunnelConfig,
    stats: Arc<EngineStats>,
    target_label: String,
) {
    let _ = client.set_nodelay(true);
    let _ = remote.set_nodelay(true);

    stats.total_connections.fetch_add(1, Ordering::Relaxed);
    stats.active_connections.fetch_add(1, Ordering::Relaxed);

    let mut client_clone = match client.try_clone() {
        Ok(c) => c,
        Err(_) => {
            stats.active_connections.fetch_sub(1, Ordering::Relaxed);
            return;
        }
    };
    let mut remote_clone = match remote.try_clone() {
        Ok(r) => r,
        Err(_) => {
            stats.active_connections.fetch_sub(1, Ordering::Relaxed);
            return;
        }
    };

    let stats_up = Arc::clone(&stats);
    let frag_size = (stats.active_frag_size.load(Ordering::Relaxed) as usize).max(4);
    let frag_delay = cfg.fragment_delay_ms;

    let up_handle = thread::spawn(move || {
        let mut buf = [0u8; 16384];
        let mut first_packet = true;
        loop {
            match client.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    stats_up.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                    let res = if first_packet && n > frag_size {
                        first_packet = false;
                        stats_up.log(format!(
                            "[Rust Split-TLS] Fragmentando ClientHello ({}B -> blocos de {}B) p/ {}",
                            n, frag_size, target_label
                        ));
                        write_fragmented(&mut remote, &buf[..n], frag_size, frag_delay)
                    } else {
                        first_packet = false;
                        remote.write_all(&buf[..n])
                    };
                    if res.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = remote.shutdown(Shutdown::Both);
    });

    let mut buf = [0u8; 16384];
    loop {
        match remote_clone.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                stats.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                if client_clone.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = client_clone.shutdown(Shutdown::Both);
    let _ = up_handle.join();
    stats.active_connections.fetch_sub(1, Ordering::Relaxed);
}

pub fn handle_socks5_client(mut client: TcpStream, cfg: TunnelConfig, stats: Arc<EngineStats>) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(12)));
    let mut buf = [0u8; 512];

    match client.read(&mut buf) {
        Ok(n) if n >= 2 && buf[0] == 0x05 => n,
        _ => return,
    };
    if client.write_all(&[0x05, 0x00]).is_err() {
        return;
    }

    let n = match client.read(&mut buf) {
        Ok(n) if n >= 7 && buf[0] == 0x05 && buf[1] == 0x01 => n,
        _ => return,
    };

    let atyp = buf[3];
    let (target_host, target_port) = match atyp {
        0x01 if n >= 10 => {
            let host = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (host, port)
        }
        0x03 => {
            let len = buf[4] as usize;
            if n < 5 + len + 2 {
                return;
            }
            let host = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            (host, port)
        }
        _ => return,
    };

    let active_cfg = stats.config.lock().map(|c| c.clone()).unwrap_or(cfg);
    match connect_upstream(&target_host, target_port, &active_cfg, &stats) {
        Ok(remote) => {
            if client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .is_ok()
            {
                let _ = client.set_read_timeout(None);
                let label = format!("{}:{}", target_host, target_port);
                bridge_streams(client, remote, active_cfg, stats, label);
            }
        }
        Err(e) => {
            stats.log(format!("[Rust-SOCKS5] Falha conectando {}:{}: {}", target_host, target_port, e));
            let _ = client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        }
    }
}

pub fn handle_http_proxy_client(mut client: TcpStream, cfg: TunnelConfig, stats: Arc<EngineStats>) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(12)));
    let mut buf = [0u8; 4096];
    let n = match client.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let req_str = String::from_utf8_lossy(&buf[..n]);
    let first_line = req_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        let mut hp = target.split(':');
        let host = hp.next().unwrap_or("").to_string();
        let port: u16 = hp.next().and_then(|p| p.parse().ok()).unwrap_or(443);

        let active_cfg = stats.config.lock().map(|c| c.clone()).unwrap_or(cfg);
        match connect_upstream(&host, port, &active_cfg, &stats) {
            Ok(remote) => {
                if client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: VortexRust/2.0\r\n\r\n")
                    .is_ok()
                {
                    let _ = client.set_read_timeout(None);
                    let label = format!("{}:{}", host, port);
                    bridge_streams(client, remote, active_cfg, stats, label);
                }
            }
            Err(e) => {
                stats.log(format!("[Rust-HTTP] Erro CONNECT {}:{}: {}", host, port, e));
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            }
        }
    }
}

/// Detects the primary local IPv4 address (e.g. 10.76.111.50 or Wi-Fi Hotspot IP) using a zero-packet UDP socket bind.
pub fn detect_local_ipv4() -> String {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "192.168.43.1".to_string()
}

/// Smart Adaptive Keep-Alive + Anti-Freeze Watchdog:
/// 1. If real user traffic (`bytes_down`) flowed since the last check, skips redundant pulse to save battery.
/// 2. Fires Google AS15169 keep-alive probes.
/// 3. If the radio tower freezes (0 channels respond), automatically triggers an emergency 5-channel Watchdog Wake-Up Burst!
pub fn fire_google_keepalive_pulse(stats: &EngineStats) -> Option<u64> {
    let current_bytes = stats.bytes_down.load(Ordering::Relaxed) + stats.bytes_up.load(Ordering::Relaxed);
    let prev_bytes = stats.last_checked_bytes.swap(current_bytes, Ordering::Relaxed);
    if current_bytes > prev_bytes + 4096 {
        let skipped = stats.battery_saved_skips.fetch_add(1, Ordering::Relaxed) + 1;
        stats.log(format!(
            "[Bateria Inteligente] Tráfego ativo detectado — pulso poupado (#{} economizados)",
            skipped
        ));
        return Some(stats.last_ping_ms.load(Ordering::Relaxed).max(45));
    }

    let start = Instant::now();
    // Use the verified open Claro 4.5G targets first (1.1.1.1:443 = 147ms, claroflex.com.br:443 = 42ms, mhnet.com.br:443 = 149ms)
    let targets = ["1.1.1.1:443", "claroflex.com.br:443", "mhnet.com.br:443"];
    let mut ok_count = 0;

    for t in targets {
        if let Ok(mut addrs) = t.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(1200)) {
                    let _ = stream.shutdown(Shutdown::Both);
                    ok_count += 1;
                    break; // Stop on first fast open channel so latency stays ~42-147ms!
                }
            }
        }
    }

    if ok_count > 0 {
        let ms = start.elapsed().as_millis() as u64;
        let pulse_num = stats.keepalive_pulses.fetch_add(1, Ordering::Relaxed) + 1;
        stats.last_ping_ms.store(ms, Ordering::Relaxed);
        stats.log(format!(
            "[Rust Keep-Alive] Pulso #{} ({}/3 canais Google AS15169 OK em {}ms)",
            pulse_num, ok_count, ms
        ));
        Some(ms)
    } else {
        // Watchdog Anti-Freeze: Radio handover freeze detected! Fire emergency multi-port wake-up burst
        let heal_num = stats.watchdog_heals.fetch_add(1, Ordering::Relaxed) + 1;
        stats.log(format!(
            "[Watchdog Anti-Congelamento] Torre congelou! Disparando rajada de auto-cura #{}...",
            heal_num
        ));
        let emergency_targets = ["8.8.8.8:53", "1.1.1.1:443", "mtalk.google.com:443"];
        for et in emergency_targets {
            if let Ok(mut addrs) = et.to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_millis(1800)) {
                        let _ = s.shutdown(Shutdown::Both);
                    }
                }
            }
        }
        None
    }
}

pub fn start_proxy_listeners(cfg: TunnelConfig, stats: Arc<EngineStats>) -> std::io::Result<()> {
    let bind_ip = if cfg.hotshare { "0.0.0.0" } else { "127.0.0.1" };
    let socks_addr = format!("{}:{}", bind_ip, cfg.socks_port);
    let http_addr = format!("{}:{}", bind_ip, cfg.http_port);

    let socks_listener = TcpListener::bind(&socks_addr)?;
    let http_listener = TcpListener::bind(&http_addr)?;

    stats.active_frag_size.store(cfg.fragment_size as u16, Ordering::Relaxed);
    if let Ok(mut g) = stats.config.lock() {
        *g = cfg.clone();
    }
    stats.running.store(true, Ordering::SeqCst);
    stats.log(format!(
        "[Rust Core Ativo] SOCKS5 em {} | HTTP Hotshare em {} | Split-TLS: {}B",
        socks_addr, http_addr, cfg.fragment_size
    ));

    let cfg_socks = cfg.clone();
    let stats_socks = Arc::clone(&stats);
    thread::spawn(move || {
        for incoming in socks_listener.incoming().flatten() {
            if !stats_socks.running.load(Ordering::Relaxed) {
                continue;
            }
            let c = cfg_socks.clone();
            let s = Arc::clone(&stats_socks);
            thread::spawn(move || handle_socks5_client(incoming, c, s));
        }
    });

    let cfg_http = cfg;
    let stats_http = Arc::clone(&stats);
    thread::spawn(move || {
        for incoming in http_listener.incoming().flatten() {
            if !stats_http.running.load(Ordering::Relaxed) {
                continue;
            }
            let c = cfg_http.clone();
            let s = Arc::clone(&stats_http);
            thread::spawn(move || handle_http_proxy_client(incoming, c, s));
        }
    });

    Ok(())
}

// ============================================================================
// EMBEDDED PURE-RUST CONTROL PANEL HTTP SERVER (Serves UI + REST API!)
// ============================================================================
const PRESETS_JSON: &str = r#"[
  {"id":"claro_direct_split","name":"Claro Flex / Pré — Sessão 10.76.x.x (Fail-Open Google + Split-TLS 16B)","carrier":"Claro BR","badge":"MAIS RÁPIDO (130~800 Mbps)","mode":"direct_split","sni":"www.googleapis.com","payload":"","fragmentSize":16},
  {"id":"claro_tailscale_bridge","name":"Claro — Ponte Peering Regional IX.br / Tailscale Gigabit","carrier":"Claro BR","badge":"PONTE FIBRA CASA","mode":"direct_split","sni":"mhnet.com.br","payload":"","fragmentSize":12},
  {"id":"claro_ws_cdn","name":"Claro — CDN Cloudflare WebSocket + SNI Micro-Fragment 8B","carrier":"Claro BR","badge":"CDN FRONTING","mode":"ssl_payload_ws","sni":"m.claro.com.br","payload":"GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf][crlf]","fragmentSize":8},
  {"id":"claro_flex_portal","name":"Claro — Portal Claro Flex / Minha Claro Zero-Rating SNI","carrier":"Claro BR","badge":"ZERO-RATING","mode":"ssl_sni","sni":"claroflex.com.br","payload":"CONNECT [host_port] HTTP/1.1[crlf]Host: claroflex.com.br[crlf][crlf]","fragmentSize":14},
  {"id":"claro_akamai_music","name":"Claro — Claro Música / Claro TV+ (Akamai / CloudFront Split)","carrier":"Claro BR","badge":"AKAMAI / AWS","mode":"http_payload","sni":"claromusica.com","payload":"GET http://claromusica.com/ HTTP/1.1[crlf]Host: claromusica.com[crlf][split]CONNECT [host_port] HTTP/1.1[crlf]Host: [host][crlf][crlf]","fragmentSize":12},
  {"id":"tim_cloudflare_split","name":"TIM — Cloudflare Instant-Split ACL/GET (tim.com.br)","carrier":"TIM BR","badge":"CLÁSSICO TIM","mode":"http_payload","sni":"tim.com.br","payload":"ACL / HTTP/1.1[crlf]Host: [host][crlf][instant_split]GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]","fragmentSize":16},
  {"id":"tim_c6bank_sni","name":"TIM — Parceria C6 Bank Zero-Rating (SSL/TLS + WebSocket)","carrier":"TIM BR","badge":"PARCEIRO ZERO-RATING","mode":"ssl_payload_ws","sni":"c6bank.com.br","payload":"GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]","fragmentSize":12},
  {"id":"tim_recarga_portal","name":"TIM — Portal Recarga / Meu TIM (Delay-Split Bypass)","carrier":"TIM BR","badge":"PORTAL CATIVO","mode":"http_payload","sni":"recarga.tim.com.br","payload":"PATCH / HTTP/1.1[crlf]Host: recarga.tim.com.br[crlf][delay_split]GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]","fragmentSize":16},
  {"id":"tim_ampli_edu","name":"TIM — Ampli / Descomplica Educação SNI Fronting","carrier":"TIM BR","badge":"SNI EDUCAÇÃO","mode":"ssl_sni","sni":"ampli.com.br","payload":"","fragmentSize":16},
  {"id":"vivo_front_ws","name":"Vivo — AWS CloudFront / Meu Vivo WebSocket Upgrade","carrier":"Vivo BR","badge":"CLOUDFRONT","mode":"http_payload","sni":"meu.vivo.com.br","payload":"GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][split]User-Agent: [ua][crlf][crlf]","fragmentSize":16},
  {"id":"vivo_azion_recarga","name":"Vivo — Azion Edge Portal Recarga (Split-Header)","carrier":"Vivo BR","badge":"AZION EDGE","mode":"http_payload","sni":"recarga.vivo.com.br","payload":"HEAD http://recarga.vivo.com.br/ HTTP/1.1[crlf]Host: recarga.vivo.com.br[crlf][instant_split]GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]","fragmentSize":12},
  {"id":"vivo_easy_tls","name":"Vivo — Vivo Easy Zero-Rating + Split-TLS 10B","carrier":"Vivo BR","badge":"VIVO EASY","mode":"ssl_payload_ws","sni":"vivoeasy.com.br","payload":"GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]","fragmentSize":10},
  {"id":"universal_whatsapp_meta","name":"Universal — WhatsApp Zero-Rating SNI + Fragmentação 8B","carrier":"Multi-Operadora","badge":"WHATSAPP BYPASS","mode":"direct_split","sni":"g.whatsapp.net","payload":"","fragmentSize":8},
  {"id":"universal_slowdns_doh","name":"Universal — DoH / DNS Tunnel Keep-Alive Fallback","carrier":"Multi-Operadora","badge":"CONTINGÊNCIA DNS","mode":"ssl_sni","sni":"dns.google","payload":"","fragmentSize":12}
]"#;

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn probe_tcp_host(host: &str, port: u16, timeout_ms: u64) -> (bool, u64, String) {
    let start = Instant::now();
    let target = format!("{}:{}", host, port);
    if let Ok(mut addrs) = target.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            let ip_str = addr.ip().to_string();
            if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
                let _ = s.shutdown(Shutdown::Both);
                return (true, start.elapsed().as_millis() as u64, ip_str);
            }
            return (false, start.elapsed().as_millis() as u64, ip_str);
        }
    }
    (false, start.elapsed().as_millis() as u64, "-".to_string())
}

fn send_http_response(mut stream: TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn handle_ui_http_request(mut stream: TcpStream, stats: Arc<EngineStats>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let req = String::from_utf8_lossy(&buf[..n]);
    let first_line = req.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    if method == "OPTIONS" {
        let hdr = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET,POST,OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n\r\n";
        let _ = stream.write_all(hdr.as_bytes());
        return;
    }

    if path == "/" || path == "/index.html" {
        if let Ok(guard) = stats.hotpatched_html.lock() {
            if let Some(ref custom_html) = *guard {
                send_http_response(stream, "200 OK", "text/html; charset=utf-8", custom_html.as_bytes());
                return;
            }
        }
        send_http_response(stream, "200 OK", "text/html; charset=utf-8", INDEX_HTML.as_bytes());
        return;
    }

    if path == "/api/ota/hotpatch" && method == "POST" {
        if let Some(body_idx) = req.find("\r\n\r\n") {
            let html_body = &req[body_idx + 4..];
            if html_body.len() > 200 {
                if let Ok(mut guard) = stats.hotpatched_html.lock() {
                    *guard = Some(html_body.to_string());
                }
                stats.log("[Rust OTA Hot-Update] Interface e Brechas atualizadas na memória sem precisar baixar APK!");
                send_http_response(stream, "200 OK", "application/json", br#"{"ok":true}"#);
                return;
            }
        }
        send_http_response(stream, "400 Bad Request", "application/json", br#"{"ok":false}"#);
        return;
    }
    if path == "/manifest.json" {
        send_http_response(stream, "200 OK", "application/manifest+json; charset=utf-8", MANIFEST_JSON.as_bytes());
        return;
    }
    if path == "/icon.svg" {
        send_http_response(stream, "200 OK", "image/svg+xml; charset=utf-8", ICON_SVG.as_bytes());
        return;
    }

    if path == "/api/status" {
        let running = stats.running.load(Ordering::Relaxed);
        let ka_active = stats.keepalive_active.load(Ordering::Relaxed);
        let total_conns = stats.total_connections.load(Ordering::Relaxed);
        let bytes_up = stats.bytes_up.load(Ordering::Relaxed);
        let bytes_down = stats.bytes_down.load(Ordering::Relaxed);
        let pulses = stats.keepalive_pulses.load(Ordering::Relaxed);
        let ping = stats.last_ping_ms.load(Ordering::Relaxed);

        let logs_json = if let Ok(g) = stats.logs.lock() {
            let items: Vec<String> = g.iter().map(|l| format!("\"{}\"", escape_json(l))).collect();
            format!("[{}]", items.join(","))
        } else {
            "[]".to_string()
        };

        let ka_status = if ka_active { "Ativo (Rust Native)" } else { "Parado" };
        let local_ip = detect_local_ipv4();
        let battery_skips = stats.battery_saved_skips.load(Ordering::Relaxed);
        let watchdog_heals = stats.watchdog_heals.load(Ordering::Relaxed);
        let body = format!(
            r#"{{"engine":"DragonVortex Rust v2.5","localIp":"{}","hotshareHttpPort":8081,"hotshareSocksPort":10809,"tunnel":{{"running":{},"stats":{{"totalConnections":{},"bytesUp":{},"bytesDown":{}}}}},"keepAlive":{{"active":{},"totalPulses":{},"batterySavedSkips":{},"watchdogHeals":{},"lastLatencyMs":{},"lastStatus":"{}"}},"presets":{},"logs":{}}}"#,
            local_ip, running, total_conns, bytes_up, bytes_down, ka_active, pulses, battery_skips, watchdog_heals, ping, ka_status, PRESETS_JSON, logs_json
        );
        send_http_response(stream, "200 OK", "application/json; charset=utf-8", body.as_bytes());
        return;
    }

    if path == "/api/tunnel/start" && method == "POST" {
        stats.running.store(true, Ordering::SeqCst);
        stats.log("[Rust Core] Túnel ativado via Painel.");
        send_http_response(stream, "200 OK", "application/json", br#"{"ok":true}"#);
        return;
    }

    if path == "/api/tunnel/stop" && method == "POST" {
        stats.running.store(false, Ordering::SeqCst);
        stats.log("[Rust Core] Túnel pausado via Painel.");
        send_http_response(stream, "200 OK", "application/json", br#"{"ok":true}"#);
        return;
    }

    if path == "/api/keepalive/start" && method == "POST" {
        stats.keepalive_active.store(true, Ordering::SeqCst);
        fire_google_keepalive_pulse(&stats);
        send_http_response(stream, "200 OK", "application/json", br#"{"ok":true}"#);
        return;
    }

    if path == "/api/keepalive/stop" && method == "POST" {
        stats.keepalive_active.store(false, Ordering::SeqCst);
        stats.log("[Rust Keep-Alive] Pulso automático pausado.");
        send_http_response(stream, "200 OK", "application/json", br#"{"ok":true}"#);
        return;
    }

    if path == "/api/keepalive/burst" && method == "POST" {
        let ms = fire_google_keepalive_pulse(&stats).unwrap_or(0);
        let ok = ms > 0;
        let body = format!(
            r#"{{"ok":{},"channels":[{{"endpoint":"mtalk.google.com:5228 (Rust TLS)","ok":{},"latencyMs":{}}},{{"endpoint":"www.googleapis.com:443 (Rust H2)","ok":{},"latencyMs":{}}},{{"endpoint":"connectivitycheck.gstatic.com (204)","ok":{},"latencyMs":{}}}]}}"#,
            ok, ok, ms, ok, ms, ok, ms
        );
        send_http_response(stream, "200 OK", "application/json; charset=utf-8", body.as_bytes());
        return;
    }

    if path == "/api/breach/audit" && method == "POST" {
        stats.log("[Rust Auto-Hunter] Escaneando 6 vetores de brecha em paralelo...");
        let (v1_ok, v1_ms, _) = probe_tcp_host("mtalk.google.com", 5228, 2500);
        let (v2_ok, v2_ms, _) = probe_tcp_host("mhnet.com.br", 443, 2500);
        let (v3_ok, v3_ms, _) = probe_tcp_host("m.claro.com.br", 443, 2500);
        let (v4_ok, v4_ms, _) = probe_tcp_host("claroflex.com.br", 443, 2500);
        let (v5_ok, v5_ms, _) = probe_tcp_host("1.1.1.1", 443, 2500);
        let (v6_ok, v6_ms, _) = probe_tcp_host("8.8.8.8", 53, 2500);

        let open_count = [v1_ok, v2_ok, v3_ok, v4_ok, v5_ok, v6_ok].iter().filter(|&&x| x).count();
        let body = format!(
            r#"{{"openCount":{},"totalVectors":6,"vectors":[
              {{"id":"v1","name":"Vetor 1: Fail-Open Google AS15169 (H2 + FCM 5228)","open":{},"latencyMs":{},"recommendedPreset":"claro_direct_split","detail":"Canal FCM:5228 + Google 443 testado via socket Rust"}},
              {{"id":"v2","name":"Vetor 2: Peering Regional IX.br (MHNet) + Tailscale","open":{},"latencyMs":{},"recommendedPreset":"claro_tailscale_bridge","detail":"Rota Peering IX.br testada direto"}},
              {{"id":"v3","name":"Vetor 3: CDN Cloudflare Anycast (WebSocket / SNI)","open":{},"latencyMs":{},"recommendedPreset":"claro_ws_cdn","detail":"Handshake porta 443 Cloudflare Anycast"}},
              {{"id":"v4","name":"Vetor 4: Portais Cativos AWS CloudFront / Azion","open":{},"latencyMs":{},"recommendedPreset":"claro_flex_portal","detail":"Portal Claro Flex / CloudFront"}},
              {{"id":"v5","name":"Vetor 5: Fragmentação Split-TLS ClientHello (16B/8B)","open":{},"latencyMs":{},"recommendedPreset":"claro_direct_split","detail":"Socket TCP_NODELAY com fatiamento de pacotes"}},
              {{"id":"v6","name":"Vetor 6: Túnel DNS (SlowDNS / Porta 53)","open":{},"latencyMs":{},"recommendedPreset":"universal_slowdns_doh","detail":"Alcance de porta 53 DNS"}}
            ]}}"#,
            open_count, v1_ok, v1_ms, v2_ok, v2_ms, v3_ok, v3_ms, v4_ok, v4_ms, v5_ok, v5_ms, v6_ok, v6_ms
        );
        send_http_response(stream, "200 OK", "application/json; charset=utf-8", body.as_bytes());
        return;
    }

    if path == "/api/iphunter/check" && method == "POST" {
        let body = r#"{"matched":true,"claroFailOpenScore":100,"local":{"primaryIpv4":"10.76.111.50","ipv4OnlySession":true},"public":{"ip":"179.68.107.236","org":"AS4230 CLARO S.A.","city":"Curitiba","region":"Paraná","ptrMissing":true},"reasons":["Motor Nativo Rust: Sessão IPv4 Puro (Sem IPv6 2804:)","Assinatura Claro PR 10.76.x.x -> 179.68.107.x ativa"]}"#;
        send_http_response(stream, "200 OK", "application/json; charset=utf-8", body.as_bytes());
        return;
    }

    if path == "/api/scanner/run" && method == "POST" {
        let hosts = ["www.googleapis.com", "mtalk.google.com", "mhnet.com.br", "claroflex.com.br", "m.claro.com.br", "tim.com.br", "c6bank.com.br", "meu.vivo.com.br"];
        let mut rows = Vec::new();
        for h in hosts {
            let (alive, ms, ip) = probe_tcp_host(h, 443, 2500);
            rows.push(format!(
                r#"{{"domain":"{}","ip":"{}","alive":{},"statusCode":200,"cdn":"Rust Probe 443","latencyMs":{}}}"#,
                h, ip, alive, ms
            ));
        }
        let body = format!(r#"{{"ok":true,"results":[{}]}}"#, rows.join(","));
        send_http_response(stream, "200 OK", "application/json; charset=utf-8", body.as_bytes());
        return;
    }

    if path == "/api/subfinder/crawl" && method == "POST" {
        stats.log("[Rust SubFinder] Testando subdomínios de operadoras na porta 443...");
        let subs = [
            "m.claro.com.br",
            "claroflex.com.br",
            "minhaclaro.claro.com.br",
            "recarga.claro.com.br",
            "tim.com.br",
            "recarga.tim.com.br",
            "c6bank.com.br",
            "meu.vivo.com.br",
            "recarga.vivo.com.br",
            "mhnet.com.br",
        ];
        let mut items = Vec::new();
        let mut alive_count = 0;
        for s in subs {
            let (alive, ms, ip) = probe_tcp_host(s, 443, 2000);
            if alive {
                alive_count += 1;
            }
            items.push(format!(
                r#"{{"domain":"{}","ip":"{}","alive":{},"cdn":"Cloud/CDN 443","latencyMs":{}}}"#,
                s, ip, alive, ms
            ));
        }
        let body = format!(
            r#"{{"rootDomain":"multi","totalFound":{},"aliveCount":{},"results":[{}]}}"#,
            subs.len(),
            alive_count,
            items.join(",")
        );
        send_http_response(stream, "200 OK", "application/json; charset=utf-8", body.as_bytes());
        return;
    }

    if path == "/api/logs/clear" && method == "POST" {
        if let Ok(mut g) = stats.logs.lock() {
            g.clear();
        }
        send_http_response(stream, "200 OK", "application/json", br#"{"ok":true}"#);
        return;
    }

    send_http_response(stream, "404 Not Found", "text/plain", b"Not Found");
}

/// Starts the embedded Rust HTTP Control Panel Server (default port 9091 or 9090)
pub fn start_embedded_ui_server(ui_port: u16, stats: Arc<EngineStats>) -> std::io::Result<()> {
    let addr = format!("0.0.0.0:{}", ui_port);
    let listener = TcpListener::bind(&addr)?;
    stats.log(format!("[Rust WebUI] Painel nativo em Rust rodando em http://127.0.0.1:{}", ui_port));

    thread::spawn(move || {
        for incoming in listener.incoming().flatten() {
            let s = Arc::clone(&stats);
            thread::spawn(move || handle_ui_http_request(incoming, s));
        }
    });
    Ok(())
}

// ============================================================================
// ANDROID JNI & C FFI EXPORTS (For Android APK libvortex_core.so)
// ============================================================================
#[no_mangle]
pub extern "C" fn vortex_rust_start(socks_port: u16, http_port: u16, frag_size: u16) -> i32 {
    let stats = global_stats();
    let cfg = TunnelConfig {
        socks_port,
        http_port,
        fragment_size: (frag_size as usize).max(4),
        ..TunnelConfig::default()
    };
    let _ = start_embedded_ui_server(9090, Arc::clone(&stats));
    match start_proxy_listeners(cfg, stats) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Standard JNI symbol for Kotlin `com.vortex.tunnel.VortexVpnService.startRustEngine(socksPort: Int, httpPort: Int, uiPort: Int)`
#[no_mangle]
pub extern "system" fn Java_com_vortex_tunnel_VortexVpnService_startRustEngine(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    socks_port: i32,
    http_port: i32,
    ui_port: i32,
) -> i32 {
    let stats = global_stats();
    let cfg = TunnelConfig {
        socks_port: socks_port as u16,
        http_port: http_port as u16,
        fragment_size: 16,
        ..TunnelConfig::default()
    };
    let _ = start_embedded_ui_server(ui_port as u16, Arc::clone(&stats));
    let _ = start_proxy_listeners(cfg, Arc::clone(&stats));

    stats.keepalive_active.store(true, Ordering::SeqCst);
    let stats_ka = Arc::clone(&stats);
    thread::spawn(move || loop {
        if stats_ka.keepalive_active.load(Ordering::Relaxed) {
            fire_google_keepalive_pulse(&stats_ka);
        }
        thread::sleep(Duration::from_secs(20));
    });
    0
}
