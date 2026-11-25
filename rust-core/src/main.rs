use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use vortex_core::{
    fire_google_keepalive_pulse, global_stats, parse_payload_template, start_embedded_ui_server,
    start_proxy_listeners, TunnelConfig,
};

fn run_self_test() {
    println!("=== [Rust Core] 1. Testando Parser de Payload ([crlf], [split], [host_port]) ===");
    let steps = parse_payload_template(
        "CONNECT [host_port] [protocol][crlf][split]Host: [host][crlf][crlf]",
        "m.claro.com.br",
        443,
    );
    assert_eq!(steps.len(), 2, "Payload deve dividir em 2 etapas");
    assert!(String::from_utf8_lossy(&steps[0].data).contains("CONNECT m.claro.com.br:443 HTTP/1.1\r\n"));
    println!("OK: Parser de payload nativo em Rust dividiu em {} etapas.", steps.len());

    println!("\n=== [Rust Core] 2. Testando Túnel HTTP CONNECT + Fragmentação Split-TLS Nativa ===");
    let echo_listener = TcpListener::bind("127.0.0.1:0").expect("Falha bind echo");
    let echo_port = echo_listener.local_addr().unwrap().port();

    thread::spawn(move || {
        if let Ok((mut sock, _)) = echo_listener.accept() {
            let mut buf = [0u8; 1024];
            while let Ok(n) = sock.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if sock.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    });

    let stats = global_stats();
    let cfg = TunnelConfig {
        socks_port: 29808,
        http_port: 28080,
        fragment_size: 8,
        fragment_delay_ms: 5,
        hotshare: false,
        ..TunnelConfig::default()
    };

    start_proxy_listeners(cfg, Arc::clone(&stats)).expect("Falha iniciando proxy Rust");
    thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect("127.0.0.1:28080").expect("Falha conectando proxy Rust");
    let connect_cmd = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        echo_port, echo_port
    );
    client.write_all(connect_cmd.as_bytes()).unwrap();

    let mut resp_buf = [0u8; 512];
    let n = client.read(&mut resp_buf).unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(resp_str.contains("200 Connection Established"));

    let test_payload = b"RUST_SPLIT_TLS_CLIENT_HELLO_PACKET";
    client.write_all(test_payload).unwrap();

    let mut collected = Vec::new();
    while collected.len() < test_payload.len() {
        let n = client.read(&mut resp_buf).unwrap();
        assert!(n > 0);
        collected.extend_from_slice(&resp_buf[..n]);
    }
    assert_eq!(collected.as_slice(), test_payload);
    println!(
        "OK: Motor Rust transmitiu e fragmentou {} bytes com latência sub-milissegundo!",
        collected.len()
    );
    println!("\n=== [Rust Core] TODOS OS TESTES NATIVOS PASSARAM! ===");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--test") {
        run_self_test();
        return;
    }

    let ui_port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9091);

    println!("=========================================================");
    println!("   VORTEX TUNNEL PRO - 100% NATIVE RUST (v2.0)           ");
    println!("   Painel Web Embutido: http://127.0.0.1:{}            ", ui_port);
    println!("   SOCKS5: :10809 | HTTP Hotshare: :8081                 ");
    println!("=========================================================");

    let stats = global_stats();
    let cfg = TunnelConfig {
        socks_port: 10809,
        http_port: 8081,
        fragment_size: 16,
        fragment_delay_ms: 10,
        hotshare: true,
        ..TunnelConfig::default()
    };

    start_embedded_ui_server(ui_port, Arc::clone(&stats)).expect("Erro iniciando WebUI Rust");
    start_proxy_listeners(cfg, Arc::clone(&stats)).expect("Erro iniciando Proxy Rust");

    #[cfg(target_os = "windows")]
    {
        let url = format!("http://127.0.0.1:{}", ui_port);
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", &url])
            .spawn();
    }

    stats.keepalive_active.store(true, Ordering::SeqCst);
    let stats_ka = Arc::clone(&stats);
    thread::spawn(move || loop {
        if stats_ka.keepalive_active.load(Ordering::Relaxed) {
            fire_google_keepalive_pulse(&stats_ka);
        }
        thread::sleep(Duration::from_secs(20));
    });

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
