package com.vortex.tunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.concurrent.thread

/**
 * DragonVortex v2.8 — Immortal VpnService + Raw-IP 1.1.1.1:443 DoH DNS Bypass + Rust Split-TLS Core.
 *
 * Key breakthrough from Claro 4.5G audit:
 * - Claro blocks UDP/TCP Port 53 DNS (8.8.8.8:53 timeouts at 2504ms),
 *   WHILE raw IP TCP Port 443 (`1.1.1.1:443` = 147ms, `claroflex.com.br:443` = 42ms, `mhnet.com.br:443` = 149ms) is OPEN!
 * - This service runs a local DNS-over-HTTPS (DoH) bridge on 127.0.0.1:9092 that connects directly
 *   to the raw IP `1.1.1.1:443` (and `1.0.0.1:443`) without using Port 53 DNS at all, resolving any domain
 *   for the Rust Split-TLS proxy!
 */
class VortexVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        acquireWakeLock()
        promoteToForeground()
        startRawIpDohBridgeIfNeeded()
        bootRustCoreIfNeeded()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        if (action == ACTION_STOP) {
            teardownVpnInterface()
            return START_STICKY
        }

        acquireWakeLock()
        promoteToForeground()
        startRawIpDohBridgeIfNeeded()
        bootRustCoreIfNeeded()
        establishVpnInterface()
        return START_STICKY
    }

    private fun establishVpnInterface() {
        if (vpnInterface != null) return
        try {
            val builder = Builder()
                .setSession("DragonVortex")
                .setMtu(1500)
                .addAddress("10.88.0.2", 24)
                // Critical: Android requires at least one route on tun0 to display the [VPN] status bar icon
                // and bind ProxyInfo to the active network! We route only the virtual 10.88.0.0/16 subnet
                // into tun0 while global HTTP/HTTPS traffic is redirected into our Rust proxy 127.0.0.1:8081.
                .addRoute("10.88.0.0", 16)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", 8081))
            }

            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: Throwable) {
            }

            vpnInterface = builder.establish()
        } catch (_: Throwable) {
        }
    }

    private fun teardownVpnInterface() {
        try {
            vpnInterface?.close()
        } catch (_: Throwable) {
        }
        vpnInterface = null
    }

    /**
     * Resolves a domain name over raw IP `1.1.1.1:443` (Cloudflare DoH JSON API)
     * completely bypassing Claro's blocked Port 53 DNS!
     */
    private fun resolveDomainOver1111Port443(domain: String): String? {
        val clean = domain.trim().lowercase()
        dnsCache[clean]?.let { return it }

        val rawDohIps = arrayOf("1.1.1.1", "1.0.0.1")
        for (dohIp in rawDohIps) {
            var sslSock: SSLSocket? = null
            try {
                val rawSock = Socket()
                protect(rawSock)
                rawSock.tcpNoDelay = true
                rawSock.connect(InetSocketAddress(dohIp, 443), 3500)
                rawSock.soTimeout = 3500

                val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                sslSock = factory.createSocket(rawSock, "cloudflare-dns.com", 443, true) as SSLSocket
                val params = SSLParameters()
                params.serverNames = listOf(SNIHostName("cloudflare-dns.com"))
                sslSock.sslParameters = params
                sslSock.startHandshake()

                val req = "GET /dns-query?name=$clean&type=A HTTP/1.1\r\n" +
                        "Host: cloudflare-dns.com\r\n" +
                        "Accept: application/dns-json\r\n" +
                        "Connection: close\r\n\r\n"
                sslSock.outputStream.write(req.toByteArray(Charsets.US_ASCII))
                sslSock.outputStream.flush()

                val resp = BufferedReader(InputStreamReader(sslSock.inputStream, Charsets.UTF_8)).readText()
                val jsonStart = resp.indexOf('{')
                if (jsonStart >= 0) {
                    val json = JSONObject(resp.substring(jsonStart))
                    val answers = json.optJSONArray("Answer")
                    if (answers != null) {
                        for (i in 0 until answers.length()) {
                            val ans = answers.getJSONObject(i)
                            if (ans.optInt("type") == 1) {
                                val ip = ans.optString("data", "")
                                if (ip.isNotEmpty()) {
                                    dnsCache[clean] = ip
                                    return ip
                                }
                            }
                        }
                    }
                }
            } catch (_: Throwable) {
            } finally {
                try { sslSock?.close() } catch (_: Throwable) {}
            }
        }
        return null
    }

    private fun startRawIpDohBridgeIfNeeded() {
        if (dohBridgeStarted.getAndSet(true)) return
        // Pre-seed critical hosts so they resolve in 0ms
        dnsCache["1.1.1.1"] = "1.1.1.1"
        dnsCache["mhnet.com.br"] = "170.247.195.132"

        thread(name = "DragonDohBridge") {
            try {
                val server = ServerSocket()
                server.reuseAddress = true
                server.bind(InetSocketAddress("127.0.0.1", 9092))
                while (true) {
                    val client = server.accept()
                    thread {
                        try {
                            client.soTimeout = 4000
                            val reader = BufferedReader(InputStreamReader(client.getInputStream()))
                            val line = reader.readLine() ?: ""
                            // Expected: GET /resolve?host=example.com HTTP/1.1
                            val hostParam = line.substringAfter("host=", "").substringBefore(" ").substringBefore("&").trim()
                            val resolvedIp = if (hostParam.isNotEmpty()) {
                                resolveDomainOver1111Port443(hostParam) ?: ""
                            } else ""

                            val body = resolvedIp.toByteArray(Charsets.UTF_8)
                            val hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n"
                            client.getOutputStream().write(hdr.toByteArray(Charsets.US_ASCII))
                            client.getOutputStream().write(body)
                            client.getOutputStream().flush()
                        } catch (_: Throwable) {
                        } finally {
                            try { client.close() } catch (_: Throwable) {}
                        }
                    }
                }
            } catch (_: Throwable) {
            }
        }
    }

    private fun bootRustCoreIfNeeded() {
        if (!rustInitialized.getAndSet(true)) {
            try {
                startRustEngine(10809, 8081, 9091)
            } catch (_: Throwable) {
            }
        }
    }

    private fun acquireWakeLock() {
        try {
            if (wakeLock == null) {
                val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                wakeLock = pm.newWakeLock(
                    PowerManager.PARTIAL_WAKE_LOCK,
                    "DragonVortex::RustKeepAliveLock"
                ).apply {
                    setReferenceCounted(false)
                    acquire()
                }
            } else if (wakeLock?.isHeld == false) {
                wakeLock?.acquire()
            }
        } catch (_: Throwable) {
        }
    }

    private fun promoteToForeground() {
        try {
            val channelId = "vortex_rust_permanent_channel"
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    channelId,
                    "DragonVortex • Motor Rust em Segundo Plano",
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = "Mantém o túnel VPN e o segurador de sessão 4.5G/5G ativos"
                    setShowBadge(false)
                }
                nm.createNotificationChannel(channel)
            }

            val openIntent = Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            val pendingFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            } else {
                PendingIntent.FLAG_UPDATE_CURRENT
            }
            val pendingIntent = PendingIntent.getActivity(this, 0, openIntent, pendingFlags)

            val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(this, channelId)
            } else {
                @Suppress("DEPRECATION")
                Notification.Builder(this)
            }

            val notification = builder
                .setContentTitle("DragonVortex • VPN + DoH 443 Ativo")
                .setContentText("Bypass DNS 1.1.1.1:443 + Split-TLS ativo em 2º plano")
                .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build()

            startForeground(101, notification)
        } catch (_: Throwable) {
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        val restartIntent = Intent(applicationContext, VortexVpnService::class.java).apply {
            action = ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            applicationContext.startForegroundService(restartIntent)
        } else {
            applicationContext.startService(restartIntent)
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
            }
        } catch (_: Throwable) {
        }
        teardownVpnInterface()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "com.vortex.tunnel.START"
        const val ACTION_STOP = "com.vortex.tunnel.STOP"
        private val rustInitialized = AtomicBoolean(false)
        private val dohBridgeStarted = AtomicBoolean(false)
        private val dnsCache = ConcurrentHashMap<String, String>()

        init {
            try {
                System.loadLibrary("vortex_core")
            } catch (_: Throwable) {
            }
        }

        @JvmStatic
        external fun startRustEngine(socksPort: Int, httpPort: Int, uiPort: Int): Int
    }
}
