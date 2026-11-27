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
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Immortal Android VpnService + Foreground Notification + WakeLock + Native Rust Core (`libvortex_core.so`).
 * - Calls `Builder().establish()` so Android activates the `[VPN]` icon in the status bar
 * - Injects `ProxyInfo.buildDirectProxy("127.0.0.1", 8081)` into the Android VPN bearer so system apps
 *   automatically route through the Rust Mid-SNI Split-TLS & Payload engine on 127.0.0.1:8081
 * - Excludes DragonVortex itself (`addDisallowedApplication(packageName)`) so Rust sockets go straight
 *   out the 4.5G/5G cellular interface (`rmnet_data0`) without routing loops.
 */
class VortexVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        acquireWakeLock()
        promoteToForeground()
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
                .addAddress("10.0.0.2", 32)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")

            // Route system traffic through our local Rust Split-TLS & Payload proxy on 127.0.0.1:8081
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", 8081))
            }

            // Exclude our own package so the Rust engine talks directly to the 4.5G/5G radio antenna
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
                .setContentTitle("DragonVortex • VPN Ativa")
                .setContentText("Motor Rust + Split-TLS ativo em 2º plano (4.5G/5G)")
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
