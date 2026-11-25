package com.vortex.tunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Immortal Android Foreground Service + WakeLock + Native Rust Core (`libvortex_core.so`).
 * Protections against Android / HyperOS background killing:
 *  1. Persistent Foreground Service Notification (startForeground) with Ongoing flag
 *  2. PARTIAL_WAKE_LOCK so CPU never suspends the 20s Rust Keep-Alive when screen is locked
 *  3. stopWithTask="false" + onTaskRemoved auto-revive so swiping the app away keeps the tunnel alive
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
        acquireWakeLock()
        promoteToForeground()
        bootRustCoreIfNeeded()
        return START_STICKY
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
                    "VortexPro::RustKeepAliveLock"
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
                    "Vortex Pro • Motor Rust em Segundo Plano",
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = "Mantém o túnel e o segurador de sessão 4.5G/5G ativos sem fechar"
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
                .setContentTitle("Vortex Pro • Conexão Protegida")
                .setContentText("Motor Rust ativo em 2º plano (Segurando 4.5G/5G)")
                .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build()

            startForeground(101, notification)
        } catch (_: Throwable) {
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // If user swipes the app card away from Recents, immediately re-assert foreground service
        val restartIntent = Intent(applicationContext, VortexVpnService::class.java)
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
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        super.onDestroy()
    }

    companion object {
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
