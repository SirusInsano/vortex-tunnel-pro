package com.vortex.tunnel

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Native Android VpnService linked directly to our compiled Rust library (`libvortex_core.so`).
 */
class VortexVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!rustInitialized.getAndSet(true)) {
            try {
                // Boots the embedded Rust Split-TLS + SOCKS5 (:10809) + HTTP Hotshare (:8081) + WebUI (:9091) + Keep-Alive
                startRustEngine(10809, 8081, 9091)
            } catch (_: Throwable) {
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
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
