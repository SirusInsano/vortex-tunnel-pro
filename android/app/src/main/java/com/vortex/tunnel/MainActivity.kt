package com.vortex.tunnel

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient

/**
 * Fullscreen Android Native Activity powered by the embedded Rust Core (`libvortex_core.so`).
 * 1. Requests Android VPN Service permission and starts `VortexVpnService` (which boots the Rust engine on 127.0.0.1:9091)
 * 2. Renders the embedded Rust WebUI at http://127.0.0.1:9091 with zero external runtime dependencies.
 */
class MainActivity : Activity() {

    private lateinit var webView: WebView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.parseColor("#07090F")
        window.navigationBarColor = Color.parseColor("#0A0E17")

        // Ensure Rust engine & VpnService are started
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, 100)
        } else {
            startVortexService()
        }

        webView = WebView(this)
        webView.setBackgroundColor(Color.parseColor("#07090F"))
        val settings: WebSettings = webView.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        webView.webViewClient = WebViewClient()
        setContentView(webView)

        webView.postDelayed({
            webView.loadUrl("http://127.0.0.1:9091")
        }, 400)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        startVortexService()
        webView.postDelayed({
            webView.loadUrl("http://127.0.0.1:9091")
        }, 400)
    }

    private fun startVortexService() {
        val intent = Intent(this, VortexVpnService::class.java)
        startService(intent)
    }
}
