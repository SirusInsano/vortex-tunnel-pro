package com.vortex.tunnel

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient

class MainActivity : Activity() {

    private lateinit var webView: WebView

    @SuppressLint("SetJavaScriptEnabled", "BatteryLife")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.parseColor("#06080E")
        window.navigationBarColor = Color.parseColor("#090D16")

        // 1. Request exemption from Android / Xiaomi HyperOS Battery Killer so app never closes
        requestBatteryExemptionIfNeeded()

        // 2. Start Foreground Rust Service immediately
        startVortexService()

        // 3. Also prepare VPN permission if user activates system-wide TUN
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, 100)
        }

        webView = WebView(this)
        webView.setBackgroundColor(Color.parseColor("#06080E"))
        val settings: WebSettings = webView.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        webView.webViewClient = WebViewClient()

        // Handle 1-click In-App APK Auto-Update downloads cleanly via Android system installer
        webView.setDownloadListener { url, _, _, _, _ ->
            try {
                val dlIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                startActivity(dlIntent)
            } catch (_: Throwable) {
            }
        }

        setContentView(webView)

        webView.postDelayed({
            webView.loadUrl("http://127.0.0.1:9091")
        }, 350)
    }

    @SuppressLint("BatteryLife")
    private fun requestBatteryExemptionIfNeeded() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                    val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                        data = Uri.parse("package:$packageName")
                    }
                    startActivity(intent)
                }
            }
        } catch (_: Throwable) {
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        startVortexService()
        webView.postDelayed({
            webView.loadUrl("http://127.0.0.1:9091")
        }, 300)
    }

    private fun startVortexService() {
        try {
            val intent = Intent(this, VortexVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        } catch (_: Throwable) {
        }
    }
}
