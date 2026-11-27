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
import android.webkit.JavascriptInterface
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class MainActivity : Activity() {

    private lateinit var webView: WebView

    @SuppressLint("SetJavaScriptEnabled", "BatteryLife")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.parseColor("#06080E")
        window.navigationBarColor = Color.parseColor("#090D16")

        requestBatteryExemptionIfNeeded()

        // Request Android VPN permission and immediately start VpnService (shows [VPN] icon in top bar!)
        ensureVpnPermissionAndStart()

        webView = WebView(this)
        webView.setBackgroundColor(Color.parseColor("#06080E"))
        val settings: WebSettings = webView.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.cacheMode = WebSettings.LOAD_NO_CACHE
        webView.webViewClient = WebViewClient()

        webView.addJavascriptInterface(OtaBridge(), "DragonNativeOTA")

        setContentView(webView)

        webView.postDelayed({
            webView.loadUrl("http://127.0.0.1:9091")
            pullSilentOtaFromGithub(false)
        }, 350)
    }

    private fun ensureVpnPermissionAndStart() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, 100)
        } else {
            sendVpnServiceAction(VortexVpnService.ACTION_START)
        }
    }

    inner class OtaBridge {
        @JavascriptInterface
        fun triggerHotUpdate() {
            pullSilentOtaFromGithub(true)
        }

        @JavascriptInterface
        fun setVpnTunnelState(enable: Boolean) {
            runOnUiThread {
                if (enable) {
                    ensureVpnPermissionAndStart()
                } else {
                    sendVpnServiceAction(VortexVpnService.ACTION_STOP)
                }
            }
        }
    }

    private fun pullSilentOtaFromGithub(forceReload: Boolean) {
        thread {
            try {
                val url = URL("https://raw.githubusercontent.com/SirusInsano/vortex-tunnel-pro/main/public/index.html?t=${System.currentTimeMillis()}")
                val conn = url.openConnection() as HttpURLConnection
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                if (conn.responseCode == 200) {
                    val html = conn.inputStream.bufferedReader().use { it.readText() }
                    if (html.contains("DRAGON VORTEX")) {
                        val postUrl = URL("http://127.0.0.1:9091/api/ota/hotpatch")
                        val postConn = postUrl.openConnection() as HttpURLConnection
                        postConn.requestMethod = "POST"
                        postConn.doOutput = true
                        postConn.outputStream.use { it.write(html.toByteArray(Charsets.UTF_8)) }
                        postConn.responseCode

                        if (forceReload) {
                            runOnUiThread {
                                webView.reload()
                            }
                        }
                    }
                }
            } catch (_: Throwable) {
            }
        }
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
        sendVpnServiceAction(VortexVpnService.ACTION_START)
        webView.postDelayed({
            webView.loadUrl("http://127.0.0.1:9091")
        }, 300)
    }

    private fun sendVpnServiceAction(actionStr: String) {
        try {
            val intent = Intent(this, VortexVpnService::class.java).apply {
                action = actionStr
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        } catch (_: Throwable) {
        }
    }
}
