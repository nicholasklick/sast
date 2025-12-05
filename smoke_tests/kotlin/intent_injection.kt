// Android Intent Injection vulnerabilities in Kotlin
package com.example.security

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle

class IntentInjectionVulnerabilities {

    // Test 1: Unvalidated intent extra
    fun handleIntent(intent: Intent) {
        // VULNERABLE: Using extra without validation
        val url = intent.getStringExtra("url")
        if (url != null) {
            openWebPage(url)
        }
    }

    // Test 2: Intent data URL
    fun processIntentData(intent: Intent) {
        val data = intent.data
        // VULNERABLE: Processing arbitrary URI
        if (data != null) {
            loadContent(data.toString())
        }
    }

    // Test 3: Implicit intent with user data
    fun shareContent(context: Context, userContent: String) {
        // VULNERABLE: User data in implicit intent
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, userContent)
        }
        context.startActivity(intent)
    }

    // Test 4: File access via intent
    fun openFile(context: Context, filePath: String) {
        // VULNERABLE: Arbitrary file access
        val intent = Intent(Intent.ACTION_VIEW).apply {
            data = Uri.parse("file://$filePath")
        }
        context.startActivity(intent)
    }

    // Test 5: Deep link handling
    fun handleDeepLink(intent: Intent) {
        val uri = intent.data
        // VULNERABLE: No validation of deep link target
        if (uri?.scheme == "myapp") {
            val target = uri.getQueryParameter("target")
            navigateTo(target)
        }
    }

    // Test 6: Exported activity without permission
    fun startExportedActivity(context: Context, className: String) {
        // VULNERABLE: Starting activity by class name from user
        val intent = Intent()
        intent.setClassName(context, className)
        context.startActivity(intent)
    }

    // Test 7: Pending intent manipulation
    fun createPendingIntent(context: Context, action: String): android.app.PendingIntent {
        // VULNERABLE: Action from user
        val intent = Intent(action)
        return android.app.PendingIntent.getActivity(context, 0, intent, 0)
    }

    // Test 8: Broadcast with user data
    fun sendBroadcast(context: Context, action: String, data: String) {
        // VULNERABLE: User-controlled broadcast
        val intent = Intent(action).apply {
            putExtra("data", data)
        }
        context.sendBroadcast(intent)
    }

    // Test 9: Service start with user data
    fun startService(context: Context, serviceName: String, params: Bundle) {
        // VULNERABLE: Service and params from user
        val intent = Intent().apply {
            setClassName(context, serviceName)
            putExtras(params)
        }
        context.startService(intent)
    }

    // Test 10: Content provider access
    fun queryContent(context: Context, uriString: String): Any? {
        // VULNERABLE: Arbitrary content provider access
        val uri = Uri.parse(uriString)
        return context.contentResolver.query(uri, null, null, null, null)
    }

    // Test 11: Intent redirection
    fun redirectIntent(context: Context, intent: Intent) {
        val targetIntent = intent.getParcelableExtra<Intent>("target")
        // VULNERABLE: Forwarding user-provided intent
        if (targetIntent != null) {
            context.startActivity(targetIntent)
        }
    }

    // Test 12: Custom scheme handler
    fun handleCustomScheme(uri: Uri) {
        val command = uri.host
        val args = uri.pathSegments
        // VULNERABLE: Executing commands from URI
        executeCommand(command, args)
    }

    // Test 13: WebView intent handling
    fun handleWebViewIntent(context: Context, url: String) {
        // VULNERABLE: Loading arbitrary URL
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        context.startActivity(intent)
    }

    private fun openWebPage(url: String) {}
    private fun loadContent(content: String) {}
    private fun navigateTo(target: String?) {}
    private fun executeCommand(command: String?, args: List<String>) {}
}
