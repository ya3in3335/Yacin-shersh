package com.strykerx.lab.scanner.apk

import android.content.Context
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ProviderInfo
import android.content.pm.ServiceInfo
import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.scanner.web.WebFinding
import java.io.File
import java.util.zip.ZipFile

/** Metadata + findings produced by a static APK analysis. */
data class ApkReport(
    val ok: Boolean,
    val packageName: String,
    val versionName: String,
    val versionCode: Long,
    val minSdk: Int,
    val targetSdk: Int,
    val permissionCount: Int,
    val componentCount: Int,
    val findings: List<WebFinding>,
    val error: String? = null
)

/**
 * Offline, static APK analyzer. It never executes the imported app. The binary
 * AndroidManifest is parsed by the platform PackageManager (the authoritative
 * parser); DEX files are scanned with bounded memory for risky indicators.
 */
object ApkAnalyzer {

    const val MAX_APK_BYTES = 200L * 1024 * 1024       // reject larger uploads
    private const val MAX_DEX_SCAN_BYTES = 25L * 1024 * 1024
    private const val MAX_ENTRIES = 20_000
    private const val MAX_COMPONENT_FINDINGS = 40
    private const val MAX_ENDPOINTS = 200

    private val URL_REGEX = Regex("""https?://[A-Za-z0-9._~:/?#\[\]@!${'$'}&'()*+,;=%-]{3,}""")

    // Permissions worth calling out (classic "dangerous"/powerful set).
    private val SENSITIVE_PERMISSIONS = setOf(
        "android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
        "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_PHONE_STATE", "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.QUERY_ALL_PACKAGES", "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.WRITE_SETTINGS", "android.permission.BIND_ACCESSIBILITY_SERVICE"
    )

    // Security-sensitive API/string indicators to look for in DEX strings.
    private val DEX_INDICATORS = listOf(
        "addJavascriptInterface" to ("Insecure WebView JS bridge (addJavascriptInterface)" to Severity.MEDIUM),
        "setAllowFileAccessFromFileURLs" to ("WebView allows file access from file URLs" to Severity.MEDIUM),
        "setJavaScriptEnabled" to ("WebView JavaScript enabled" to Severity.LOW),
        "MODE_WORLD_READABLE" to ("World-readable file mode" to Severity.MEDIUM),
        "MODE_WORLD_WRITEABLE" to ("World-writable file mode" to Severity.HIGH),
        "ALLOW_ALL_HOSTNAME_VERIFIER" to ("Disabled TLS hostname verification" to Severity.HIGH),
        "TrustAllCerts" to ("Possible trust-all TLS manager" to Severity.HIGH),
        "Runtime.getRuntime().exec" to ("Runtime command execution" to Severity.LOW),
        "DES/" to ("Weak cipher (DES) reference" to Severity.MEDIUM),
        "ECB" to ("ECB cipher mode reference" to Severity.LOW)
    )

    private val SECRET_PATTERNS = listOf(
        "AWS access key" to Regex("AKIA[0-9A-Z]{16}"),
        "Google API key" to Regex("AIza[0-9A-Za-z_\\-]{35}"),
        "Private key block" to Regex("-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
        "Slack token" to Regex("xox[baprs]-[0-9A-Za-z\\-]{10,}")
    )

    @Suppress("DEPRECATION")
    fun analyze(context: Context, apk: File): ApkReport {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or
            PackageManager.GET_PROVIDERS or PackageManager.GET_SIGNING_CERTIFICATES
        val info: PackageInfo = pm.getPackageArchiveInfo(apk.absolutePath, flags)
            ?: return ApkReport(
                ok = false, packageName = "", versionName = "", versionCode = 0,
                minSdk = 0, targetSdk = 0, permissionCount = 0, componentCount = 0,
                findings = emptyList(), error = "Could not parse the APK (malformed or unsupported)."
            )
        val appInfo = info.applicationInfo
        // Ensure component parsing can resolve resources from the archive path.
        appInfo?.apply { sourceDir = apk.absolutePath; publicSourceDir = apk.absolutePath }

        val findings = mutableListOf<WebFinding>()
        val pkg = info.packageName ?: "(unknown)"

        manifestFindings(appInfo, pkg, findings)
        permissionFindings(info, pkg, findings)
        signingFindings(info, pkg, findings)
        val componentCount = componentFindings(info, pkg, findings)
        dexFindings(apk, pkg, findings)

        return ApkReport(
            ok = true,
            packageName = pkg,
            versionName = info.versionName ?: "",
            versionCode = if (android.os.Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong(),
            minSdk = appInfo?.minSdkVersion ?: 0,
            targetSdk = appInfo?.targetSdkVersion ?: 0,
            permissionCount = info.requestedPermissions?.size ?: 0,
            componentCount = componentCount,
            findings = findings
        )
    }

    private fun manifestFindings(appInfo: ApplicationInfo?, pkg: String, out: MutableList<WebFinding>) {
        appInfo ?: return
        val flags = appInfo.flags
        if (flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            out += f("apk-debuggable", "Application is debuggable", pkg,
                "Manifest flag", "android:debuggable=true",
                Severity.HIGH, VerificationStatus.CONFIRMED,
                "Set android:debuggable=false (or omit it) in release builds.")
        }
        if (flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0) {
            out += f("apk-allowbackup", "Backup is allowed (android:allowBackup=true)", pkg,
                "Manifest flag", "FLAG_ALLOW_BACKUP set",
                Severity.LOW, VerificationStatus.CONFIRMED,
                "Set android:allowBackup=false for apps handling sensitive data.")
        }
        if (flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0) {
            out += f("apk-cleartext", "Cleartext (HTTP) traffic permitted", pkg,
                "Manifest flag", "FLAG_USES_CLEARTEXT_TRAFFIC set",
                Severity.MEDIUM, VerificationStatus.CONFIRMED,
                "Disable cleartext traffic and use a Network Security Config that requires TLS.")
        }
    }

    private fun permissionFindings(info: PackageInfo, pkg: String, out: MutableList<WebFinding>) {
        val perms = info.requestedPermissions?.toList() ?: return
        // Full permission inventory as evidence.
        out += f("apk-permissions-all", "Declares ${perms.size} permission(s)", pkg,
            "Manifest permission inventory",
            perms.joinToString(", ") { it.substringAfterLast('.') }.take(1500),
            Severity.INFO, VerificationStatus.INFORMATIONAL,
            "Review the full permission set against what the app actually needs.")

        val sensitive = perms.filter { it in SENSITIVE_PERMISSIONS }
        if (sensitive.isNotEmpty()) {
            out += f("apk-permissions", "Requests ${sensitive.size} sensitive permission(s)", pkg,
                "Manifest permission review", sensitive.joinToString(", "),
                Severity.LOW, VerificationStatus.POTENTIAL,
                "Confirm each powerful permission is actually required and justified.")
        }
    }

    private fun signingFindings(info: PackageInfo, pkg: String, out: MutableList<WebFinding>) {
        val signers = runCatching {
            info.signingInfo?.apkContentsSigners?.toList().orEmpty()
        }.getOrDefault(emptyList())
        if (signers.isEmpty()) return
        val cf = runCatching { java.security.cert.CertificateFactory.getInstance("X.509") }.getOrNull() ?: return
        for (sig in signers) {
            val cert = runCatching {
                cf.generateCertificate(sig.toByteArray().inputStream()) as java.security.cert.X509Certificate
            }.getOrNull() ?: continue
            val subject = cert.subjectDN.name
            val sha256 = sha256Hex(cert.encoded)
            val isDebug = subject.contains("Android Debug", ignoreCase = true)
            out += f(
                "apk-signer", if (isDebug) "Signed with an Android debug certificate" else "Signing certificate",
                pkg, "APK signature inspection",
                "subject=$subject ; SHA-256=$sha256",
                if (isDebug) Severity.MEDIUM else Severity.INFO,
                if (isDebug) VerificationStatus.CONFIRMED else VerificationStatus.INFORMATIONAL,
                if (isDebug) "Debug-signed APKs must not ship to production; re-sign with a release key."
                else "Record the signer fingerprint; verify it matches the expected publisher."
            )
        }
    }

    private fun componentFindings(info: PackageInfo, pkg: String, out: MutableList<WebFinding>): Int {
        val activities: Array<ActivityInfo> = info.activities ?: emptyArray()
        val services: Array<ServiceInfo> = info.services ?: emptyArray()
        val receivers: Array<ActivityInfo> = info.receivers ?: emptyArray()
        val providers: Array<ProviderInfo> = info.providers ?: emptyArray()
        var reported = 0

        fun report(name: String, kind: String, sev: Severity) {
            if (reported >= MAX_COMPONENT_FINDINGS) return
            reported++
            out += f(
                "apk-exported-$name", "Exported $kind without permission: ${name.substringAfterLast('.')}",
                pkg, "Component export analysis", "$name is exported and has no permission guard",
                sev, VerificationStatus.POTENTIAL,
                "Set android:exported=false, or protect it with a signature-level permission."
            )
        }

        for (a in activities) if (a.exported && a.permission == null) report(a.name, "activity", Severity.MEDIUM)
        for (s in services) if (s.exported && s.permission == null) report(s.name, "service", Severity.MEDIUM)
        for (r in receivers) if (r.exported && r.permission == null) report(r.name, "receiver", Severity.MEDIUM)
        for (p in providers) if (p.exported && p.readPermission == null && p.writePermission == null) {
            report(p.name, "provider", Severity.HIGH)
        }
        return activities.size + services.size + receivers.size + providers.size
    }

    private fun dexFindings(apk: File, pkg: String, out: MutableList<WebFinding>) {
        runCatching {
            ZipFile(apk).use { zip ->
                if (zip.size() > MAX_ENTRIES) return
                var scanned = 0L
                val indicatorSnippets = linkedMapOf<String, String>()  // needle -> context
                val secretSnippets = linkedMapOf<String, String>()     // label -> redacted context
                val endpoints = linkedSetOf<String>()                  // discovered server URLs/hosts
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    if (!e.name.endsWith(".dex")) continue
                    if (scanned >= MAX_DEX_SCAN_BYTES) break
                    zip.getInputStream(e).use { ins ->
                        val remaining = (MAX_DEX_SCAN_BYTES - scanned).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                        val bytes = ins.readNBytesCompat(remaining)
                        scanned += bytes.size
                        val text = asciiStrings(bytes)
                        for ((needle, _) in DEX_INDICATORS) {
                            if (!indicatorSnippets.containsKey(needle)) {
                                val idx = text.indexOf(needle)
                                if (idx >= 0) indicatorSnippets[needle] = snippet(text, idx, needle.length)
                            }
                        }
                        for ((label, rx) in SECRET_PATTERNS) {
                            if (!secretSnippets.containsKey(label)) {
                                rx.find(text)?.let { m ->
                                    secretSnippets[label] = m.value.take(10) + "… (redacted)"
                                }
                            }
                        }
                        URL_REGEX.findAll(text).forEach { m ->
                            if (endpoints.size < MAX_ENDPOINTS) endpoints.add(m.value.take(120))
                        }
                    }
                }
                for ((needle, ctx) in indicatorSnippets) {
                    val (title, sev) = DEX_INDICATORS.first { it.first == needle }.second
                    out += f("apk-dex-$needle", "DEX indicator: $title", pkg,
                        "Bounded DEX string scan",
                        "Reference to '$needle' in bytecode. Context: …$ctx…",
                        sev, VerificationStatus.POTENTIAL,
                        "Review this usage; confirm it is safe in context (a string match is not proof of a vulnerability).")
                }
                for ((label, ctx) in secretSnippets) {
                    out += f("apk-dex-secret-$label", "Possible hardcoded secret in DEX: $label", pkg,
                        "Bounded DEX string scan", "Matched $label pattern (redacted sample: $ctx)",
                        Severity.HIGH, VerificationStatus.POTENTIAL,
                        "Remove hardcoded secrets from the app; use secure storage / server-side exchange and rotate if valid.")
                }
                if (endpoints.isNotEmpty()) {
                    val hosts = endpoints.mapNotNull { hostOf(it) }.distinct()
                    out += f("apk-endpoints", "Network endpoints referenced (${endpoints.size})", pkg,
                        "Static DEX URL extraction (no connection made)",
                        "Hosts: " + hosts.take(25).joinToString(", ").take(600) +
                            "\nSample URLs: " + endpoints.take(15).joinToString("  |  ").take(900),
                        Severity.INFO, VerificationStatus.INFORMATIONAL,
                        "These are the servers/URLs the app's code references. Verify each is expected; no request was sent by this scan.")
                    val cleartext = endpoints.filter { it.startsWith("http://") }
                    if (cleartext.isNotEmpty()) {
                        out += f("apk-cleartext-endpoints", "Cleartext (http://) endpoints referenced in code", pkg,
                            "Static DEX URL extraction", cleartext.take(10).joinToString("  |  ").take(600),
                            Severity.MEDIUM, VerificationStatus.POTENTIAL,
                            "Move these endpoints to HTTPS; cleartext traffic can be intercepted.")
                    }
                }
            }
        }
    }

    // --- helpers ---

    private fun asciiStrings(bytes: ByteArray, minRun: Int = 6): String {
        val sb = StringBuilder(bytes.size / 2)
        val run = StringBuilder()
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c in 0x20..0x7E) {
                run.append(c.toChar())
            } else {
                if (run.length >= minRun) { sb.append(run); sb.append('\n') }
                run.setLength(0)
            }
        }
        if (run.length >= minRun) sb.append(run)
        return sb.toString()
    }

    /** A sanitized context window around a match, for human-readable evidence. */
    private fun snippet(text: String, index: Int, len: Int): String {
        val start = (index - 30).coerceAtLeast(0)
        val end = (index + len + 30).coerceAtMost(text.length)
        return text.substring(start, end).replace('\n', ' ').trim()
    }

    private fun hostOf(url: String): String? = runCatching {
        java.net.URI(url).host
    }.getOrNull()

    private fun sha256Hex(bytes: ByteArray): String {
        val d = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
        return d.joinToString(":") { "%02X".format(it) }
    }

    private fun f(
        code: String, title: String, affected: String, method: String, evidence: String,
        sev: Severity, status: VerificationStatus, fix: String
    ) = WebFinding(
        code = code, title = title, affected = affected, detectionMethod = method,
        evidence = evidence, severity = sev, confidence = Confidence.MEDIUM,
        verification = status, reproduction = "Statically inspect the APK ($affected) for this indicator.",
        remediation = fix
    )
}

/** readNBytes is API 33+; this bounded reader works on all supported levels. */
private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
    val buf = java.io.ByteArrayOutputStream()
    val chunk = ByteArray(16 * 1024)
    var total = 0
    while (total < limit) {
        val toRead = minOf(chunk.size, limit - total)
        val n = this.read(chunk, 0, toRead)
        if (n < 0) break
        buf.write(chunk, 0, n)
        total += n
    }
    return buf.toByteArray()
}
