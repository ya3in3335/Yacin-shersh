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
    val components: List<DetectedComponent> = emptyList(),
    val error: String? = null
)

/**
 * A third-party library detected inside the APK. Fed to the online CVE lookup
 * (OSV.dev) so the report can flag components with known vulnerabilities.
 */
data class DetectedComponent(
    val name: String,         // human label, e.g. "OkHttp"
    val coordinate: String,   // OSV Maven coordinate "group:artifact"
    val version: String?      // extracted version, or null if unknown
)

/**
 * Offline, static APK analyzer. It never executes the imported app. The binary
 * AndroidManifest is parsed by the platform PackageManager (the authoritative
 * parser); DEX files are scanned with bounded memory for risky indicators.
 */
object ApkAnalyzer {

    const val MAX_APK_BYTES = 200L * 1024 * 1024       // reject larger uploads
    private const val MAX_DEX_SCAN_BYTES = 64L * 1024 * 1024   // scan all DEX up to this budget
    private const val MAX_ENTRIES = 40_000
    private const val MAX_COMPONENT_FINDINGS = 40
    private const val MAX_ENDPOINTS = 300
    private const val MAX_COMPONENTS = 60

    // Full-archive ("unpack the files") analysis budgets.
    private const val MAX_RES_FILE_BYTES = 2L * 1024 * 1024
    private const val MAX_RES_TOTAL_BYTES = 48L * 1024 * 1024
    private const val MAX_RES_FILES = 4000
    private const val MAX_SO_SCAN_BYTES = 4L * 1024 * 1024

    // Text-like packaged files we read and scan for secrets/endpoints.
    private val TEXT_EXT = setOf(
        "json", "xml", "txt", "properties", "js", "html", "htm", "css", "yaml", "yml",
        "cfg", "conf", "ini", "env", "pem", "key", "sql", "csv", "md", "map", "graphql", "proto", "plist"
    )

    // Known commercial packers/protectors, keyed by a native-lib name fragment.
    private val PACKER_LIBS = linkedMapOf(
        "libjiagu" to "Qihoo 360 Jiagu",
        "libsecexe" to "Bangcle / SecNeo",
        "libsecmain" to "Bangcle / SecNeo",
        "libSecShell" to "Bangcle",
        "libDexHelper" to "SecNeo / APKProtect",
        "libprotectClass" to "Baidu protect",
        "libnqshield" to "NetQin shield",
        "libtup" to "Tencent",
        "libtersafe" to "Tencent",
        "libshella" to "Tencent Legu",
        "libshellx" to "Tencent Legu",
        "libexec" to "Ijiami",
        "libexecmain" to "Ijiami",
        "libddog" to "Ijiami",
        "libmobisec" to "Alibaba"
    )

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

    /**
     * Security-sensitive API/string indicators. Each is a concrete, high-value
     * vulnerability class a reviewer would actually report — CWE-tagged, with the
     * remediation that closes it. Severity reflects real impact, not just presence.
     */
    private data class Indicator(
        val needle: String, val title: String, val severity: Severity,
        val cwe: String, val fix: String
    )

    private val DEX_INDICATORS = listOf(
        // --- WebView / remote-code surface ---
        Indicator("addJavascriptInterface", "Insecure WebView JavaScript bridge", Severity.HIGH,
            "CWE-749", "Remove addJavascriptInterface for untrusted content, or gate it to API 17+ with @JavascriptInterface on explicit methods only."),
        Indicator("setAllowUniversalAccessFromFileURLs", "WebView grants universal access from file URLs", Severity.HIGH,
            "CWE-200", "Call setAllowUniversalAccessFromFileURLs(false); never load untrusted content with it enabled."),
        Indicator("setAllowFileAccessFromFileURLs", "WebView allows file access from file URLs", Severity.MEDIUM,
            "CWE-200", "Disable file-from-file URL access; isolate local HTML from remote content."),
        Indicator("setWebContentsDebuggingEnabled", "WebView remote debugging enabled", Severity.MEDIUM,
            "CWE-489", "Guard setWebContentsDebuggingEnabled(true) behind BuildConfig.DEBUG only."),
        Indicator("setAllowFileAccess", "WebView file access enabled", Severity.LOW,
            "CWE-200", "Set setAllowFileAccess(false) unless the app must load local files."),
        Indicator("setJavaScriptEnabled", "WebView JavaScript enabled", Severity.LOW,
            "CWE-79", "Only enable JavaScript for trusted origins; validate all loaded URLs."),
        Indicator("onReceivedSslError", "WebView may override SSL error handling", Severity.HIGH,
            "CWE-295", "Never call handler.proceed() on SSL errors; call handler.cancel()."),
        // --- TLS / transport ---
        Indicator("ALLOW_ALL_HOSTNAME_VERIFIER", "Disabled TLS hostname verification", Severity.HIGH,
            "CWE-295", "Use the default hostname verifier; a MITM can impersonate any host otherwise."),
        Indicator("AllowAllHostnameVerifier", "Disabled TLS hostname verification", Severity.HIGH,
            "CWE-295", "Use the default hostname verifier; a MITM can impersonate any host otherwise."),
        Indicator("TrustAllCerts", "Trust-all TLS certificate manager", Severity.HIGH,
            "CWE-295", "Remove the trust-all X509TrustManager; rely on the system trust store (optionally pin)."),
        Indicator("checkClientTrusted", "Custom TrustManager (verify it validates certs)", Severity.MEDIUM,
            "CWE-295", "Ensure checkServerTrusted/checkClientTrusted actually validate the chain and throw on failure."),
        Indicator("SSLSocketFactory", "Custom SSLSocketFactory (verify trust config)", Severity.LOW,
            "CWE-295", "Confirm the socket factory uses a validating trust manager and hostname verifier."),
        // --- Weak / misused cryptography ---
        Indicator("AES/ECB", "AES in ECB mode (no semantic security)", Severity.MEDIUM,
            "CWE-327", "Use AES/GCM/NoPadding (or AES/CBC with a random IV + HMAC); never ECB."),
        Indicator("DES/", "Weak cipher (DES)", Severity.MEDIUM,
            "CWE-327", "Replace DES/3DES with AES-GCM."),
        Indicator("DESede", "Weak cipher (3DES)", Severity.MEDIUM,
            "CWE-327", "Replace 3DES with AES-GCM."),
        Indicator("RC4", "Weak stream cipher (RC4)", Severity.MEDIUM,
            "CWE-327", "Replace RC4 with AES-GCM."),
        Indicator("MD5", "Weak hash (MD5)", Severity.LOW,
            "CWE-328", "Use SHA-256+ for integrity; never MD5 for security."),
        Indicator("getInstance(\"SHA1\")", "Weak hash (SHA-1)", Severity.LOW,
            "CWE-328", "Use SHA-256 or stronger."),
        Indicator("SecretKeySpec", "Possible hardcoded symmetric key (SecretKeySpec)", Severity.HIGH,
            "CWE-321", "Never embed keys in the APK; derive per-device keys in the Android Keystore."),
        Indicator("PBEKeySpec", "Password-based key derivation (check iterations/salt)", Severity.LOW,
            "CWE-916", "Use a random per-user salt and high iteration count (PBKDF2 ≥ 120k, or Argon2)."),
        // --- Local storage exposure ---
        Indicator("MODE_WORLD_READABLE", "World-readable file/preferences mode", Severity.MEDIUM,
            "CWE-732", "Use MODE_PRIVATE; other apps can read world-readable data."),
        Indicator("MODE_WORLD_WRITEABLE", "World-writable file/preferences mode", Severity.HIGH,
            "CWE-732", "Use MODE_PRIVATE; world-writable data can be tampered with by any app."),
        Indicator("getExternalStorageDirectory", "Sensitive data may be on shared external storage", Severity.LOW,
            "CWE-312", "Keep sensitive files in app-private internal storage, not external/shared storage."),
        // --- Injection surfaces ---
        Indicator("rawQuery", "Raw SQL query (check for string concatenation → SQLi)", Severity.MEDIUM,
            "CWE-89", "Use parameterized queries (selectionArgs); never concatenate user input into SQL."),
        Indicator("execSQL", "Direct SQL execution (check for concatenation → SQLi)", Severity.MEDIUM,
            "CWE-89", "Use parameterized statements; never build SQL from untrusted strings."),
        // --- Code execution / dynamic loading ---
        Indicator("DexClassLoader", "Dynamic DEX/code loading", Severity.MEDIUM,
            "CWE-494", "Avoid loading external code; if unavoidable, verify a signature before loading."),
        Indicator("PathClassLoader", "Runtime class loading (verify source integrity)", Severity.LOW,
            "CWE-494", "Only load code shipped and verified inside the APK."),
        Indicator("Runtime.getRuntime().exec", "Runtime command execution", Severity.MEDIUM,
            "CWE-78", "Avoid shell execution; if required, never pass untrusted input and use absolute paths."),
        Indicator("ProcessBuilder", "Process execution (ProcessBuilder)", Severity.LOW,
            "CWE-78", "Avoid spawning processes with untrusted arguments."),
        // --- Intent / component safety ---
        Indicator("FLAG_MUTABLE", "Mutable PendingIntent (verify intent is fully specified)", Severity.MEDIUM,
            "CWE-927", "Use FLAG_IMMUTABLE unless mutability is required; always set an explicit component."),
        Indicator("setComponent", "Implicit→explicit intent handling (verify no redirection)", Severity.LOW,
            "CWE-926", "Validate the target of any intent built from external input to prevent redirection."),
        // --- Logging of secrets ---
        Indicator("Log.d", "Debug logging present (verify no secrets are logged)", Severity.LOW,
            "CWE-532", "Strip debug logs in release (ProGuard/R8) and never log tokens, PII, or keys.")
    )

    /**
     * High-value secret patterns. Hardcoded credentials in an APK are the classic
     * "profitable" finding — anyone can unzip the APK and read them.
     */
    private val SECRET_PATTERNS = listOf(
        "AWS access key" to Regex("AKIA[0-9A-Z]{16}"),
        "AWS secret key (candidate)" to Regex("(?i)aws(.{0,20})?(secret|private).{0,3}['\"=:\\s]([0-9a-zA-Z/+]{40})"),
        "Google API key" to Regex("AIza[0-9A-Za-z_\\-]{35}"),
        "Google OAuth client secret" to Regex("GOCSPX-[0-9A-Za-z_\\-]{20,}"),
        "Firebase database URL" to Regex("https://[a-z0-9.-]+\\.firebaseio\\.com"),
        "Firebase Cloud Messaging / FCM server key" to Regex("AAAA[A-Za-z0-9_\\-]{7}:[A-Za-z0-9_\\-]{140,}"),
        "Stripe live secret key" to Regex("sk_live_[0-9a-zA-Z]{24,}"),
        "Stripe live publishable key" to Regex("pk_live_[0-9a-zA-Z]{24,}"),
        "Twilio API key" to Regex("SK[0-9a-fA-F]{32}"),
        "SendGrid API key" to Regex("SG\\.[0-9A-Za-z_\\-]{22}\\.[0-9A-Za-z_\\-]{43}"),
        "Mailgun key" to Regex("key-[0-9a-zA-Z]{32}"),
        "GitHub token" to Regex("gh[pousr]_[0-9A-Za-z]{36}"),
        "Slack token" to Regex("xox[baprs]-[0-9A-Za-z\\-]{10,}"),
        "JSON Web Token (JWT)" to Regex("eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"),
        "Private key block" to Regex("-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "Generic hardcoded password" to Regex("(?i)(password|passwd|pwd)\\s*[=:]\\s*[\"'][^\"']{4,}[\"']"),
        "Generic hardcoded API key/secret" to Regex("(?i)(api[_-]?key|secret|token|auth)\\s*[=:]\\s*[\"'][0-9A-Za-z_\\-]{12,}[\"']")
    )

    /**
     * Third-party libraries we can recognize from DEX type descriptors, mapped to
     * their OSV Maven coordinate for an online CVE lookup. A version regex is used
     * when the library embeds its version as a readable string (best-effort).
     */
    private data class ComponentSig(
        val marker: String, val name: String, val coordinate: String, val versionRegex: Regex? = null
    )

    private val COMPONENT_SIGNATURES = listOf(
        ComponentSig("okhttp3/OkHttpClient", "OkHttp", "com.squareup.okhttp3:okhttp",
            Regex("""okhttp/(\d+\.\d+\.\d+)""")),
        ComponentSig("okio/BufferedSource", "Okio", "com.squareup.okio:okio"),
        ComponentSig("retrofit2/Retrofit", "Retrofit", "com.squareup.retrofit2:retrofit"),
        ComponentSig("com/google/gson/Gson", "Gson", "com.google.code.gson:gson"),
        ComponentSig("com/fasterxml/jackson/databind/ObjectMapper", "Jackson Databind",
            "com.fasterxml.jackson.core:jackson-databind"),
        ComponentSig("org/bouncycastle/jce/provider/BouncyCastleProvider", "Bouncy Castle",
            "org.bouncycastle:bcprov-jdk15on"),
        ComponentSig("org/apache/commons/collections4", "Apache Commons Collections 4",
            "org.apache.commons:commons-collections4"),
        ComponentSig("org/apache/commons/collections/", "Apache Commons Collections",
            "commons-collections:commons-collections"),
        ComponentSig("com/bumptech/glide/Glide", "Glide", "com.github.bumptech.glide:glide"),
        ComponentSig("com/squareup/picasso/Picasso", "Picasso", "com.squareup.picasso:picasso"),
        ComponentSig("io/netty/channel/Channel", "Netty", "io.netty:netty-all"),
        ComponentSig("org/apache/cordova/CordovaActivity", "Apache Cordova", "org.apache.cordova:framework"),
        ComponentSig("net/sqlcipher/database/SQLiteDatabase", "SQLCipher", "net.zetetic:android-database-sqlcipher"),
        ComponentSig("com/google/android/exoplayer2/ExoPlayer", "ExoPlayer",
            "com.google.android.exoplayer:exoplayer"),
        ComponentSig("org/jsoup/Jsoup", "jsoup", "org.jsoup:jsoup"),
        ComponentSig("com/google/common/collect/ImmutableList", "Guava", "com.google.guava:guava")
    )

    // Cloud storage / backend hosts worth flagging as an attack-surface map.
    private val CLOUD_HOST_HINTS = listOf(
        "firebaseio.com", "firebasedatabase.app", "s3.amazonaws.com", "amazonaws.com",
        "storage.googleapis.com", "blob.core.windows.net", "cloudfront.net",
        "digitaloceanspaces.com", "firebaseremoteconfig.googleapis.com"
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

        val components = mutableListOf<DetectedComponent>()
        manifestFindings(appInfo, pkg, findings)
        permissionFindings(info, pkg, findings)
        signingFindings(info, pkg, findings)
        val exportedClasses = linkedSetOf<String>()
        val componentCount = componentFindings(info, pkg, findings, exportedClasses)
        dexFindings(apk, pkg, findings, components)
        archiveFindings(apk, pkg, findings)
        flowFindings(apk, pkg, exportedClasses, findings)

        return ApkReport(
            ok = true,
            packageName = pkg,
            versionName = info.versionName ?: "",
            versionCode = if (android.os.Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong(),
            minSdk = appInfo?.minSdkVersion ?: 0,
            targetSdk = appInfo?.targetSdkVersion ?: 0,
            permissionCount = info.requestedPermissions?.size ?: 0,
            componentCount = componentCount,
            findings = findings,
            components = components
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

    private fun componentFindings(
        info: PackageInfo, pkg: String, out: MutableList<WebFinding>,
        exportedOut: MutableSet<String>
    ): Int {
        val activities: Array<ActivityInfo> = info.activities ?: emptyArray()
        val services: Array<ServiceInfo> = info.services ?: emptyArray()
        val receivers: Array<ActivityInfo> = info.receivers ?: emptyArray()
        val providers: Array<ProviderInfo> = info.providers ?: emptyArray()
        var reported = 0

        fun report(name: String, kind: String, sev: Severity) {
            exportedOut += name
            if (reported >= MAX_COMPONENT_FINDINGS) return
            reported++
            // The platform PackageManager confirms exported=true with no permission —
            // this is a verified fact about the manifest, not a guess, so CONFIRMED.
            out += f(
                "apk-exported-$name", "Exported $kind without permission: ${name.substringAfterLast('.')} [CWE-926]",
                pkg, "Manifest component export analysis (PackageManager)",
                "$name is exported (android:exported=true) and declares no permission guard; any app can invoke it.",
                sev, VerificationStatus.CONFIRMED,
                "Set android:exported=false, or protect it with a signature-level permission. Validate all inbound Intents/URIs."
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

    private fun dexFindings(
        apk: File, pkg: String, out: MutableList<WebFinding>,
        componentsOut: MutableList<DetectedComponent>
    ) {
        runCatching {
            ZipFile(apk).use { zip ->
                if (zip.size() > MAX_ENTRIES) return
                var scanned = 0L
                val indicatorHits = linkedMapOf<String, String>()      // needle -> context snippet
                val secretHits = linkedMapOf<String, MutableList<String>>() // label -> redacted samples
                val endpoints = linkedSetOf<String>()                  // discovered server URLs
                val components = linkedMapOf<String, DetectedComponent>() // coordinate -> component
                val trackers = linkedMapOf<String, TrackerSignatures.Tracker>() // name -> tracker
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    if (!e.name.endsWith(".dex")) continue              // scan ALL dex files, not just the first
                    if (scanned >= MAX_DEX_SCAN_BYTES) break
                    zip.getInputStream(e).use { ins ->
                        val remaining = (MAX_DEX_SCAN_BYTES - scanned).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                        val bytes = ins.readNBytesCompat(remaining)
                        scanned += bytes.size
                        val text = asciiStrings(bytes)
                        for (ind in DEX_INDICATORS) {
                            if (!indicatorHits.containsKey(ind.needle)) {
                                val idx = text.indexOf(ind.needle)
                                if (idx >= 0) indicatorHits[ind.needle] = snippet(text, idx, ind.needle.length)
                            }
                        }
                        for ((label, rx) in SECRET_PATTERNS) {
                            val bucket = secretHits.getOrPut(label) { mutableListOf() }
                            if (bucket.size >= 3) continue
                            val generic = label.startsWith("Generic")
                            rx.findAll(text).forEach { m ->
                                if (bucket.size >= 3) return@forEach
                                // Generic patterns are noisy: keep only high-entropy values
                                // so placeholders like password="changeme" are dropped.
                                if (generic && shannonEntropy(m.value) < 3.4) return@forEach
                                bucket.add(redact(m.value))
                            }
                        }
                        for (sig in COMPONENT_SIGNATURES) {
                            if (components.containsKey(sig.coordinate)) continue
                            if (text.contains(sig.marker)) {
                                val version = sig.versionRegex?.find(text)?.groupValues?.getOrNull(1)
                                components[sig.coordinate] = DetectedComponent(sig.name, sig.coordinate, version)
                            }
                        }
                        // Cherlogons Privacy Radar — our own tracker/SDK fingerprints.
                        for (t in TrackerSignatures.ALL) {
                            if (!trackers.containsKey(t.name) && text.contains(t.marker)) trackers[t.name] = t
                        }
                        URL_REGEX.findAll(text).forEach { m ->
                            if (endpoints.size < MAX_ENDPOINTS) endpoints.add(m.value.take(160))
                        }
                    }
                }
                // Authoritative versions from Gradle's META-INF/*.version files.
                // This turns "version unknown (POTENTIAL)" into an exact version →
                // an exact CVE match (CONFIRMED). The high-value, verifiable path.
                val metaVersions = metaInfVersions(zip)
                for ((coordinate, version) in metaVersions) {
                    val existing = components[coordinate]
                    if (existing != null) {
                        if (existing.version == null) components[coordinate] = existing.copy(version = version)
                    } else if (components.size < MAX_COMPONENTS) {
                        val artifact = coordinate.substringAfterLast(':')
                        components[coordinate] = DetectedComponent(artifact, coordinate, version)
                    }
                }

                componentsOut += components.values
                if (components.isNotEmpty()) {
                    val known = components.values.count { it.version != null }
                    out += f("apk-components", "Third-party libraries detected (${components.size}, $known with exact version)", pkg,
                        "DEX fingerprint + META-INF version extraction",
                        components.values.joinToString("  |  ") {
                            it.name + (it.version?.let { v -> " v$v" } ?: " (version unknown)")
                        }.take(1200),
                        Severity.INFO, VerificationStatus.INFORMATIONAL,
                        "Components with an exact version are matched against the CVE database (OSV) for a CONFIRMED verdict; version-unknown ones are checked as leads.")
                }

                // Cherlogons Privacy Radar: report detected trackers/SDKs (our engine).
                if (trackers.isNotEmpty()) {
                    val byCat = trackers.values.groupBy { it.category }
                    val summary = byCat.entries.joinToString("\n") { (cat, list) ->
                        "• ${cat.label}: " + list.joinToString(", ") { it.name }
                    }
                    val hasAds = byCat.containsKey(TrackerSignatures.Category.ADVERTISING)
                    val hasLoc = byCat.containsKey(TrackerSignatures.Category.LOCATION)
                    val sev = when {
                        hasLoc -> Severity.MEDIUM
                        hasAds -> Severity.MEDIUM
                        trackers.size >= 4 -> Severity.MEDIUM
                        else -> Severity.LOW
                    }
                    out += f("apk-privacy-radar", "Cherlogons Privacy Radar: ${trackers.size} tracker/SDK(s) bundled", pkg,
                        "Cherlogons Privacy Radar (offline DEX signature match)",
                        summary.take(1400),
                        sev, VerificationStatus.CONFIRMED,
                        "Each bundled SDK is a verified fact. Confirm which are actually needed; advertising, profiling and location SDKs carry the highest privacy impact and may require consent/disclosure (e.g. GDPR/CCPA).")
                }

                // Vulnerability-class indicators, with severity escalation on correlation.
                val jsBridge = indicatorHits.containsKey("addJavascriptInterface")
                val jsEnabled = indicatorHits.containsKey("setJavaScriptEnabled")
                for (ind in DEX_INDICATORS) {
                    val ctx = indicatorHits[ind.needle] ?: continue
                    // A JS bridge together with JavaScript enabled is a real remote-code path.
                    val sev = if (ind.needle == "addJavascriptInterface" && jsEnabled) Severity.CRITICAL else ind.severity
                    val extra = if (ind.needle == "addJavascriptInterface" && jsEnabled)
                        " Correlated with setJavaScriptEnabled → exploitable JS→native bridge." else ""
                    out += f("apk-dex-${ind.needle}", "${ind.title} [${ind.cwe}]", pkg,
                        "Bounded DEX string scan (all DEX)",
                        "Reference to '${ind.needle}' in bytecode.$extra Context: …$ctx…",
                        sev, VerificationStatus.POTENTIAL, ind.fix)
                }

                // Hardcoded secrets — the high-value, anyone-can-extract finding.
                for ((label, samples) in secretHits) {
                    if (samples.isEmpty()) continue
                    out += f("apk-dex-secret-$label", "Hardcoded secret in APK: $label", pkg,
                        "Bounded DEX string scan (all DEX)",
                        "Matched $label (redacted): " + samples.joinToString("  |  "),
                        Severity.HIGH, VerificationStatus.POTENTIAL,
                        "Anyone can unzip the APK and read this. Remove it, move secrets server-side, and ROTATE the exposed credential immediately.")
                }

                if (endpoints.isNotEmpty()) {
                    val hosts = endpoints.mapNotNull { hostOf(it) }.distinct()
                    out += f("apk-endpoints", "Backend attack surface: ${hosts.size} host(s), ${endpoints.size} URL(s)", pkg,
                        "Static DEX URL extraction (no connection made)",
                        "Hosts: " + hosts.take(30).joinToString(", ").take(700) +
                            "\nSample URLs: " + endpoints.take(20).joinToString("  |  ").take(1100),
                        Severity.INFO, VerificationStatus.INFORMATIONAL,
                        "These are the servers/URLs the app references — the map to test next (with authorization). No request was sent by this scan.")

                    val cleartext = endpoints.filter { it.startsWith("http://") }
                    if (cleartext.isNotEmpty()) {
                        out += f("apk-cleartext-endpoints", "Cleartext (http://) endpoints referenced in code [CWE-319]", pkg,
                            "Static DEX URL extraction", cleartext.take(12).joinToString("  |  ").take(700),
                            Severity.MEDIUM, VerificationStatus.POTENTIAL,
                            "Move these endpoints to HTTPS; cleartext traffic can be read and modified by a network attacker.")
                    }

                    // Cloud backends are classic high-value targets (open Firebase DB, public buckets).
                    val cloud = endpoints.filter { url -> CLOUD_HOST_HINTS.any { url.contains(it, ignoreCase = true) } }
                    if (cloud.isNotEmpty()) {
                        val firebase = cloud.any { it.contains("firebaseio.com", true) || it.contains("firebasedatabase.app", true) }
                        out += f("apk-cloud-backends",
                            if (firebase) "Firebase database endpoint referenced (test for open read/write)"
                            else "Cloud storage/backends referenced (test for public access)",
                            pkg, "Static DEX URL extraction",
                            cloud.distinct().take(15).joinToString("  |  ").take(900),
                            Severity.MEDIUM, VerificationStatus.POTENTIAL,
                            if (firebase) "With authorization, verify the Realtime Database rules are not world-readable/writable (append /.json). Open Firebase DBs are a common high-impact disclosure."
                            else "With authorization, verify these buckets/CDNs are not publicly listable or writable.")
                    }
                }
            }
        }
    }

    /**
     * Bytecode data-flow: for each exported component, prove whether a method both
     * reads attacker input (Intent/URI) and reaches a dangerous sink. Upgrades the
     * finding from "exported, no permission (fact)" to "exported entry point has a
     * reachable path to a sink" — the evidence the reviewer actually needs.
     */
    private fun flowFindings(
        apk: File, pkg: String, exportedClasses: Set<String>, out: MutableList<WebFinding>
    ) {
        val flows = runCatching { DexFlowAnalyzer.analyze(apk, exportedClasses) }.getOrDefault(emptyList())
        for (fl in flows) {
            val baseSev = when {
                fl.sink.contains("SQL") || fl.sink.contains("command") || fl.sink.contains("code loading") -> Severity.HIGH
                else -> Severity.MEDIUM
            }
            val cls = fl.component.substringAfterLast('.')
            val chainTxt = fl.chain?.let { " via $it" } ?: ""
            if (fl.tainted) {
                // Taint actually reached the sink — a proven value-flow path.
                out += f(
                    "apk-taint-${fl.component}-${fl.sink.substringBefore(' ')}",
                    "Tainted data-flow: exported $cls → ${fl.sink}",
                    pkg, "Bytecode taint analysis (dexlib2)",
                    "Attacker-controllable input (${fl.source}) flows through registers into the sink '${fl.sink}' in ${fl.component}.${fl.method}()$chainTxt. The tainted value reaches the sink — a value-flow path exists, not just co-occurrence.",
                    baseSev, VerificationStatus.CONFIRMED,
                    "Sanitize/parameterize the input before this sink (bound SQL params, URL allow-lists, no shell, canonicalize paths). NOTE: confirms a value-flow path, not end impact — a runtime PoC is still needed to prove exploitability."
                )
            } else {
                // Source and sink co-occur but taint did not link them — a lead.
                out += f(
                    "apk-flow-${fl.component}-${fl.sink.substringBefore(' ')}",
                    "Possible path: exported $cls has input + ${fl.sink}",
                    pkg, "Bytecode data-flow (dexlib2)",
                    "In ${fl.component}.${fl.method}(), attacker-controllable input (${fl.source}) and the sink '${fl.sink}' both occur, but taint tracking did not link them. Review manually.",
                    if (baseSev == Severity.HIGH) Severity.MEDIUM else Severity.LOW,
                    VerificationStatus.POTENTIAL,
                    "Verify whether the input can reach this sink; sanitize/parameterize if so."
                )
            }
        }
    }

    /**
     * Unpacks the APK archive and analyzes EVERY file inside it — not just DEX.
     * Reads text-like resources/assets for secrets and endpoints (API keys and
     * Firebase configs often live in assets, not code), inspects native .so
     * libraries, detects embedded executable payloads (secondary dex/apk/jar) and
     * commercial packers/protectors, and reports an archive inventory. Fully
     * offline and bounded in memory.
     */
    private fun archiveFindings(apk: File, pkg: String, out: MutableList<WebFinding>) {
        runCatching {
            ZipFile(apk).use { zip ->
                if (zip.size() > MAX_ENTRIES) return
                var total = 0L
                var files = 0
                val assetSecrets = linkedMapOf<String, MutableList<String>>()  // label -> samples@path
                val assetEndpoints = linkedSetOf<String>()
                val nativeLibs = linkedSetOf<String>()                          // "abi/name.so"
                val packers = linkedMapOf<String, String>()                     // vendor -> lib
                val embedded = mutableListOf<String>()                          // suspicious payloads
                val byExt = HashMap<String, Int>()
                val dexRoot = Regex("""classes\d*\.dex""")

                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    if (e.isDirectory) continue
                    val name = e.name
                    val ext = name.substringAfterLast('.', "").lowercase()
                    byExt[ext] = (byExt[ext] ?: 0) + 1

                    // Native libraries (and packer detection + bounded string scan).
                    if (name.startsWith("lib/") && ext == "so") {
                        val parts = name.split('/')
                        if (parts.size >= 3) nativeLibs.add(parts[1] + "/" + parts.last())
                        val base = name.substringAfterLast('/')
                        for ((frag, vendor) in PACKER_LIBS) if (base.contains(frag, true)) packers.putIfAbsent(vendor, base)
                        if (total < MAX_RES_TOTAL_BYTES) {
                            val cap = minOf(MAX_SO_SCAN_BYTES, MAX_RES_TOTAL_BYTES - total)
                                .coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                            runCatching {
                                zip.getInputStream(e).use { ins ->
                                    val bytes = ins.readNBytesCompat(cap)
                                    total += bytes.size
                                    val t = asciiStrings(bytes)
                                    URL_REGEX.findAll(t).forEach {
                                        if (assetEndpoints.size < MAX_ENDPOINTS) assetEndpoints.add(it.value.take(160))
                                    }
                                }
                            }
                        }
                        continue
                    }

                    // Embedded executable payloads (a secondary dex/apk/jar outside the
                    // normal root classesN.dex is a packer/dropper indicator).
                    val isRootDex = ext == "dex" && !name.contains('/') && dexRoot.matches(name)
                    if ((ext == "dex" && !isRootDex) || ext == "apk" || ext == "jar") {
                        if (embedded.size < 30) embedded.add(name.take(120))
                    }

                    // Text-like resources/assets: scan for secrets + endpoints.
                    if (ext in TEXT_EXT && files < MAX_RES_FILES && total < MAX_RES_TOTAL_BYTES &&
                        e.size in 1..MAX_RES_FILE_BYTES
                    ) {
                        files++
                        val cap = minOf(MAX_RES_FILE_BYTES, MAX_RES_TOTAL_BYTES - total)
                            .coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                        runCatching {
                            zip.getInputStream(e).use { ins ->
                                val bytes = ins.readNBytesCompat(cap)
                                total += bytes.size
                                val content = String(bytes, Charsets.UTF_8)
                                for ((label, rx) in SECRET_PATTERNS) {
                                    val generic = label.startsWith("Generic")
                                    val bucket = assetSecrets.getOrPut(label) { mutableListOf() }
                                    if (bucket.size >= 3) continue
                                    rx.findAll(content).forEach { m ->
                                        if (bucket.size >= 3) return@forEach
                                        if (generic && shannonEntropy(m.value) < 3.4) return@forEach
                                        bucket.add(redact(m.value) + "  @" + name.takeLast(70))
                                    }
                                }
                                URL_REGEX.findAll(content).forEach {
                                    if (assetEndpoints.size < MAX_ENDPOINTS) assetEndpoints.add(it.value.take(160))
                                }
                            }
                        }
                    }
                }

                // --- Findings ---
                if (embedded.isNotEmpty()) {
                    out += f("apk-embedded-payload", "Embedded executable payload(s) in resources (${embedded.size})", pkg,
                        "Archive inspection", embedded.joinToString("  |  ").take(900),
                        Severity.HIGH, VerificationStatus.CONFIRMED,
                        "A secondary dex/apk/jar bundled in assets is a packer/dropper pattern. Verify it is legitimate and not loading unreviewed code at runtime.")
                }
                if (packers.isNotEmpty()) {
                    out += f("apk-packer", "App is packed/protected: ${packers.keys.joinToString(", ")}", pkg,
                        "Native-library packer fingerprint",
                        packers.entries.joinToString("  |  ") { "${it.key} (${it.value})" }.take(600),
                        Severity.MEDIUM, VerificationStatus.CONFIRMED,
                        "Packed apps hide their real code until runtime, so static analysis sees little. Real code is unpacked in memory — deeper review needs a dynamic/unpacking step.")
                }
                for ((label, samples) in assetSecrets) {
                    if (samples.isEmpty()) continue
                    out += f("apk-asset-secret-$label", "Hardcoded secret in packaged file: $label", pkg,
                        "Resource/asset content scan",
                        "Matched $label (redacted) in bundled file(s): " + samples.joinToString("  |  "),
                        Severity.HIGH, VerificationStatus.POTENTIAL,
                        "Secrets in assets are trivially extractable by unzipping the APK. Remove, move server-side, and ROTATE the credential.")
                }
                if (assetEndpoints.isNotEmpty()) {
                    val hosts = assetEndpoints.mapNotNull { hostOf(it) }.distinct()
                    out += f("apk-asset-endpoints", "Endpoints in packaged files: ${hosts.size} host(s)", pkg,
                        "Resource/asset + native-lib URL extraction (no connection made)",
                        "Hosts: " + hosts.take(30).joinToString(", ").take(700) +
                            "\nSample URLs: " + assetEndpoints.take(20).joinToString("  |  ").take(1000),
                        Severity.INFO, VerificationStatus.INFORMATIONAL,
                        "Servers referenced in assets/native libraries (not just code). Verify each is expected.")
                    val cleartext = assetEndpoints.filter { it.startsWith("http://") }
                    if (cleartext.isNotEmpty()) {
                        out += f("apk-asset-cleartext", "Cleartext (http://) endpoints in packaged files [CWE-319]", pkg,
                            "Resource/asset URL extraction", cleartext.take(12).joinToString("  |  ").take(700),
                            Severity.MEDIUM, VerificationStatus.POTENTIAL,
                            "Move these endpoints to HTTPS.")
                    }
                }
                if (nativeLibs.isNotEmpty()) {
                    val abis = nativeLibs.mapNotNull { it.substringBefore('/').ifBlank { null } }.distinct()
                    out += f("apk-native-libs", "Native libraries bundled (${nativeLibs.size})", pkg,
                        "Archive inspection",
                        "ABIs: " + abis.joinToString(", ") + "\n" + nativeLibs.take(40).joinToString("  |  ").take(900),
                        Severity.INFO, VerificationStatus.INFORMATIONAL,
                        "Native code is not covered by the DEX scan; review these libraries separately if in scope.")
                }
                val topExt = byExt.entries.sortedByDescending { it.value }.take(12)
                    .joinToString(", ") { "${it.key.ifBlank { "(none)" }}:${it.value}" }
                out += f("apk-archive-inventory", "Archive inventory (${byExt.values.sum()} files, $files text scanned)", pkg,
                    "Archive inspection", "By type → $topExt".take(900),
                    Severity.INFO, VerificationStatus.INFORMATIONAL,
                    "Full list of packaged file types. Unusual payloads are flagged separately.")
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

    /**
     * Reads Gradle's `META-INF/<group>_<artifact>.version` files, which carry the
     * exact bundled version of a dependency. Authoritative when present — far more
     * reliable than guessing a version from a DEX string. Returns coordinate→version.
     */
    private fun metaInfVersions(zip: ZipFile): Map<String, String> {
        val out = linkedMapOf<String, String>()
        val entries = zip.entries()
        while (entries.hasMoreElements()) {
            val e = entries.nextElement()
            val name = e.name
            if (!name.startsWith("META-INF/") || !name.endsWith(".version")) continue
            if (e.size > 256) continue
            if (out.size >= MAX_COMPONENTS) break
            // File name: META-INF/<group>_<artifact>.version ; one '_' splits group/artifact.
            val base = name.removePrefix("META-INF/").removeSuffix(".version")
            val sep = base.indexOf('_')
            if (sep <= 0 || sep >= base.length - 1) continue
            val coordinate = base.substring(0, sep) + ":" + base.substring(sep + 1)
            val version = runCatching {
                zip.getInputStream(e).use { it.readBytes() }.toString(Charsets.UTF_8).trim()
            }.getOrNull()?.takeIf { it.isNotBlank() && it.length <= 40 && it.none { c -> c == '\n' } } ?: continue
            out[coordinate] = version
        }
        return out
    }

    /** Shannon entropy (bits/char) — used to drop low-signal generic secret matches. */
    private fun shannonEntropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val freq = HashMap<Char, Int>()
        for (c in s) freq[c] = (freq[c] ?: 0) + 1
        var h = 0.0
        val n = s.length.toDouble()
        for ((_, cnt) in freq) {
            val p = cnt / n
            h -= p * (Math.log(p) / Math.log(2.0))
        }
        return h
    }

    /** Shows just enough of a matched secret to be recognizable, never the whole value. */
    private fun redact(value: String): String {
        val v = value.trim()
        return if (v.length <= 12) v.take(4) + "…(redacted)"
        else v.take(8) + "…(redacted, ${v.length} chars)"
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
