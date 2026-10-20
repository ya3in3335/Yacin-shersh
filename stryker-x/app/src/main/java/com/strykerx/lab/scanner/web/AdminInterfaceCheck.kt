package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp

/** Discovers exposed admin/login panels and management interfaces (attack surface). */
class AdminInterfaceCheck : WebCheck {
    override val id = "admin-interface"
    override val displayName = "Admin / Login Interfaces"

    private val paths = listOf(
        "/admin", "/admin/", "/administrator/", "/wp-admin/", "/wp-login.php",
        "/login", "/user/login", "/admin/login", "/phpmyadmin/", "/pma/",
        "/manager/html", "/.git/config", "/server-status", "/actuator",
        "/actuator/health", "/console", "/adminer.php"
    )
    private val loginHint = Regex("(?i)(password|log ?in|sign ?in|username|wp-login|phpmyadmin|dashboard)")

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val baseline = runCatching {
            http.get(baseUrl + "/cherlogons-404-probe-" + System.nanoTime().toString(36))
                ?.let { ExposureCheck.signatureOf(it) }
        }.getOrNull()
        val out = mutableListOf<WebFinding>()
        for (path in paths) {
            val resp = http.get(baseUrl + path) ?: continue
            if (resp.code !in listOf(200, 401, 403)) continue
            if (ExposureCheck.looksLikeCatchAll(baseline, ExposureCheck.signatureOf(resp))) continue
            val isActuator = path.startsWith("/actuator") || path == "/server-status" || path.endsWith(".git/config")
            val looksLogin = loginHint.containsMatchIn(resp.body.take(20_000))
            if (!looksLogin && !isActuator && resp.code == 200) continue
            val sev = when {
                path.endsWith(".git/config") -> Severity.HIGH
                isActuator -> Severity.MEDIUM
                resp.code == 200 -> Severity.LOW
                else -> Severity.INFO
            }
            out += WebFinding(
                code = "admin-$path",
                title = "Management interface reachable: $path (HTTP ${resp.code})",
                affected = resp.finalUrl,
                detectionMethod = "Known-path probe (catch-all guarded)",
                evidence = "Path responded ${resp.code}" + if (looksLogin) " and looks like a login/admin page." else ".",
                severity = sev,
                confidence = Confidence.MEDIUM,
                verification = VerificationStatus.CONFIRMED,
                reproduction = "Fetch ${resp.finalUrl}.",
                remediation = "Restrict management interfaces to trusted networks/VPN, require strong auth, and never expose VCS/actuator endpoints publicly."
            )
            if (out.size >= 8) break
        }
        return out
    }
}
