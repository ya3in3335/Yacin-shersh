package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Confidence
import com.strykerx.lab.core.common.Severity
import com.strykerx.lab.core.common.VerificationStatus
import com.strykerx.lab.core.network.SafeHttp
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * An Nmap-like TCP connect port scanner — our own, native, no external binary.
 * It performs a full TCP connect (no raw sockets / no root needed), grabs a
 * service banner where offered, and flags high-risk exposed services. ACTIVE
 * recon, so it runs only when active testing is authorized; it is locked to the
 * single target host and refuses private/reserved addresses unless the scope
 * policy explicitly allows internal targets.
 */
class PortScanCheck(private val allowInternal: Boolean) : WebCheck {
    override val id = "port-scan"
    override val displayName = "Port Scan (TCP connect)"

    private val services: Map<Int, String> = linkedMapOf(
        21 to "ftp", 22 to "ssh", 23 to "telnet", 25 to "smtp", 53 to "dns",
        80 to "http", 110 to "pop3", 111 to "rpcbind", 135 to "msrpc", 139 to "netbios",
        143 to "imap", 443 to "https", 445 to "smb", 1433 to "mssql", 1521 to "oracle",
        2049 to "nfs", 2375 to "docker-api", 3306 to "mysql", 3389 to "rdp",
        5432 to "postgresql", 5900 to "vnc", 5984 to "couchdb", 6379 to "redis",
        7001 to "weblogic", 8080 to "http-alt", 8443 to "https-alt", 8888 to "http-alt",
        9200 to "elasticsearch", 11211 to "memcached", 27017 to "mongodb"
    )

    // Services that are frequently exposed without authentication / high impact.
    private val highRisk = mapOf(
        6379 to "Redis (often unauthenticated — full data access/RCE)",
        27017 to "MongoDB (often unauthenticated)",
        9200 to "Elasticsearch (often unauthenticated — data exposure)",
        11211 to "Memcached (unauthenticated; DDoS amplification)",
        2375 to "Docker API (unauthenticated = host takeover)",
        5984 to "CouchDB (often unauthenticated)",
        2049 to "NFS export",
        3389 to "RDP (brute-force/exploit target)",
        5900 to "VNC (often weak/no auth)",
        23 to "Telnet (cleartext credentials)",
        1433 to "MS SQL exposed",
        3306 to "MySQL exposed",
        5432 to "PostgreSQL exposed",
        445 to "SMB exposed"
    )

    override fun run(http: SafeHttp, baseUrl: String): List<WebFinding> {
        val host = runCatching { java.net.URI(baseUrl).host }.getOrNull()?.takeIf { it.isNotBlank() }
            ?: return emptyList()

        val addresses = runCatching { InetAddress.getAllByName(host).toList() }.getOrDefault(emptyList())
        if (addresses.isEmpty()) return emptyList()
        if (!allowInternal && addresses.any { ScopeValidator.isPrivateOrReserved(it) }) {
            return listOf(
                WebFinding(
                    code = "port-scan-skipped",
                    title = "Port scan skipped (target resolves to a private/reserved address)",
                    affected = host,
                    detectionMethod = "Scope policy",
                    evidence = "Resolved address is private/reserved; scanning it is disabled unless internal targets are authorized.",
                    severity = Severity.INFO,
                    confidence = Confidence.HIGH,
                    verification = VerificationStatus.INFORMATIONAL,
                    reproduction = "n/a",
                    remediation = "Enable internal-network scope only for hosts you are explicitly authorized to scan internally."
                )
            )
        }
        val target = addresses.first()
        val open = mutableListOf<Triple<Int, String, String>>() // port, service, banner
        for ((port, svc) in services) {
            val banner = probe(target, port) ?: continue
            open += Triple(port, svc, banner)
            Thread.sleep(25) // gentle pacing
        }
        if (open.isEmpty()) return emptyList()

        val out = mutableListOf<WebFinding>()
        out += WebFinding(
            code = "ports-open",
            title = "Open TCP ports: ${open.size}",
            affected = "$host (${target.hostAddress})",
            detectionMethod = "TCP connect scan",
            evidence = open.joinToString("  |  ") { (p, s, b) ->
                "$p/$s" + if (b.isNotBlank()) " [${b.take(60)}]" else ""
            }.take(1200),
            severity = Severity.INFO,
            confidence = Confidence.HIGH,
            verification = VerificationStatus.CONFIRMED,
            reproduction = "TCP connect to ${target.hostAddress} on the listed ports.",
            remediation = "Expose only the ports a public service requires; firewall the rest."
        )

        val risky = open.mapNotNull { (p, _, _) -> highRisk[p]?.let { p to it } }
        if (risky.isNotEmpty()) {
            out += WebFinding(
                code = "ports-risky",
                title = "High-risk services exposed: ${risky.joinToString(", ") { it.first.toString() }}",
                affected = "$host (${target.hostAddress})",
                detectionMethod = "TCP connect scan",
                evidence = risky.joinToString("  |  ") { "${it.first}: ${it.second}" }.take(1000),
                severity = Severity.HIGH,
                confidence = Confidence.MEDIUM,
                verification = VerificationStatus.POTENTIAL,
                reproduction = "Connect to the listed ports and check whether authentication is required.",
                remediation = "Do not expose datastores/management services to the internet. Require auth, bind to localhost/VPN, and firewall."
            )
        }
        return out
    }

    /** Returns a (possibly empty) banner if the port is open, or null if closed. */
    private fun probe(addr: InetAddress, port: Int): String? {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(addr, port), 800)
                s.soTimeout = 700
                val buf = ByteArray(128)
                val n = runCatching { s.getInputStream().read(buf) }.getOrDefault(-1)
                if (n > 0) String(buf, 0, n, Charsets.ISO_8859_1).replace(Regex("[\\x00-\\x1F]"), " ").trim()
                else ""
            }
        } catch (_: Exception) {
            null
        }
    }
}
