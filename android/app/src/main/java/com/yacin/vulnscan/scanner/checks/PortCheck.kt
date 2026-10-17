package com.yacin.vulnscan.scanner.checks

import com.yacin.vulnscan.scanner.Finding
import com.yacin.vulnscan.scanner.ScanContext
import com.yacin.vulnscan.scanner.Severity
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Light TCP connect scan of a small curated port list on the in-scope host.
 * A single authorized host, common ports only — not a mass/stealth scanner.
 */
class PortCheck : Check {
    override val id = "ports"

    private val common = mapOf(
        21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP", 53 to "DNS",
        80 to "HTTP", 110 to "POP3", 143 to "IMAP", 443 to "HTTPS", 445 to "SMB",
        1433 to "MSSQL", 3306 to "MySQL", 3389 to "RDP", 5432 to "PostgreSQL",
        5900 to "VNC", 6379 to "Redis", 8080 to "HTTP-alt", 8443 to "HTTPS-alt",
        9200 to "Elasticsearch", 27017 to "MongoDB"
    )

    private val risky = mapOf(
        23 to "Telnet", 445 to "SMB", 3389 to "RDP", 6379 to "Redis",
        9200 to "Elasticsearch", 27017 to "MongoDB", 5900 to "VNC"
    )

    override fun run(ctx: ScanContext): List<Finding> {
        val out = mutableListOf<Finding>()
        val host = ctx.scopeHost
        if (host.isEmpty()) return out

        val open = linkedMapOf<Int, String>()
        for ((port, svc) in common) {
            val reachable = runCatching {
                Socket().use { it.connect(InetSocketAddress(host, port), 2000); true }
            }.getOrDefault(false)
            if (reachable) open[port] = svc
        }

        if (open.isNotEmpty()) {
            out += Finding(
                id, "Open TCP ports discovered", Severity.INFO, host,
                evidence = open.entries.joinToString(", ") { "${it.key}/${it.value}" },
                remediation = "Expose only required services; firewall the rest."
            )
        }
        for ((port, svc) in open) {
            risky[port]?.let {
                out += Finding(
                    id, "Sensitive service exposed: $svc (port $port)", Severity.MEDIUM,
                    "$host:$port",
                    remediation = "Restrict $svc to trusted networks or disable public access."
                )
            }
        }
        return out
    }
}
