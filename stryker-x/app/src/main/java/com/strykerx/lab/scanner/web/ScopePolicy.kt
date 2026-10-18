package com.strykerx.lab.scanner.web

import java.net.InetAddress
import java.net.URI

/**
 * Authorized scope + authorization declaration for a single scan.
 * Possession of a URL is NOT authorization; [authorizationDeclared] must be true
 * and the host must be in [allowlist] before any request is permitted.
 */
data class ScopePolicy(
    val targetHost: String,
    val allowlist: Set<String>,
    val authorizationDeclared: Boolean,
    val allowActiveTests: Boolean,
    val allowInternalNetwork: Boolean
) {
    /** A host is in scope if it is the target or an explicitly allow-listed host. */
    fun hostInScope(host: String): Boolean {
        val h = host.lowercase()
        if (h == targetHost.lowercase()) return true
        return allowlist.any { entry ->
            val e = entry.trim().lowercase()
            e.isNotEmpty() && (h == e || h.endsWith(".$e"))
        }
    }
}

/** Result of validating a target or a redirect hop. */
sealed interface ScopeResult {
    data class Allowed(val normalizedUrl: String, val host: String) : ScopeResult
    data class Rejected(val reason: String) : ScopeResult
}

object ScopeValidator {

    private val ALLOWED_SCHEMES = setOf("http", "https")
    private const val METADATA_IP = "169.254.169.254"

    private val SCHEME_PREFIX = Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://")

    fun normalizeUrl(raw: String): String {
        var v = raw.trim()
        // Only default to https when NO scheme is present; a non-http(s) scheme
        // (e.g. ftp://) must be preserved so validateSyntax can reject it.
        if (!SCHEME_PREFIX.containsMatchIn(v)) v = "https://$v"
        return v.trimEnd('/')
    }

    /** Validate URL syntax, scheme and host without network I/O. */
    fun validateSyntax(rawUrl: String): ScopeResult {
        val url = normalizeUrl(rawUrl)
        val uri = runCatching { URI(url) }.getOrNull()
            ?: return ScopeResult.Rejected("Malformed URL.")
        val scheme = uri.scheme?.lowercase()
        if (scheme !in ALLOWED_SCHEMES) return ScopeResult.Rejected("Unsupported scheme: $scheme")
        val host = uri.host ?: return ScopeResult.Rejected("Missing host.")
        if (host.isBlank()) return ScopeResult.Rejected("Empty host.")
        return ScopeResult.Allowed(url, host)
    }

    /**
     * True if the address is private, reserved, loopback, link-local or the
     * cloud metadata endpoint — blocked unless an internal assessment is approved.
     */
    fun isPrivateOrReserved(address: InetAddress): Boolean {
        if (address.hostAddress == METADATA_IP) return true
        return address.isLoopbackAddress ||
            address.isLinkLocalAddress ||
            address.isSiteLocalAddress ||
            address.isAnyLocalAddress ||
            address.isMulticastAddress
    }

    /**
     * Full validation for a target or redirect hop: syntax + scope membership +
     * (when resolver provided) resolved-address classification. The resolver is
     * injected so it can be mocked in tests and re-run at connect time to defeat
     * DNS rebinding.
     */
    fun validate(
        rawUrl: String,
        policy: ScopePolicy,
        resolver: (String) -> List<InetAddress> = { emptyList() }
    ): ScopeResult {
        if (!policy.authorizationDeclared) {
            return ScopeResult.Rejected("Authorization has not been declared for this scan.")
        }
        val syntax = validateSyntax(rawUrl)
        val allowed = syntax as? ScopeResult.Allowed ?: return syntax
        if (!policy.hostInScope(allowed.host)) {
            return ScopeResult.Rejected("Host '${allowed.host}' is outside the authorized scope.")
        }
        val addresses = runCatching { resolver(allowed.host) }.getOrDefault(emptyList())
        if (addresses.isNotEmpty() && !policy.allowInternalNetwork) {
            if (addresses.any { isPrivateOrReserved(it) }) {
                return ScopeResult.Rejected(
                    "Host '${allowed.host}' resolves to a private/reserved address; " +
                        "internal-network assessment is not approved."
                )
            }
        }
        return allowed
    }
}
