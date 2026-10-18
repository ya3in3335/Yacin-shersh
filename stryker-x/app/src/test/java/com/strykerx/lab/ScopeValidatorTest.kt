package com.strykerx.lab

import com.strykerx.lab.scanner.web.ScopePolicy
import com.strykerx.lab.scanner.web.ScopeResult
import com.strykerx.lab.scanner.web.ScopeValidator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class ScopeValidatorTest {

    private fun policy(
        host: String = "example.com",
        allow: Set<String> = emptySet(),
        authorized: Boolean = true,
        internal: Boolean = false
    ) = ScopePolicy(host, allow, authorized, allowActiveTests = false, allowInternalNetwork = internal)

    @Test
    fun normalizes_scheme_and_trailing_slash() {
        assertEquals("https://example.com", ScopeValidator.normalizeUrl("example.com/"))
        assertEquals("http://example.com", ScopeValidator.normalizeUrl("http://example.com"))
    }

    @Test
    fun rejects_unsupported_scheme() {
        val r = ScopeValidator.validateSyntax("ftp://example.com")
        assertTrue(r is ScopeResult.Rejected)
    }

    @Test
    fun unauthorized_scan_is_rejected() {
        val r = ScopeValidator.validate("https://example.com", policy(authorized = false))
        assertTrue(r is ScopeResult.Rejected)
    }

    @Test
    fun out_of_scope_host_is_rejected() {
        val r = ScopeValidator.validate("https://evil.com", policy(host = "example.com"))
        assertTrue(r is ScopeResult.Rejected)
    }

    @Test
    fun allowlisted_subdomain_is_in_scope() {
        val p = policy(host = "example.com", allow = setOf("example.com"))
        assertTrue(p.hostInScope("api.example.com"))
        assertTrue(p.hostInScope("example.com"))
        assertFalse(p.hostInScope("example.org"))
    }

    @Test
    fun redirect_to_out_of_scope_host_is_rejected() {
        // Simulates a redirect hop being re-validated against the same policy.
        val r = ScopeValidator.validate("https://tracker.evil.com/next", policy(host = "example.com"))
        assertTrue(r is ScopeResult.Rejected)
    }

    @Test
    fun private_and_metadata_addresses_are_detected() {
        assertTrue(ScopeValidator.isPrivateOrReserved(InetAddress.getByName("127.0.0.1")))
        assertTrue(ScopeValidator.isPrivateOrReserved(InetAddress.getByName("10.0.0.5")))
        assertTrue(ScopeValidator.isPrivateOrReserved(InetAddress.getByName("192.168.1.1")))
        assertTrue(ScopeValidator.isPrivateOrReserved(InetAddress.getByName("169.254.169.254")))
        assertFalse(ScopeValidator.isPrivateOrReserved(InetAddress.getByName("8.8.8.8")))
    }

    @Test
    fun resolves_to_private_blocks_without_internal_approval() {
        val resolver: (String) -> List<InetAddress> = { listOf(InetAddress.getByName("127.0.0.1")) }
        val blocked = ScopeValidator.validate("https://example.com", policy(internal = false), resolver)
        assertTrue(blocked is ScopeResult.Rejected)

        val allowed = ScopeValidator.validate("https://example.com", policy(internal = true), resolver)
        assertTrue(allowed is ScopeResult.Allowed)
    }
}
