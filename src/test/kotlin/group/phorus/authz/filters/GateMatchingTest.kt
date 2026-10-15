package group.phorus.authz.filters

import group.phorus.authn.config.Path
import group.phorus.authz.config.Gate
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.http.HttpMethod

/**
 * Which requests a gate and an ignored path cover.
 */
class GateMatchingTest {

    private fun gate(path: String, method: String? = null) =
        Gate(path = path, method = method, requiresAny = listOf("admin:access"))

    @Nested
    @DisplayName("Matching a gate")
    inner class Gates {

        @Test
        fun `an exact path matches only itself`() {
            assertTrue(matchesGate(gate("/admin/users"), "/admin/users", HttpMethod.GET))
            assertFalse(matchesGate(gate("/admin/users"), "/admin/users/1", HttpMethod.GET))
            assertFalse(matchesGate(gate("/admin/users"), "/admin", HttpMethod.GET))
        }

        @Test
        fun `a double star covers every depth below it`() {
            val subtree = gate("/admin/**")

            assertTrue(matchesGate(subtree, "/admin", HttpMethod.GET))
            assertTrue(matchesGate(subtree, "/admin/users", HttpMethod.GET))
            assertTrue(matchesGate(subtree, "/admin/users/1/roles", HttpMethod.GET))
            assertFalse(matchesGate(subtree, "/administration", HttpMethod.GET))
        }

        @Test
        fun `a single star covers one segment`() {
            val one = gate("/documents/*/approve")

            assertTrue(matchesGate(one, "/documents/doc_1/approve", HttpMethod.POST))
            assertFalse(matchesGate(one, "/documents/doc_1/versions/approve", HttpMethod.POST))
        }

        @Test
        fun `a template variable covers one segment and reads the same`() {
            val template = gate("/documents/{id}/approve")

            assertTrue(matchesGate(template, "/documents/doc_1/approve", HttpMethod.POST))
            assertFalse(matchesGate(template, "/documents/approve", HttpMethod.POST))
        }

        @Test
        fun `a gate naming a method covers that method alone`() {
            val post = gate("/documents/**", "POST")

            assertTrue(matchesGate(post, "/documents/doc_1", HttpMethod.POST))
            assertFalse(matchesGate(post, "/documents/doc_1", HttpMethod.GET))
            assertFalse(matchesGate(post, "/documents/doc_1", HttpMethod.DELETE))
        }

        @Test
        fun `a gate leaving the method out covers every method`() {
            val any = gate("/admin/**")

            HttpMethod.values().forEach { method ->
                assertTrue(matchesGate(any, "/admin/users", method), "$method should match")
            }
        }

        @Test
        fun `the path has to match even where the method does`() {
            assertFalse(matchesGate(gate("/admin/**", "POST"), "/documents/doc_1", HttpMethod.POST))
        }

        @Test
        fun `a trailing segment is covered only where the pattern says so`() {
            assertTrue(matchesGate(gate("/documents/{id}"), "/documents/doc_1", HttpMethod.GET))
            assertFalse(matchesGate(gate("/documents"), "/documents/doc_1", HttpMethod.GET))
        }
    }

    @Nested
    @DisplayName("Matching an ignored path")
    inner class Ignored {

        @Test
        fun `an empty list covers nothing`() {
            assertFalse(isIgnored(emptyList(), "/health", HttpMethod.GET))
        }

        @Test
        fun `one entry covers the path it names`() {
            assertTrue(isIgnored(listOf(Path("/health")), "/health", HttpMethod.GET))
            assertFalse(isIgnored(listOf(Path("/health")), "/metrics", HttpMethod.GET))
        }

        @Test
        fun `any entry covering the request is enough`() {
            val paths = listOf(Path("/health"), Path("/docs/**"), Path("/version"))

            assertTrue(isIgnored(paths, "/docs/api/v1", HttpMethod.GET))
            assertTrue(isIgnored(paths, "/version", HttpMethod.POST))
            assertFalse(isIgnored(paths, "/admin", HttpMethod.GET))
        }

        @Test
        fun `an entry naming a method covers that method alone`() {
            val getOnly = listOf(Path("/health", "GET"))

            assertTrue(isIgnored(getOnly, "/health", HttpMethod.GET))
            assertFalse(isIgnored(getOnly, "/health", HttpMethod.POST))
        }
    }
}
