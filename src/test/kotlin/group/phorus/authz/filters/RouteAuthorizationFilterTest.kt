package group.phorus.authz.filters

import group.phorus.authn.config.Path
import group.phorus.authn.config.SecurityConfiguration
import group.phorus.authz.PrincipalResolver
import group.phorus.authz.config.AuthzConfiguration
import group.phorus.authz.config.DefaultPolicy
import group.phorus.authz.config.Gate
import group.phorus.authz.core.evaluation.Authorizer
import group.phorus.authz.core.evaluation.InMemoryRoleCatalog
import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.RoleName
import group.phorus.authz.core.model.Scope
import group.phorus.exception.core.Forbidden
import group.phorus.exception.core.Unauthorized
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import org.springframework.http.HttpHeaders
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import java.util.UUID

/**
 * What the filter does to a request, gate by gate.
 */
class RouteAuthorizationFilterTest {

    private val organization = Scope("organization", "org_123")

    private val authorizer = Authorizer(
        InMemoryRoleCatalog(
            mapOf(
                RoleName("ADMIN") to setOf("document:approve", "document:read"),
                RoleName("VIEWER") to setOf("document:read"),
            ),
        ),
    )

    private val administrator = Principal(
        subjectId = UUID.randomUUID(),
        roles = mapOf(organization to setOf(RoleName("ADMIN"))),
        scope = listOf(Authorizer.UNRESTRICTED),
    )

    private val viewer = Principal(
        subjectId = UUID.randomUUID(),
        roles = mapOf(organization to setOf(RoleName("VIEWER"))),
        scope = listOf(Authorizer.UNRESTRICTED),
    )

    /** Records whether the request got past the filter. */
    private class RecordingChain : WebFilterChain {
        var reached = false
        override fun filter(exchange: ServerWebExchange): Mono<Void> {
            reached = true
            return Mono.empty()
        }
    }

    private fun filterFor(
        principal: Principal?,
        gates: List<Gate> = emptyList(),
        defaultPolicy: DefaultPolicy = DefaultPolicy.ALLOW,
        ignoredPaths: List<Path> = emptyList(),
        // A route the token filter protects reaches authz with a token in hand, so the two lists
        // agree unless a test is about them disagreeing.
        tokenIgnoredPaths: List<Path> = ignoredPaths,
        tokenProtectedPaths: List<Path> = emptyList(),
        refreshTokenPath: String? = null,
        tokenFilterEnabled: Boolean = true,
    ) = RouteAuthorizationFilter(
        configuration = AuthzConfiguration(
            defaultPolicy = defaultPolicy,
            gates = gates,
            ignoredPaths = ignoredPaths,
        ),
        securityConfiguration = SecurityConfiguration().apply {
            filters.token.enabled = tokenFilterEnabled
            filters.token.ignoredPaths = tokenIgnoredPaths
            filters.token.protectedPaths = tokenProtectedPaths
            filters.token.refreshTokenPath = refreshTokenPath
        },
        principalResolver = PrincipalResolver { principal },
        authorizer = authorizer,
    )

    private fun gate(
        path: String,
        method: String? = null,
        requiresAny: List<String> = emptyList(),
        requiresAll: List<String> = emptyList(),
        requiresScope: List<String> = emptyList(),
    ) = Gate(path, method, requiresAny, requiresAll, requiresScope)

    private fun post(path: String) =
        MockServerWebExchange.from(MockServerHttpRequest.post(path))

    private fun get(path: String) =
        MockServerWebExchange.from(MockServerHttpRequest.get(path))

    @Test
    fun `lets a request through where no gate covers it`() {
        val chain = RecordingChain()

        filterFor(administrator, listOf(gate("/admin/**", requiresAny = listOf("admin:access"))))
            .filter(post("/documents/doc_1/approve"), chain).block()

        assertTrue(chain.reached)
    }

    @Test
    fun `refuses a request no gate covers under the deny policy`() {
        val chain = RecordingChain()
        val filter = filterFor(administrator, defaultPolicy = DefaultPolicy.DENY)

        assertThrows<Forbidden> { filter.filter(get("/documents"), chain).block() }
        assertFalse(chain.reached)
    }

    @Test
    fun `lets an ignored route through under the deny policy`() {
        val chain = RecordingChain()

        filterFor(
            principal = null,
            defaultPolicy = DefaultPolicy.DENY,
            ignoredPaths = listOf(Path("/health")),
        ).filter(get("/health"), chain).block()

        assertTrue(chain.reached)
    }

    @Test
    fun `refuses to start where an ignored route still demands a token under the deny policy`() {
        val error = assertThrows<IllegalArgumentException> {
            filterFor(
                principal = null,
                defaultPolicy = DefaultPolicy.DENY,
                ignoredPaths = listOf(Path("/health")),
                tokenIgnoredPaths = emptyList(),
            )
        }

        assertTrue(error.message.orEmpty().contains("/health"), error.message.orEmpty())
    }

    @Test
    fun `allows the same pairing under the allow policy, where a route outside every gate is open anyway`() {
        assertDoesNotThrow {
            filterFor(
                principal = null,
                defaultPolicy = DefaultPolicy.ALLOW,
                ignoredPaths = listOf(Path("/health")),
                tokenIgnoredPaths = emptyList(),
            )
        }
    }

    @Test
    fun `accepts the refresh route, which the token filter authenticates with a credential of its own`() {
        assertDoesNotThrow {
            filterFor(
                principal = null,
                defaultPolicy = DefaultPolicy.DENY,
                ignoredPaths = listOf(Path("/auth/token")),
                tokenIgnoredPaths = emptyList(),
                refreshTokenPath = "/auth/token",
            )
        }
    }

    @Test
    fun `accepts an ignored route where the token filter is switched off`() {
        assertDoesNotThrow {
            filterFor(
                principal = null,
                defaultPolicy = DefaultPolicy.DENY,
                ignoredPaths = listOf(Path("/health")),
                tokenIgnoredPaths = emptyList(),
                tokenFilterEnabled = false,
            )
        }
    }

    @Test
    fun `accepts an ignored route where the token filter's protected list names other routes`() {
        assertDoesNotThrow {
            filterFor(
                principal = null,
                defaultPolicy = DefaultPolicy.DENY,
                ignoredPaths = listOf(Path("/health")),
                tokenIgnoredPaths = emptyList(),
                tokenProtectedPaths = listOf(Path("/documents/**")),
            )
        }
    }

    @Test
    fun `refuses to start where the token filter's protected list covers the ignored route`() {
        val error = assertThrows<IllegalArgumentException> {
            filterFor(
                principal = null,
                defaultPolicy = DefaultPolicy.DENY,
                ignoredPaths = listOf(Path("/health")),
                tokenIgnoredPaths = emptyList(),
                tokenProtectedPaths = listOf(Path("/health")),
            )
        }

        assertTrue(error.message.orEmpty().contains("/health"), error.message.orEmpty())
    }

    @Test
    fun `lets a gated route through for a caller holding the permission`() {
        val chain = RecordingChain()

        filterFor(
            administrator,
            listOf(gate("/documents/{id}/approve", "POST", requiresAny = listOf("document:approve"))),
        ).filter(post("/documents/doc_1/approve"), chain).block()

        assertTrue(chain.reached)
    }

    @Test
    fun `refuses a gated route for a caller the role falls short of`() {
        val chain = RecordingChain()
        val filter = filterFor(
            viewer,
            listOf(gate("/documents/{id}/approve", "POST", requiresAny = listOf("document:approve"))),
        )

        val refusal = assertThrows<Forbidden> {
            filter.filter(post("/documents/doc_1/approve"), chain).block()
        }

        assertFalse(chain.reached)
        assertTrue(refusal.message!!.contains("document:approve"))
    }

    @Test
    fun `answers 401 where a gated route carries no identity`() {
        val chain = RecordingChain()
        val filter = filterFor(null, listOf(gate("/admin/**", requiresAny = listOf("admin:access"))))

        assertThrows<Unauthorized> { filter.filter(get("/admin/users"), chain).block() }
        assertFalse(chain.reached)
    }

    @Test
    fun `a gate ignores a method it does not name`() {
        val chain = RecordingChain()

        filterFor(viewer, listOf(gate("/documents/**", "POST", requiresAny = listOf("document:approve"))))
            .filter(get("/documents/doc_1"), chain).block()

        assertTrue(chain.reached)
    }

    @Test
    fun `one of several permissions is enough under requires-any`() {
        val chain = RecordingChain()

        filterFor(
            viewer,
            listOf(gate("/documents/**", requiresAny = listOf("document:approve", "document:read"))),
        ).filter(get("/documents/doc_1"), chain).block()

        assertTrue(chain.reached)
    }

    @Test
    fun `every permission is needed under requires-all`() {
        val chain = RecordingChain()
        val filter = filterFor(
            viewer,
            listOf(gate("/documents/**", requiresAll = listOf("document:read", "document:approve"))),
        )

        val refusal = assertThrows<Forbidden> { filter.filter(get("/documents/doc_1"), chain).block() }

        assertTrue(refusal.message!!.contains("document:approve"))
        assertFalse(refusal.message!!.contains("document:read"))
    }

    @Test
    fun `both lists have to hold where a gate names both`() {
        val chain = RecordingChain()
        val filter = filterFor(
            administrator,
            listOf(
                gate(
                    "/documents/**",
                    requiresAny = listOf("document:read"),
                    requiresAll = listOf("document:publish"),
                ),
            ),
        )

        assertThrows<Forbidden> { filter.filter(get("/documents/doc_1"), chain).block() }
    }

    @Test
    fun `every gate covering one route has to pass`() {
        val chain = RecordingChain()
        val filter = filterFor(
            viewer,
            listOf(
                gate("/documents/**", requiresAny = listOf("document:read")),
                gate("/documents/{id}/approve", requiresAny = listOf("document:approve")),
            ),
        )

        assertThrows<Forbidden> { filter.filter(post("/documents/doc_1/approve"), chain).block() }
    }

    @Test
    fun `a gate passes on a permission the caller holds at a scope the route never names`() {
        val chain = RecordingChain()

        // The caller administers org_123 and the route is about doc_1, whose organization nothing
        // has loaded yet. The gate passes on the strength of the role held elsewhere.
        filterFor(administrator, listOf(gate("/documents/**", requiresAny = listOf("document:approve"))))
            .filter(post("/documents/doc_in_another_org/approve"), chain).block()

        assertTrue(chain.reached)
    }

    @Test
    fun `lets a request through where the token carries the required scope`() {
        val chain = RecordingChain()

        filterFor(
            administrator.copy(scope = listOf("documents.write")),
            listOf(gate("/documents/**", requiresScope = listOf("documents.write"))),
        ).filter(post("/documents/doc_1/approve"), chain).block()

        assertTrue(chain.reached)
    }

    @Test
    fun `refuses where the token lacks a required scope, naming it in the response`() {
        val exchange = post("/documents/doc_1/approve")
        val filter = filterFor(
            administrator.copy(scope = listOf("documents.read")),
            listOf(gate("/documents/**", requiresScope = listOf("documents.write"))),
        )

        val refusal = assertThrows<Forbidden> { filter.filter(exchange, RecordingChain()).block() }

        assertEquals(RouteAuthorizationFilter.INSUFFICIENT_SCOPE, refusal.code)
        assertEquals(
            "Bearer error=\"insufficient_scope\", scope=\"documents.write\"",
            exchange.response.headers.getFirst(HttpHeaders.WWW_AUTHENTICATE),
        )
    }

    @Test
    fun `names every missing scope at once`() {
        val exchange = get("/internal/reports")
        val filter = filterFor(
            administrator.copy(scope = listOf("reports.list")),
            listOf(gate("/internal/**", requiresScope = listOf("reports.read", "reports.export"))),
        )

        assertThrows<Forbidden> { filter.filter(exchange, RecordingChain()).block() }

        assertEquals(
            "Bearer error=\"insufficient_scope\", scope=\"reports.read reports.export\"",
            exchange.response.headers.getFirst(HttpHeaders.WWW_AUTHENTICATE),
        )
    }

    @Test
    fun `a scope gate reads no roles, which is how an application calls for itself`() {
        val chain = RecordingChain()
        val roleless = Principal(
            subjectId = UUID.randomUUID(),
            roles = emptyMap(),
            scope = listOf("reports.read"),
        )

        filterFor(roleless, listOf(gate("/internal/**", requiresScope = listOf("reports.read"))))
            .filter(get("/internal/reports"), chain).block()

        assertTrue(chain.reached)
    }

    @Test
    fun `a missing scope is answered before a missing role`() {
        val exchange = get("/internal/reports")
        val filter = filterFor(
            viewer.copy(scope = listOf("reports.list")),
            listOf(
                gate(
                    "/internal/**",
                    requiresAny = listOf("document:approve"),
                    requiresScope = listOf("reports.read"),
                ),
            ),
        )

        val refusal = assertThrows<Forbidden> { filter.filter(exchange, RecordingChain()).block() }

        assertEquals(RouteAuthorizationFilter.INSUFFICIENT_SCOPE, refusal.code)
    }

    @Test
    fun `a role refusal carries no scope header`() {
        val exchange = get("/documents/doc_1")
        val filter = filterFor(viewer, listOf(gate("/documents/**", requiresAny = listOf("document:approve"))))

        val refusal = assertThrows<Forbidden> { filter.filter(exchange, RecordingChain()).block() }

        assertNull(refusal.code)
        assertNull(exchange.response.headers.getFirst(HttpHeaders.WWW_AUTHENTICATE))
    }
}
