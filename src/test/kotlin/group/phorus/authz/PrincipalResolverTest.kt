package group.phorus.authz

import group.phorus.authn.core.context.AuthenticationContext
import group.phorus.authn.core.dtos.AuthenticationContextData
import group.phorus.authz.core.model.RoleName
import group.phorus.authz.core.model.Scope
import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.core.read.ListAppender
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import java.util.UUID

/**
 * What the authenticated request turns into on the way to a permission check.
 */
class PrincipalResolverTest {

    private val resolver = AuthenticationContextPrincipalResolver()
    private val subject = UUID.fromString("00000000-0000-0000-0000-000000000001")
    private val organization = Scope("organization", "org_123")

    private fun authenticatedWith(roles: List<String>, scope: List<String> = emptyList()) {
        AuthenticationContext.context.set(AuthenticationContextData(userId = subject, roles = roles, scope = scope))
    }

    private val logged = ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>()
    private val resolverLog = LoggerFactory.getLogger(AuthenticationContextPrincipalResolver::class.java) as Logger

    @BeforeEach
    fun captureLogs() {
        logged.start()
        resolverLog.addAppender(logged)
    }

    @AfterEach
    fun clear() {
        resolverLog.detachAppender(logged)
        AuthenticationContext.context.remove()
    }

    @Test
    fun `answers nothing where the request carries no identity`() {
        assertNull(resolver.resolve())
    }

    @Test
    fun `reads a qualified role into the scope it names`() {
        authenticatedWith(listOf("ADMIN@organization:org_123"))

        assertEquals(mapOf(organization to setOf(RoleName("ADMIN"))), resolver.resolve()!!.roles)
    }

    @Test
    fun `holds an unqualified role platform-wide`() {
        authenticatedWith(listOf("OWNER"))

        assertEquals(mapOf(Scope.PLATFORM to setOf(RoleName("OWNER"))), resolver.resolve()!!.roles)
    }

    @Test
    fun `carries the subject and the delegated scope across`() {
        authenticatedWith(listOf("OWNER"), listOf("reports.read", "reports.export"))

        val principal = resolver.resolve()!!

        assertEquals(subject, principal.subjectId)
        assertEquals(listOf("reports.read", "reports.export"), principal.scope)
    }

    @Test
    fun `keeps the roles that parse where one beside them is malformed`() {
        authenticatedWith(listOf("ADMIN@", "VIEWER@organization:org_123"))

        assertEquals(mapOf(organization to setOf(RoleName("VIEWER"))), resolver.resolve()!!.roles)
    }

    @Test
    fun `a token whose every role is malformed still answers with a subject`() {
        authenticatedWith(listOf("ADMIN@", "@organization:org_123"))

        val principal = resolver.resolve()!!

        assertEquals(subject, principal.subjectId)
        assertTrue(principal.roles.isEmpty())
    }

    @Test
    fun `a dropped entry is reported at warn level, naming the entry`() {
        authenticatedWith(listOf("ADMIN@", "VIEWER@organization:org_123"))

        resolver.resolve()

        val warning = logged.list.single()

        assertEquals(Level.WARN, warning.level)
        assertTrue(warning.formattedMessage.contains("ADMIN@"))
    }

    @Test
    fun `a token whose roles all parse leaves the log empty`() {
        authenticatedWith(listOf("VIEWER@organization:org_123"))

        resolver.resolve()

        assertTrue(logged.list.isEmpty())
    }

    @Test
    fun `a token carrying no role answers with a subject holding none`() {
        authenticatedWith(emptyList(), listOf("reports.read"))

        val principal = resolver.resolve()!!

        assertTrue(principal.roles.isEmpty())
        assertEquals(listOf("reports.read"), principal.scope)
    }
}
