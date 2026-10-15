package group.phorus.authz.config

import group.phorus.authn.config.SecurityConfiguration
import group.phorus.authz.PrincipalResolver
import group.phorus.authz.core.evaluation.AuthorizationChain
import group.phorus.authz.core.evaluation.AuthorizationEvaluator
import group.phorus.authz.core.evaluation.Authorizer
import group.phorus.authz.core.evaluation.InMemoryRoleCatalog
import group.phorus.authz.core.evaluation.RoleCatalog
import group.phorus.authz.core.model.AuthZResult
import group.phorus.authz.core.model.AuthZSource
import group.phorus.authz.core.model.EvaluationContext
import group.phorus.authz.core.model.Permission
import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.RoleName
import group.phorus.authz.core.model.Scope
import group.phorus.authz.filters.RouteAuthorizationFilter
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.util.UUID

/**
 * What the starter builds, what it steps aside for, and what it refuses to start on.
 */
class AuthzAutoConfigurationTest {

    private val runner = ApplicationContextRunner()
        .withConfiguration(
            AutoConfigurations.of(
                ConfigurationPropertiesAutoConfiguration::class.java,
                SecurityConfiguration::class.java,
                AuthzConfiguration::class.java,
                AuthzAutoConfiguration::class.java,
            ),
        )
        .withPropertyValues("group.phorus.security.filters.token.enabled=true")

    private val subject = UUID.fromString("00000000-0000-0000-0000-000000000002")
    private val organization = Scope("organization", "org_123")

    @Test
    fun `builds every bean a service needs to gate a route`() {
        runner.run { context ->
            assertTrue(context.getBean(RoleCatalog::class.java) is InMemoryRoleCatalog)
            assertEquals(1, context.getBeansOfType(Authorizer::class.java).size)
            assertEquals(1, context.getBeansOfType(AuthorizationChain::class.java).size)
            assertEquals(1, context.getBeansOfType(PrincipalResolver::class.java).size)
            assertEquals(1, context.getBeansOfType(RouteAuthorizationFilter::class.java).size)
        }
    }

    @Test
    fun `builds nothing once authorization is turned off`() {
        runner.withPropertyValues("group.phorus.authz.enabled=false").run { context ->
            assertTrue(context.getBeansOfType(RouteAuthorizationFilter::class.java).isEmpty())
            assertTrue(context.getBeansOfType(Authorizer::class.java).isEmpty())
            assertTrue(context.getBeansOfType(RoleCatalog::class.java).isEmpty())
        }
    }

    @Test
    fun `steps aside for a catalogue the application declares`() {
        runner.withUserConfiguration(OwnCatalog::class.java).run { context ->
            val catalog = context.getBean(RoleCatalog::class.java)

            assertSame(OwnCatalog.instance, catalog)
            assertEquals(setOf("document:read"), catalog.permissions(RoleName("FROM_DATABASE")))
        }
    }

    @Test
    fun `steps aside for a principal resolver the application declares`() {
        runner.withUserConfiguration(OwnResolver::class.java).run { context ->
            assertSame(OwnResolver.instance, context.getBean(PrincipalResolver::class.java))
        }
    }

    @Test
    fun `a delegated scope narrows what the roles grant`() {
        runner.withPropertyValues("group.phorus.authz.roles.ADMIN[0]=document:read").run { context ->
            val authorizer = context.getBean(Authorizer::class.java)
            val holder = Principal(
                subjectId = UUID.randomUUID(),
                roles = mapOf(Scope.PLATFORM to setOf(RoleName("ADMIN"))),
                scope = listOf(Authorizer.UNRESTRICTED),
            )

            assertTrue(authorizer.permitsAnywhere(holder, "document:read"))
            assertTrue(authorizer.permitsAnywhere(holder.copy(scope = listOf("document:read")), "document:read"))
            assertFalse(authorizer.permitsAnywhere(holder.copy(scope = listOf("document:list")), "document:read"))
        }
    }

    @Test
    fun `places a contributed evaluator in the phase its source names`() {
        runner.withUserConfiguration(ContributedEvaluators::class.java)
            .withPropertyValues("group.phorus.authz.roles.ADMIN[0]=document:read")
            .run { context ->
                val chain = context.getBean(AuthorizationChain::class.java)
                val holder = Principal(
                    subjectId = UUID.randomUUID(),
                    roles = mapOf(Scope.PLATFORM to setOf(RoleName("ADMIN"))),
                    scope = listOf(Authorizer.UNRESTRICTED),
                )

                val result = runBlocking {
                    chain.evaluate(
                        EvaluationContext(
                            principal = holder,
                            requiredPermission = Permission.parse("document/doc_1:read"),
                        ),
                    )
                }

                // The role evaluator grants, then the attribute evaluator overrides it, which only
                // happens where the chain put the second one in the constraint phase.
                assertTrue(result.denied)
                assertEquals(AuthZSource.ABAC, result.source)
            }
    }

    @Test
    fun `refuses to start on a gate that requires nothing`() {
        runner.withPropertyValues("group.phorus.authz.gates[0].path=/admin/**").run { context ->
            assertTrue(context.startupFailure!!.stackTraceToString().contains("requires nothing"))
        }
    }

    @Test
    fun `refuses to start on a gate with no path`() {
        runner.withPropertyValues("group.phorus.authz.gates[0].requires-any[0]=admin:access")
            .run { context ->
                assertTrue(context.startupFailure!!.stackTraceToString().contains("needs a path"))
            }
    }

    @Test
    fun `refuses to start on a gate naming something that is not an HTTP method`() {
        runner.withPropertyValues(
            "group.phorus.authz.gates[0].path=/admin/**",
            "group.phorus.authz.gates[0].method=FETCH",
            "group.phorus.authz.gates[0].requires-any[0]=admin:access",
        ).run { context ->
            assertTrue(context.startupFailure!!.stackTraceToString().contains("names the method \"FETCH\""))
        }
    }

    @Test
    fun `refuses to start on a lowercase method, which would match no request`() {
        runner.withPropertyValues(
            "group.phorus.authz.gates[0].path=/admin/**",
            "group.phorus.authz.gates[0].method=post",
            "group.phorus.authz.gates[0].requires-any[0]=admin:access",
        ).run { context ->
            assertTrue(context.startupFailure!!.stackTraceToString().contains("names the method \"post\""))
        }
    }

    @Test
    fun `refuses to start on a scope holding a space`() {
        runner.withPropertyValues(
            "group.phorus.authz.gates[0].path=/admin/**",
            "group.phorus.authz.gates[0].requires-scope[0]=read write",
        ).run { context ->
            assertTrue(context.startupFailure!!.stackTraceToString().contains("holds a space"))
        }
    }

    @Test
    fun `refuses to start where gates exist while the token filter is off`() {
        ApplicationContextRunner()
            .withConfiguration(
                AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration::class.java,
                    SecurityConfiguration::class.java,
                    AuthzConfiguration::class.java,
                    AuthzAutoConfiguration::class.java,
                ),
            )
            .withPropertyValues(
                "group.phorus.security.filters.token.enabled=false",
                "group.phorus.authz.gates[0].path=/admin/**",
                "group.phorus.authz.gates[0].requires-any[0]=admin:access",
            )
            .run { context ->
                assertTrue(
                    context.startupFailure!!.stackTraceToString().contains("every gated route would answer 401"),
                )
            }
    }

    @Test
    fun `starts with the token filter off where no gate is configured`() {
        ApplicationContextRunner()
            .withConfiguration(
                AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration::class.java,
                    SecurityConfiguration::class.java,
                    AuthzConfiguration::class.java,
                    AuthzAutoConfiguration::class.java,
                ),
            )
            .run { context ->
                assertEquals(1, context.getBeansOfType(RouteAuthorizationFilter::class.java).size)
            }
    }

    @Nested
    @DisplayName("Beans the application declares")
    inner class Declared {

        @Test
        fun `a catalogue answering from somewhere other than configuration decides the checks`() {
            runner.withUserConfiguration(CatalogFromElsewhere::class.java).run { context ->
                val authorizer = context.getBean(Authorizer::class.java)
                val holder = Principal(subject, mapOf(organization to setOf(RoleName("EDITOR"))), listOf(Authorizer.UNRESTRICTED))

                assertTrue(authorizer.permits(holder, "document:write", listOf(organization)))
            }
        }

        @Test
        fun `a resolver reading roles from outside the token decides who the subject is`() {
            runner.withUserConfiguration(ResolverFromElsewhere::class.java).run { context ->
                val principal = context.getBean(PrincipalResolver::class.java).resolve()!!

                assertEquals(subject, principal.subjectId)
                assertEquals(setOf(RoleName("ASSIGNED_ELSEWHERE")), principal.roles[organization])
            }
        }

        @Test
        fun `an attribute policy takes a decision away without being able to make one`() {
            runner.withUserConfiguration(WorkingHoursPolicy::class.java)
                .withPropertyValues("group.phorus.authz.roles.ADMIN[0]=document:read")
                .run { context ->
                    val chain = context.getBean(AuthorizationChain::class.java)
                    val holder = Principal(subject, mapOf(Scope.PLATFORM to setOf(RoleName("ADMIN"))), listOf(Authorizer.UNRESTRICTED))

                    val refused = runBlocking { chain.evaluate(contextFor(holder, "document/doc_1:read")) }

                    assertTrue(refused.denied)
                    assertEquals("Outside working hours", refused.reason)
                }
        }

        @Test
        fun `an attribute policy alone leaves every request refused`() {
            runner.withUserConfiguration(AbstainingPolicy::class.java).run { context ->
                val chain = context.getBean(AuthorizationChain::class.java)
                val holder = Principal(subject, mapOf(Scope.PLATFORM to setOf(RoleName("ADMIN"))), listOf(Authorizer.UNRESTRICTED))

                // Nothing grants, because the roles property named no permission for ADMIN.
                val refused = runBlocking { chain.evaluate(contextFor(holder, "document/doc_1:read")) }

                assertTrue(refused.denied)
            }
        }

        @Test
        fun `a contributed role evaluator takes the place of the built-in one`() {
            runner.withUserConfiguration(StricterRoleEvaluator::class.java)
                // The built-in evaluator grants this through the ADMIN role, so a chain still holding
                // it allows. The contributed evaluator abstains, which leaves the two distinguishable
                // whichever order the chain runs them in.
                .withPropertyValues("group.phorus.authz.roles.ADMIN[0]=document:read")
                .run { context ->
                    val chain = context.getBean(AuthorizationChain::class.java)
                    val holder = Principal(subject, mapOf(Scope.PLATFORM to setOf(RoleName("ADMIN"))), listOf(Authorizer.UNRESTRICTED))

                    val decision = runBlocking { chain.evaluate(contextFor(holder, "document/doc_1:read")) }

                    assertTrue(decision.denied, "The built-in role evaluator is still in the chain")
                }
        }

        @Test
        fun `an evaluator for another model runs beside the built-in one`() {
            runner.withUserConfiguration(AbstainingPolicy::class.java)
                .withPropertyValues("group.phorus.authz.roles.ADMIN[0]=document:read")
                .run { context ->
                    val chain = context.getBean(AuthorizationChain::class.java)
                    val holder = Principal(subject, mapOf(Scope.PLATFORM to setOf(RoleName("ADMIN"))), listOf(Authorizer.UNRESTRICTED))

                    val decision = runBlocking { chain.evaluate(contextFor(holder, "document/doc_1:read")) }

                    assertTrue(decision.allowed)
                    assertEquals(AuthZSource.RBAC, decision.source)
                }
        }

        @Test
        fun `a granting evaluator that refuses ends the check before the constraint phase`() {
            runner.withUserConfiguration(RefusingRoleEvaluator::class.java, WorkingHoursPolicy::class.java)
                .run { context ->
                    val chain = context.getBean(AuthorizationChain::class.java)
                    val holder = Principal(subject, mapOf(Scope.PLATFORM to setOf(RoleName("ADMIN"))), listOf(Authorizer.UNRESTRICTED))

                    val decision = runBlocking { chain.evaluate(contextFor(holder, "document/doc_1:read")) }

                    // The attribute policy also refuses, so the reason names which phase answered.
                    assertTrue(decision.denied)
                    assertEquals("Roles refuse outright", decision.reason)
                }
        }
    }

    private fun contextFor(principal: Principal, permission: String) = EvaluationContext(
        principal = principal,
        requiredPermission = Permission.parse(permission),
    )

    @Configuration
    class OwnCatalog {
        @Bean
        fun roleCatalog(): RoleCatalog = instance

        companion object {
            val instance = InMemoryRoleCatalog(
                mapOf(RoleName("FROM_DATABASE") to setOf("document:read")),
            )
        }
    }

    @Configuration
    class OwnResolver {
        @Bean
        fun principalResolver(): PrincipalResolver = instance

        companion object {
            val instance = PrincipalResolver { null }
        }
    }

    @Configuration
    class ContributedEvaluators {
        @Bean
        fun attributeEvaluator(): AuthorizationEvaluator = object : AuthorizationEvaluator {
            override val source = AuthZSource.ABAC
            override suspend fun evaluate(context: EvaluationContext) =
                AuthZResult.denied(reason = "outside working hours", source = AuthZSource.ABAC)
        }
    }
    @Configuration
    class CatalogFromElsewhere {
        @Bean
        fun roleCatalog() = object : RoleCatalog {
            override fun permissions(role: RoleName): Set<String> =
                if (role == RoleName("EDITOR")) setOf("document:write") else emptySet()
        }
    }

    @Configuration
    class ResolverFromElsewhere {
        @Bean
        fun principalResolver() = PrincipalResolver {
            Principal(
                subjectId = UUID.fromString("00000000-0000-0000-0000-000000000002"),
                roles = mapOf(Scope("organization", "org_123") to setOf(RoleName("ASSIGNED_ELSEWHERE"))),
            )
        }
    }

    @Configuration
    class WorkingHoursPolicy {
        @Bean
        fun workingHoursPolicy() = object : AuthorizationEvaluator {
            override val source = AuthZSource.ABAC

            override suspend fun evaluate(context: EvaluationContext) =
                AuthZResult.denied(reason = "Outside working hours", source = source)
        }
    }

    @Configuration
    class StricterRoleEvaluator {
        @Bean
        fun ownRoleEvaluator() = object : AuthorizationEvaluator {
            override val source = AuthZSource.RBAC

            override suspend fun evaluate(context: EvaluationContext) = AuthZResult.abstain()
        }
    }

    @Configuration
    class RefusingRoleEvaluator {
        @Bean
        fun refusingRoleEvaluator() = object : AuthorizationEvaluator {
            override val source = AuthZSource.RBAC

            override suspend fun evaluate(context: EvaluationContext) =
                AuthZResult.denied(reason = "Roles refuse outright", source = source)
        }
    }

    @Configuration
    class AbstainingPolicy {
        @Bean
        fun quietPolicy() = object : AuthorizationEvaluator {
            override val source = AuthZSource.ABAC

            override suspend fun evaluate(context: EvaluationContext) = AuthZResult.abstain()
        }
    }
}
