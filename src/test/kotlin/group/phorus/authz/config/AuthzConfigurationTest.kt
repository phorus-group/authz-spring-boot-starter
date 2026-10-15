package group.phorus.authz.config

import group.phorus.authn.config.SecurityConfiguration
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration
import group.phorus.authz.core.evaluation.RoleCatalog
import group.phorus.authz.core.model.RoleName
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import kotlin.reflect.full.memberProperties
import org.junit.jupiter.api.Test

/**
 * What the `group.phorus.authz` properties turn into once Spring has bound them, and the metadata
 * an IDE reads to complete them.
 */
class AuthzConfigurationTest {

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

    @Test
    fun `a bracketed role name keeps its spelling`() {
        runner.withPropertyValues(
            "group.phorus.authz.roles.[ADMIN][0]=document:approve",
            "group.phorus.authz.roles.[ADMIN][1]=document:read",
        ).run { context ->
            val catalog = context.getBean(RoleCatalog::class.java)

            assertEquals(setOf("document:approve", "document:read"), catalog.permissions(RoleName("ADMIN")))
        }
    }

    @Test
    fun `an uppercase role name keeps its case`() {
        runner.withPropertyValues("group.phorus.authz.roles.ADMIN[0]=document:approve").run { context ->
            val catalog = context.getBean(RoleCatalog::class.java)

            assertEquals(setOf("document:approve"), catalog.permissions(RoleName("ADMIN")))
            assertEquals(emptySet<String>(), catalog.permissions(RoleName("admin")))
        }
    }

    @Test
    fun `a role name holding an underscore or a hyphen survives`() {
        runner.withPropertyValues(
            "group.phorus.authz.roles.SUPER_ADMIN[0]=*",
            "group.phorus.authz.roles.read-only[0]=document:read",
        ).run { context ->
            val catalog = context.getBean(RoleCatalog::class.java)

            assertEquals(setOf("*"), catalog.permissions(RoleName("SUPER_ADMIN")))
            assertEquals(setOf("document:read"), catalog.permissions(RoleName("read-only")))
        }
    }

    @Test
    fun `a bracketed role name binds to the same key as an unbracketed one`() {
        runner.withPropertyValues("group.phorus.authz.roles.[SUPER_ADMIN][0]=*").run { context ->
            val catalog = context.getBean(RoleCatalog::class.java)

            assertEquals(setOf("*"), catalog.permissions(RoleName("SUPER_ADMIN")))
        }
    }

    @Test
    fun `a gate binds its path, method and both requirement lists`() {
        runner.withPropertyValues(
            "group.phorus.authz.gates[0].path=/documents/{id}/approve",
            "group.phorus.authz.gates[0].method=POST",
            "group.phorus.authz.gates[0].requires-any[0]=document:approve",
            "group.phorus.authz.gates[0].requires-any[1]=document:manage",
            "group.phorus.authz.gates[0].requires-all[0]=organization:member",
            "group.phorus.authz.gates[0].requires-scope[0]=documents.write",
        ).run { context ->
            val gate = context.getBean(AuthzConfiguration::class.java).gates.single()

            assertEquals("/documents/{id}/approve", gate.path)
            assertEquals("POST", gate.method)
            assertEquals(listOf("document:approve", "document:manage"), gate.requiresAny)
            assertEquals(listOf("organization:member"), gate.requiresAll)
            assertEquals(listOf("documents.write"), gate.requiresScope)
        }
    }

    @Test
    fun `a gate naming no method binds a null method`() {
        runner.withPropertyValues(
            "group.phorus.authz.gates[0].path=/admin/**",
            "group.phorus.authz.gates[0].requires-any[0]=admin:access",
        ).run { context ->
            assertNull(context.getBean(AuthzConfiguration::class.java).gates.single().method)
        }
    }

    @Test
    fun `the default policy binds from its lowercase spelling`() {
        runner.withPropertyValues("group.phorus.authz.default-policy=deny").run { context ->
            assertEquals(DefaultPolicy.DENY, context.getBean(AuthzConfiguration::class.java).defaultPolicy)
        }
    }

    @Test
    fun `an absent configuration allows every route and names no gate`() {
        runner.run { context ->
            val configuration = context.getBean(AuthzConfiguration::class.java)

            assertEquals(DefaultPolicy.ALLOW, configuration.defaultPolicy)
            assertTrue(configuration.gates.isEmpty())
            assertTrue(configuration.roles.isEmpty())
            assertTrue(configuration.enabled)
            assertTrue(configuration.ignoredPaths.isEmpty())
        }
    }

    @Test
    fun `an ignored path binds its pattern and method`() {
        runner.withPropertyValues(
            "group.phorus.authz.ignored-paths[0].path=/health",
            "group.phorus.authz.ignored-paths[0].method=GET",
        ).run { context ->
            val ignored = context.getBean(AuthzConfiguration::class.java).ignoredPaths.single()

            assertEquals("/health", ignored.path)
            assertEquals("GET", ignored.method)
        }
    }

    /**
     * The annotation processor writes this from the doc comment on each property, so a property
     * added without one reaches a release with no description in any IDE. These hold it to
     * [AuthzConfiguration].
     */
    @Nested
    @DisplayName("The metadata an IDE reads")
    inner class Metadata {

        private val metadata: JsonNode = ObjectMapper().readTree(
            javaClass.getResourceAsStream("/META-INF/spring-configuration-metadata.json")
                ?: error("The starter ships no spring-configuration-metadata.json"),
        )

        private val documented: Map<String, JsonNode> =
            metadata["properties"].associateBy { it["name"].asText() }

        /** `narrowByScope` in Kotlin is `narrow-by-scope` in configuration. */
        private fun keyFor(property: String) =
            "group.phorus.authz." + property.replace(Regex("([a-z])([A-Z])"), "$1-$2").lowercase()

        @Test
        fun `every configuration property is documented`() {
            val expected = AuthzConfiguration::class.memberProperties.map { keyFor(it.name) }.toSet()

            assertEquals(expected, documented.keys)
        }

        @Test
        fun `every documented property carries a description`() {
            val undocumented = documented.filterValues { it["description"]?.asText().isNullOrBlank() }

            assertTrue(undocumented.isEmpty(), "Missing descriptions: ${undocumented.keys}")
        }

        @Test
        fun `the group points at the class the properties come off`() {
            val group = metadata["groups"].single()

            assertEquals("group.phorus.authz", group["name"].asText())
            assertEquals(AuthzConfiguration::class.java.name, group["type"].asText())
        }

    }
}
