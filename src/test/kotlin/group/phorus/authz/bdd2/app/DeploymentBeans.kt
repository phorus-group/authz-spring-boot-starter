package group.phorus.authz.bdd2.app

import group.phorus.authn.core.context.AuthenticationContext
import group.phorus.authz.PrincipalResolver
import group.phorus.authz.core.evaluation.Authorizer
import group.phorus.authz.core.evaluation.RoleCatalog
import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.RoleName
import group.phorus.authz.core.model.Scope
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * Stands in for a table a product team edits while the service runs.
 */
class RoleDefinitionTable {
    private val rows = mutableMapOf(
        "SUPERVISOR" to setOf("document:read", "document:approve"),
    )

    fun permissionsOf(role: String): Set<String> = rows[role].orEmpty()

    fun grant(role: String, permission: String) {
        rows[role] = rows[role].orEmpty() + permission
    }
}

/** Stands in for a table holding who holds which role where. */
class RoleAssignmentTable {
    val assignments = mutableMapOf<String, Map<Scope, Set<RoleName>>>()
}

/**
 * The two beans a service declares to decide roles for itself, written the way the README writes
 * them. Declaring either one leaves the rest of the starter in place.
 */
@Configuration
class DeploymentBeans {

    @Bean
    fun roleDefinitionTable() = RoleDefinitionTable()

    @Bean
    fun roleAssignmentTable() = RoleAssignmentTable()

    @Bean
    fun roleCatalog(table: RoleDefinitionTable) = object : RoleCatalog {
        override fun permissions(role: RoleName): Set<String> = table.permissionsOf(role.value)
    }

    @Bean
    fun principalResolver(table: RoleAssignmentTable) = PrincipalResolver {
        AuthenticationContext.context.get()?.let { authenticated ->
            Principal(
                subjectId = authenticated.userId,
                roles = table.assignments[authenticated.userId.toString()].orEmpty(),
                scope = listOf(Authorizer.UNRESTRICTED),
            )
        }
    }
}
