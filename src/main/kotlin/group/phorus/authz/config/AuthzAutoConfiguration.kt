package group.phorus.authz.config

import group.phorus.authn.config.SecurityConfiguration
import group.phorus.authz.AuthenticationContextPrincipalResolver
import group.phorus.authz.PrincipalResolver
import group.phorus.authz.context.AuthorizationContext
import group.phorus.authz.core.evaluation.AuthorizationChain
import group.phorus.authz.core.evaluation.AuthorizationEvaluator
import group.phorus.authz.core.evaluation.Authorizer
import group.phorus.authz.core.evaluation.InMemoryRoleCatalog
import group.phorus.authz.core.evaluation.RoleCatalog
import group.phorus.authz.core.evaluation.ScopedRoleEvaluator
import group.phorus.authz.core.model.AuthZSource
import group.phorus.authz.core.model.RoleName
import group.phorus.authz.filters.RouteAuthorizationFilter
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean

/**
 * Builds the beans route authorization needs, reading the `group.phorus.authz` properties.
 *
 * Each bean here steps aside for one the application declares itself, so a service that keeps its
 * roles in a database declares a [RoleCatalog] and keeps the rest. An
 * [AuthorizationEvaluator] is the exception: one the application declares joins the chain
 * alongside these, and [authorizationChain] says which case replaces rather than adds.
 *
 * Setting `group.phorus.authz.enabled` to `false` leaves all of them out, so no request is checked
 * and [AuthorizationContext] is never populated. The whole set also depends on
 * [Authorizer] being on the classpath, which the authz-core dependency supplies.
 */
@AutoConfiguration
@ConditionalOnClass(Authorizer::class)
@ConditionalOnBooleanProperty(prefix = "group.phorus.authz", name = ["enabled"], matchIfMissing = true)
class AuthzAutoConfiguration {

    /**
     * Reads the `roles` property into a catalogue.
     *
     * Declare a [RoleCatalog] bean to read them from somewhere other than configuration, such as a
     * table a product team edits while the service runs.
     */
    @Bean
    @ConditionalOnMissingBean
    fun roleCatalog(configuration: AuthzConfiguration): RoleCatalog =
        InMemoryRoleCatalog(
            configuration.roles.entries.associate { (role, permissions) ->
                RoleName(role) to permissions.toSet()
            },
        )

    /**
     * Decides whether a subject holds a permission over a chain of containers, reading role
     * definitions from [catalog].
     */
    @Bean
    @ConditionalOnMissingBean
    fun authorizer(catalog: RoleCatalog): Authorizer = Authorizer(catalog)

    /**
     * Puts the role model into the chain as one evaluator among however many the service
     * declares.
     */
    @Bean
    @ConditionalOnMissingBean
    fun scopedRoleEvaluator(authorizer: Authorizer): ScopedRoleEvaluator =
        ScopedRoleEvaluator(authorizer)

    /**
     * Assembles every [AuthorizationEvaluator] bean into one chain, placing each by the model it
     * speaks for.
     *
     * [AuthZSource.RBAC], [AuthZSource.IMPLICIT] and [AuthZSource.REBAC] grant, so they run first
     * in that order and the first allow ends the search. [AuthZSource.ABAC] constrains, so it runs
     * afterwards and any denial among those overrides the grant. [AuthZSource.GRANT] is consulted
     * last, where every phase above it abstained.
     *
     * An evaluator declared later therefore changes decisions on its own: it joins the phase its
     * [AuthorizationEvaluator.source] names.
     *
     * An evaluator reporting [AuthZSource.RBAC] takes the place of [ScopedRoleEvaluator] and leaves
     * it out of the chain, since two granting evaluators for one model would leave the more
     * permissive of the pair deciding.
     */
    @Bean
    @ConditionalOnMissingBean
    fun authorizationChain(evaluators: List<AuthorizationEvaluator>): AuthorizationChain {
        val replacesRoles = evaluators.any { it.source == AuthZSource.RBAC && it !is ScopedRoleEvaluator }
        val bySource = evaluators
            .filterNot { replacesRoles && it is ScopedRoleEvaluator }
            .groupBy { it.source }

        return AuthorizationChain(
            grantingEvaluators = listOf(AuthZSource.RBAC, AuthZSource.IMPLICIT, AuthZSource.REBAC)
                .flatMap { bySource[it].orEmpty() },
            constraintEvaluators = bySource[AuthZSource.ABAC].orEmpty(),
            fallbackEvaluators = bySource[AuthZSource.GRANT].orEmpty(),
        )
    }

    /**
     * Reads the subject out of the authenticated request, which
     * [RouteAuthorizationFilter] then puts on [AuthorizationContext].
     */
    @Bean
    @ConditionalOnMissingBean
    fun principalResolver(): PrincipalResolver = AuthenticationContextPrincipalResolver()

    /**
     * Enforces the configured [gates][AuthzConfiguration.gates] and puts the subject on
     * [AuthorizationContext] for the handler.
     */
    @Bean
    @ConditionalOnMissingBean
    fun routeAuthorizationFilter(
        configuration: AuthzConfiguration,
        principalResolver: PrincipalResolver,
        authorizer: Authorizer,
        securityConfiguration: SecurityConfiguration,
    ) = RouteAuthorizationFilter(configuration, principalResolver, authorizer, securityConfiguration)
}
