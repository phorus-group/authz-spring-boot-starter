package group.phorus.authz

import group.phorus.authn.core.context.AuthenticationContext
import group.phorus.authz.core.model.Principal
import org.slf4j.LoggerFactory

/**
 * Produces the [Principal] for the request being handled.
 *
 * Supply a bean of this type to decide the subject and its roles differently, for instance by
 * reading a role assignment table where the token carries the subject alone. The default reads the
 * token, so an application that keeps roles in its own database replaces this one. The
 * [RoleCatalog][group.phorus.authz.core.evaluation.RoleCatalog] is the other bean, and it maps a
 * role to permissions where this maps a request to a subject and its roles.
 */
fun interface PrincipalResolver {

    /**
     * @return the subject behind the request being handled, or `null` where the request arrives
     *     anonymous.
     */
    fun resolve(): Principal?
}

/**
 * Reads the subject out of the authentication context the token filter populated.
 *
 * Each entry of the `roles` claim names a role, optionally followed by `@` and the scope it is held
 * at, so `ADMIN@organization:org_123` is the admin role over that one organization and a bare
 * `OWNER` is held platform-wide. An entry in any other shape is logged and dropped, which keeps one
 * malformed claim from refusing every request the token makes.
 *
 * The token's `scope` claim is carried across untouched, and it narrows what the roles grant. A
 * token issued to the subject directly carries
 * [UNRESTRICTED][group.phorus.authz.core.evaluation.Authorizer.UNRESTRICTED] there, so whoever
 * mints a sign-in has to write that value for any check to pass.
 */
class AuthenticationContextPrincipalResolver : PrincipalResolver {

    private val log = LoggerFactory.getLogger(AuthenticationContextPrincipalResolver::class.java)

    override fun resolve(): Principal? {
        val authentication = AuthenticationContext.context.get() ?: return null

        return Principal.fromRoleEntries(
            subjectId = authentication.userId,
            roleEntries = authentication.roles,
            scope = authentication.scope,
            onDropped = { entry ->
                log.warn("Dropping role entry \"{}\": expected ROLE or ROLE@type:id", entry)
            },
        )
    }
}
