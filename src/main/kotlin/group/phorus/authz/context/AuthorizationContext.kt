package group.phorus.authz.context

import group.phorus.authz.core.model.Principal

/**
 * Holds the [Principal] for the request being handled.
 * Access the current value via `AuthorizationContext.context.get()`.
 *
 * [RouteAuthorizationFilter][group.phorus.authz.filters.RouteAuthorizationFilter] resolves the
 * subject once and puts it here, so a handler reads it without injecting anything and without the
 * role entries being parsed a second time.
 *
 * The value is present wherever the request carried an identity. A request arriving anonymous
 * leaves it empty, as does every request while `group.phorus.authz.enabled` is `false`, since the
 * filter is then left out of the context. A service in either position, or one wanting the subject
 * outside a request, calls [PrincipalResolver][group.phorus.authz.PrincipalResolver] instead.
 *
 * @see PrincipalResolver
 */
object AuthorizationContext {

    /** The subject behind the request being handled, or `null` outside one. */
    val context: ThreadLocal<Principal> = ThreadLocal()
}
