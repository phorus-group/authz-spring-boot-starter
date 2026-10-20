package group.phorus.authz.filters

import group.phorus.authn.config.Path
import group.phorus.authn.config.SecurityConfiguration
import group.phorus.authz.PrincipalResolver
import group.phorus.authz.config.AuthzConfiguration
import group.phorus.authz.config.DefaultPolicy
import group.phorus.authz.config.Gate
import group.phorus.authz.context.AuthorizationContext
import group.phorus.authz.core.evaluation.Authorizer
import group.phorus.authz.core.model.Principal
import group.phorus.exception.core.Forbidden
import group.phorus.exception.core.Unauthorized
import kotlinx.coroutines.asContextElement
import kotlinx.coroutines.withContext
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.web.server.CoWebFilter
import org.springframework.web.server.CoWebFilterChain
import org.springframework.web.server.ServerWebExchange

/**
 * WebFilter that reads the authenticated request into a [Principal], populates the
 * [AuthorizationContext] coroutine context element with it, and refuses a request before its
 * handler where the caller falls short of a [Gate] matching the route.
 *
 * ### What a gate checks
 *
 * A gate pairs a route with what a caller needs to reach it, declared under
 * [group.phorus.authz.gates][AuthzConfiguration.gates]. It runs before the handler, and a caller
 * passes where they hold the permission at **any** scope. The object the request concerns takes no
 * part, so a caller holding the permission over one container passes a gate on a route about an
 * object in a different one.
 *
 * A gate is therefore a coarse check. Once the handler has loaded the object and knows the scopes
 * it sits inside, it still has to check that the caller holds the permission **there**, through
 * [Authorizer.permits][group.phorus.authz.core.evaluation.Authorizer.permits] or through the
 * [AuthorizationChain][group.phorus.authz.core.evaluation.AuthorizationChain]. A route whose gate
 * is its only check lets a caller reach objects in containers they hold no role at.
 *
 * Gates read roles directly and do not run the chain, so an evaluator contributed later constrains
 * what a handler decides and leaves gates as they were.
 *
 * ### Roles and scope
 *
 * A gate can also require a value of the OAuth `scope` claim, which says what the calling
 * application was delegated rather than what the person may do. That claim is a separate thing from
 * [Scope][group.phorus.authz.core.model.Scope], the container a role is held at. Both have to hold,
 * so an application given a narrow scope reaches less than the person behind it. A gate requiring
 * only a scope decides from the claim alone, which leaves a route open to an application calling
 * for itself.
 *
 * ### Order of checks
 *
 * | Situation | Outcome |
 * |-----------|---------|
 * | The route is listed under [ignoredPaths][AuthzConfiguration.ignoredPaths] | The handler runs |
 * | The request falls outside every gate, under [DefaultPolicy.ALLOW] | The handler runs |
 * | The request falls outside every gate, under [DefaultPolicy.DENY] | 403 |
 * | A gate matches and the request arrives anonymous | 401 |
 * | A gate matches and the token lacks a required scope | 403 with [INSUFFICIENT_SCOPE] |
 * | A gate matches and the caller lacks a required permission | 403 |
 * | Every matching gate passes | The handler runs |
 *
 * Wherever the handler runs, it runs with the subject on [AuthorizationContext]. A request arriving
 * anonymous leaves that context empty.
 *
 * A scope refusal carries the `error` and `scope` parameters of a `WWW-Authenticate` header, so the
 * calling application can request a token from its issuer that reaches the route. It is answered
 * before a role refusal.
 *
 * ### Startup validation
 *
 * Every gate is read once at construction, and the filter throws an [IllegalArgumentException] for
 * a gate requiring nothing, a gate with no path, a blank permission or scope, a scope holding a
 * space, a method outside the standard set, or gates declared while the token filter is off.
 *
 * ### Filter ordering
 *
 * This filter runs **after** [AuthFilter][group.phorus.authn.filters.AuthFilter], which populates
 * the identity the subject is read from. It sits at `HIGHEST_PRECEDENCE + 3` against that filter's
 * `+ 2`.
 *
 * ### Enabling / disabling
 *
 * Controlled by `group.phorus.authz.enabled` (default: `true`). Turned off, the filter is left out
 * of the context, so neither the gates nor [AuthorizationContext] take any part.
 *
 * @see AuthorizationContext
 * @see AuthzConfiguration
 * @see Gate
 */
@Order(Ordered.HIGHEST_PRECEDENCE + 3)
class RouteAuthorizationFilter(
    private val configuration: AuthzConfiguration,
    private val principalResolver: PrincipalResolver,
    private val authorizer: Authorizer,
    securityConfiguration: SecurityConfiguration,
) : CoWebFilter() {

    init {
        configuration.gates.forEach { gate ->
            require(gate.path.isNotBlank()) { "Every gate needs a path. One gate has none." }

            require(
                gate.requiresAny.isNotEmpty() ||
                    gate.requiresAll.isNotEmpty() ||
                    gate.requiresScope.isNotEmpty(),
            ) {
                "Gate \"${gate.path}\" requires nothing. Name a permission under requires-any or " +
                    "requires-all, or a scope under requires-scope, or drop the gate."
            }

            (gate.requiresAny + gate.requiresAll).forEach { permission ->
                require(permission.isNotBlank()) { "Gate \"${gate.path}\" names a blank permission." }
            }

            gate.requiresScope.forEach { scope ->
                require(scope.isNotBlank()) { "Gate \"${gate.path}\" names a blank scope." }
                // RFC 6749 section 3.3 delimits scope values with spaces, so one holding a space is
                // two values written as one and would never match.
                require(' ' !in scope) {
                    "Gate \"${gate.path}\" names the scope \"$scope\", which holds a space. " +
                        "Write each scope as its own list entry."
                }
            }

            // HttpMethod.valueOf accepts any token, so a typo would build a method that equals
            // nothing and leave the gate matching no request at all.
            gate.method?.let { method ->
                require(HttpMethod.valueOf(method) in HttpMethod.values()) {
                    "Gate \"${gate.path}\" names the method \"$method\". Write one of " +
                        "${HttpMethod.values().joinToString(", ") { it.name() }}, or leave the " +
                        "method out to cover every one of them."
                }
            }
        }

        require(configuration.gates.isEmpty() || securityConfiguration.filters.token.enabled) {
            "Gates are configured while group.phorus.security.filters.token.enabled is false, so no " +
                "request would carry an identity and every gated route would answer 401. Turn the " +
                "token filter on, or remove the gates."
        }

        // Under the deny policy a gate or this list decides every route. A path listed here while
        // the token filter still demands a token is open to everyone holding any valid token, and
        // closed to the caller holding a credential of its own.
        if (configuration.defaultPolicy == DefaultPolicy.DENY) {
            configuration.ignoredPaths.filterNot { tokenFilterSkips(it, securityConfiguration) }.forEach { ignored ->
                val route = ignored.method?.let { "$it ${ignored.path}" } ?: ignored.path
                throw IllegalArgumentException(
                    "group.phorus.authz.ignored-paths names \"$route\" while the token filter still " +
                        "requires a token for it, and group.phorus.authz.default-policy is deny. The " +
                        "route would then be open to everyone holding any valid token, and closed to " +
                        "the caller holding a credential of its own. Add it to " +
                        "group.phorus.security.filters.token.ignored-paths where a credential of its " +
                        "own authenticates it, or give it a gate naming a permission its callers hold.",
                )
            }
        }
    }

    /**
     * Whether the token filter lets [ignored] through as an anonymous request, which is what makes
     * skipping authorization for it safe. True when the filter is off, when the path sits in its
     * own ignored list, and when it runs on a protected list naming other paths.
     */
    private fun tokenFilterSkips(ignored: Path, securityConfiguration: SecurityConfiguration): Boolean {
        val token = securityConfiguration.filters.token
        if (!token.enabled) return true
        val method = ignored.method?.let { HttpMethod.valueOf(it) } ?: HttpMethod.GET
        if (isIgnored(token.ignoredPaths, ignored.path, method)) return true
        // The token filter validates a refresh token and accepts it on this path alone, so the
        // route already holds a credential of its own.
        if (token.refreshTokenPath == ignored.path) return true
        return token.protectedPaths.isNotEmpty() && !isIgnored(token.protectedPaths, ignored.path, method)
    }

    override suspend fun filter(exchange: ServerWebExchange, chain: CoWebFilterChain) {
        // Read before anything suspends, while the identity the token filter installed is still on
        // this thread.
        val principal = principalResolver.resolve()

        val path = exchange.request.path.value()
        val method = exchange.request.method

        if (isIgnored(configuration.ignoredPaths, path, method)) {
            return withSubject(principal) { chain.filter(exchange) }
        }

        val gates = configuration.gates.filter { matchesGate(it, path, method) }

        if (gates.isEmpty()) {
            if (configuration.defaultPolicy == DefaultPolicy.DENY) {
                throw Forbidden("No gate covers $method $path and the default policy refuses.")
            }
            return withSubject(principal) { chain.filter(exchange) }
        }

        if (principal == null) throw Unauthorized("Authentication is required for $method $path")

        gates.forEach { gate -> enforce(gate, principal, exchange, "${method.name()} $path") }

        return withSubject(principal) { chain.filter(exchange) }
    }

    /**
     * Puts [principal] on [AuthorizationContext] for the rest of the request, so a handler reads the
     * subject without resolving it again.
     */
    private suspend fun withSubject(principal: Principal?, next: suspend () -> Unit) =
        if (principal == null) next() else withContext(AuthorizationContext.context.asContextElement(principal)) { next() }

    private fun enforce(gate: Gate, principal: Principal, exchange: ServerWebExchange, route: String) {
        val unrestricted = Authorizer.UNRESTRICTED in principal.scope
        val missingScope =
            if (unrestricted) emptyList() else gate.requiresScope.filterNot { it in principal.scope }

        if (missingScope.isNotEmpty()) {
            // RFC 6750 section 3.1 names this failure and asks for the scope that would fix it, so
            // the calling application can ask its issuer for a token that reaches this route.
            exchange.response.headers.set(
                HttpHeaders.WWW_AUTHENTICATE,
                "Bearer error=\"insufficient_scope\", scope=\"${missingScope.joinToString(" ")}\"",
            )
            throw Forbidden(
                message = "$route requires the scope ${missingScope.joinToString(" and ")}",
                code = INSUFFICIENT_SCOPE,
            )
        }

        val missing = gate.requiresAll.filterNot { authorizer.permitsAnywhere(principal, it) }
        if (missing.isNotEmpty()) {
            throw Forbidden("$route requires ${missing.joinToString(" and ")}")
        }

        if (gate.requiresAny.isNotEmpty() &&
            gate.requiresAny.none { authorizer.permitsAnywhere(principal, it) }
        ) {
            throw Forbidden("$route requires ${gate.requiresAny.joinToString(" or ")}")
        }
    }

    /** Error codes this filter puts on a refusal. */
    companion object {

        /**
         * The error code a refusal carries where the token's `scope` claim fell short while the
         * caller's roles sufficed, named by
         * [RFC 6750 §3.1](https://datatracker.ietf.org/doc/html/rfc6750#section-3.1).
         */
        const val INSUFFICIENT_SCOPE = "insufficient_scope"
    }
}
