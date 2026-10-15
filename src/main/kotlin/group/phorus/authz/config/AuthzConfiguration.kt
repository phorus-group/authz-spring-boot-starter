package group.phorus.authz.config

import group.phorus.authn.config.Path
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Configuration for route authorization, bound from the `group.phorus.authz` prefix.
 *
 * A minimal configuration names the roles the service recognises and the routes that require a
 * permission:
 *
 * ```yaml
 * group.phorus.authz:
 *   roles:
 *     ADMIN: [ "document:approve", "document:read" ]
 *     VIEWER: [ "document:read" ]
 *   gates:
 *     - path: /documents/{id}/approve
 *       method: POST
 *       requires-any: [ "document:approve" ]
 * ```
 *
 * A role name keeps the spelling written here, so `ADMIN` in the configuration matches `ADMIN` in a
 * token. A name holding a dot needs square brackets, as in `"[service.admin]"`, which stops YAML
 * reading the dot as another level of nesting.
 */
@AutoConfiguration
@ConfigurationProperties(prefix = "group.phorus.authz")
class AuthzConfiguration(

    /**
     * Whether route authorization runs at all. Setting it to `false` leaves every bean in this
     * starter out and sends every request straight to its handler.
     */
    var enabled: Boolean = true,

    /**
     * What happens to a request outside every gate. `allow` sends it to its handler, `deny`
     * refuses it with a 403.
     */
    var defaultPolicy: DefaultPolicy = DefaultPolicy.ALLOW,

    /**
     * The permissions each role grants, keyed by role name. A list holding `*` grants every
     * permission. Leave empty and supply a `RoleCatalog` bean to read role definitions from a
     * database instead.
     */
    var roles: Map<String, List<String>> = emptyMap(),

    /**
     * The routes that require a permission or a scope. Where several match one request, every one
     * of them has to pass, and the order they are written in decides only which refusal is
     * reported.
     */
    var gates: List<Gate> = emptyList(),

    /**
     * Routes that skip authorization entirely, which is how a public route stays reachable under
     * the `deny` default policy.
     */
    var ignoredPaths: List<Path> = emptyList(),
)

/**
 * What happens to a request that falls outside every [Gate].
 */
enum class DefaultPolicy {

    /**
     * The request reaches its handler. Authorization is then whatever the handler itself checks.
     */
    ALLOW,

    /**
     * The request is refused with a 403. Every route that should be reachable needs either a gate
     * or an entry in [AuthzConfiguration.ignoredPaths].
     */
    DENY,
}

/**
 * One route and what a caller needs to reach it.
 *
 * A gate names requirements along two axes. [requiresAny] and [requiresAll] read the roles the
 * person holds. [requiresScope] reads the OAuth `scope` claim, which records how far the
 * application making the call was trusted, and is a separate thing from the container a role is
 * held at. Every requirement a gate names has to hold, so an application delegated a narrow scope
 * reaches less than the person behind it.
 *
 * At least one of the three must name something. Startup fails on a gate that requires nothing.
 *
 * ```yaml
 * gates:
 *   # Someone with the role, through an application delegated the scope.
 *   - path: /admin/&#42;&#42;
 *     method: POST
 *     requires-any: [ "admin:access" ]
 *     requires-scope: [ "admin" ]
 *
 *   # An application calling for itself, with nobody behind it.
 *   - path: /internal/reports/&#42;&#42;
 *     method: GET
 *     requires-scope: [ "reports.read" ]
 * ```
 */
class Gate(

    /**
     * A Spring path pattern, so `/documents/&#42;&#42;` covers every route below `/documents` and
     * `/documents/{id}/approve` covers one.
     */
    var path: String = "",

    /**
     * The HTTP method this gate applies to, such as `POST`. Every method matches when this is
     * absent.
     */
    var method: String? = null,

    /** Permissions of which the caller needs one. */
    var requiresAny: List<String> = emptyList(),

    /** Permissions the caller needs all of. */
    var requiresAll: List<String> = emptyList(),

    /**
     * Values the OAuth `scope` claim needs all of, spelled the way the issuer spells them, which
     * may differ from the way this service spells permissions. A gate naming only this decides
     * from the claim alone, which leaves a route open to an application calling for itself. A
     * token issued to the subject directly carries the unrestricted value and satisfies any scope
     * a gate names, so this restricts applications rather than people.
     */
    var requiresScope: List<String> = emptyList(),
)
