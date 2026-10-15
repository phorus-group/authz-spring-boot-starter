package group.phorus.authz.filters

import group.phorus.authn.config.Path
import group.phorus.authz.config.Gate
import org.springframework.http.HttpMethod
import org.springframework.http.server.PathContainer
import org.springframework.web.util.pattern.PathPatternParser

/**
 * Whether [gate] applies to a request for [requestPath] made with [requestMethod].
 *
 * The path uses Spring [PathPattern][org.springframework.web.util.pattern.PathPattern] syntax. A
 * gate that leaves the method out applies to every method.
 */
internal fun matchesGate(gate: Gate, requestPath: String, requestMethod: HttpMethod): Boolean =
    matches(gate.path, gate.method, requestPath, requestMethod)

/**
 * Whether any entry of [ignoredPaths] covers a request for [requestPath] made with
 * [requestMethod]. A covered route skips authorization.
 */
internal fun isIgnored(ignoredPaths: List<Path>, requestPath: String, requestMethod: HttpMethod): Boolean =
    ignoredPaths.any { matches(it.path, it.method, requestPath, requestMethod) }

private fun matches(
    pathPattern: String,
    methodConstraint: String?,
    requestPath: String,
    requestMethod: HttpMethod,
): Boolean {
    val pathMatches = parser.parse(pathPattern).matches(PathContainer.parsePath(requestPath))
    return pathMatches && (methodConstraint == null || HttpMethod.valueOf(methodConstraint) == requestMethod)
}

private val parser = PathPatternParser()
