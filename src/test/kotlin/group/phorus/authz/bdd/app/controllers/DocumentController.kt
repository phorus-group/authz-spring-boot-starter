package group.phorus.authz.bdd.app.controllers

import group.phorus.authn.core.services.TokenFactory
import group.phorus.authz.PrincipalResolver
import group.phorus.authz.context.AuthorizationContext
import group.phorus.authz.core.evaluation.AuthorizationChain
import group.phorus.authz.core.evaluation.Authorizer
import group.phorus.authz.core.model.EvaluationContext
import group.phorus.authz.core.model.Permission
import group.phorus.authz.core.model.Scope
import group.phorus.exception.core.Forbidden
import group.phorus.exception.core.Unauthorized
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

/**
 * Routes the gating feature drives.
 *
 * Which organization a document belongs to is known only here, after the row is loaded, which is
 * what the narrower checks below stand in for.
 */
@RestController
class DocumentController(
    private val tokenFactory: TokenFactory,
    private val principalResolver: PrincipalResolver,
    private val authorizer: Authorizer,
    private val chain: AuthorizationChain,
) {

    /** Mints a token holding the claims a scenario asks for. */
    @PostMapping("/test/token")
    suspend fun token(@RequestBody request: TokenRequest): Map<String, String> {
        val token = tokenFactory.createAccessToken(
            userId = UUID.randomUUID(),
            claims = mapOf("roles" to request.roles, "scope" to request.scope),
        )

        return mapOf("token" to token.token)
    }

    @GetMapping("/health")
    fun health() = mapOf("status" to "up")

    @GetMapping("/documents/{id}")
    fun read(@PathVariable id: String) = mapOf("id" to id)

    /** Passing the gate is not the decision, so this asks again now the organization is known. */
    @PostMapping("/documents/{id}/approve")
    fun approve(@PathVariable id: String): Map<String, String> {
        val principal = principalResolver.resolve() ?: throw Unauthorized("No identity")
        val organization = organizationOf(id)

        if (!authorizer.permits(principal, "document:approve", listOf(organization))) {
            throw Forbidden("Not permitted to approve $id in $organization")
        }

        return mapOf("id" to id, "approved" to "true")
    }

    /** The same narrower question, asked through the chain rather than the authorizer. */
    @PostMapping("/documents/{id}/publish")
    suspend fun publish(
        @PathVariable id: String,
        @RequestHeader("X-Frozen", required = false) frozen: Boolean = false,
    ): Map<String, String> {
        val principal = principalResolver.resolve() ?: throw Unauthorized("No identity")
        val organization = organizationOf(id)

        val result = chain.evaluate(
            EvaluationContext(
                principal = principal,
                requiredPermission = Permission.parse("organization/${organization.id}/document/$id:publish"),
                scopes = listOf(organization),
                attributes = mapOf("document.frozen" to frozen),
            ),
        )

        if (!result.allowed) throw Forbidden(result.reason ?: "Not permitted to publish $id")

        return mapOf("id" to id, "published" to "true")
    }

    @GetMapping("/admin/users")
    fun users() = listOf(mapOf("id" to "user_1"))

    @GetMapping("/internal/reports")
    fun reports() = listOf(mapOf("id" to "report_1"))

    /** Reads the subject off the context rather than resolving it again. */
    @GetMapping("/documents/{id}/owner")
    fun owner(@PathVariable id: String): Map<String, String> {
        val principal = AuthorizationContext.context.get() ?: throw Unauthorized("No identity")

        return mapOf(
            "id" to id,
            "subject" to principal.subjectId.toString(),
            "scopes" to principal.roles.keys.joinToString(",") { it.toString() },
        )
    }

    @GetMapping("/support/tickets")
    fun tickets() = listOf(mapOf("id" to "ticket_1"))

    @PostMapping("/exports/reports")
    fun exportReports() = mapOf("exported" to "true")

    /**
     * Creating a resource takes the parent's chain, because the resource has no identifier of its
     * own until it exists.
     */
    @PostMapping("/organizations/{organizationId}/documents")
    fun create(@PathVariable organizationId: String): Map<String, String> {
        val principal = principalResolver.resolve() ?: throw Unauthorized("No identity")
        val parent = Scope("organization", organizationId)

        if (!authorizer.permits(principal, "document:create", listOf(parent))) {
            throw Forbidden("Not permitted to create a document in $organizationId")
        }

        return mapOf("organizationId" to organizationId, "created" to "true")
    }

    /**
     * Listing takes the container itself as the chain, so the answer is whether the caller may read
     * that kind of thing inside it.
     */
    @GetMapping("/organizations/{organizationId}/documents")
    fun list(@PathVariable organizationId: String): List<Map<String, String>> {
        val principal = principalResolver.resolve() ?: throw Unauthorized("No identity")
        val container = Scope("organization", organizationId)

        if (!authorizer.permits(principal, "document:read", listOf(container))) {
            throw Forbidden("Not permitted to list documents in $organizationId")
        }

        return listOf(mapOf("id" to "doc_1"))
    }

    /**
     * Authority recorded against one named object arrives as permission strings that already name
     * it, so the chain compares two strings and takes no container chain.
     */
    @PostMapping("/documents/{id}/archive")
    suspend fun archive(@PathVariable id: String, @RequestHeader("X-Granted", required = false) granted: String?): Map<String, String> {
        val principal = principalResolver.resolve() ?: throw Unauthorized("No identity")

        val result = chain.evaluate(
            EvaluationContext(
                principal = principal,
                requiredPermission = Permission.parse("document/$id:archive"),
                permissions = granted?.split(" ").orEmpty(),
            ),
        )

        if (!result.allowed) throw Forbidden(result.reason ?: "Not permitted to archive $id")

        return mapOf("id" to id, "archived" to "true", "source" to result.source.toString())
    }

    /** A document whose identifier ends in `_other` sits in a second organization. */
    private fun organizationOf(id: String): Scope =
        if (id.endsWith("_other")) Scope("organization", "org_456") else Scope("organization", "org_123")

    data class TokenRequest(
        val roles: List<String> = emptyList(),
        val scope: List<String> = emptyList(),
    )
}
