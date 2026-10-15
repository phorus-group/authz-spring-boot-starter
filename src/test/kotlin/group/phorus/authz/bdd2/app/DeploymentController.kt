package group.phorus.authz.bdd2.app

import group.phorus.authn.core.services.TokenFactory
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

/**
 * Routes the deployment feature drives. Under `default-policy: deny` every one of them needs a
 * gate or an ignored path, which is what the feature demonstrates.
 */
@RestController
class DeploymentController(private val tokenFactory: TokenFactory) {

    @PostMapping("/test/token")
    suspend fun token(@RequestBody request: TokenRequest): Map<String, String> {
        val token = tokenFactory.createAccessToken(
            userId = UUID.fromString(request.subjectId),
            claims = mapOf("roles" to request.roles, "scope" to request.scope),
        )

        return mapOf("token" to token.token)
    }

    @GetMapping("/health")
    fun health() = mapOf("status" to "up")

    @GetMapping("/documents/{id}")
    fun read() = mapOf("id" to "doc_1")

    @GetMapping("/unlisted/thing")
    fun unlisted() = mapOf("reached" to "true")

    data class TokenRequest(
        val subjectId: String,
        val roles: List<String> = emptyList(),
        val scope: List<String> = emptyList(),
    )
}
