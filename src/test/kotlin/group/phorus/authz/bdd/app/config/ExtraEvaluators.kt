package group.phorus.authz.bdd.app.config

import group.phorus.authz.core.evaluation.AuthorizationEvaluator
import group.phorus.authz.core.evaluation.PermissionMatcher
import group.phorus.authz.core.model.AuthZResult
import group.phorus.authz.core.model.AuthZSource
import group.phorus.authz.core.model.EvaluationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * The two models a service adds beside roles, declared the way the README declares them.
 */
@Configuration
class ExtraEvaluators {

    /**
     * Authority recorded against one named object, held as permission strings that already name
     * it. Joins the granting phase because its source says so.
     */
    @Bean
    fun heldPermissionEvaluator() = object : AuthorizationEvaluator {
        override val source = AuthZSource.REBAC

        override suspend fun evaluate(context: EvaluationContext): AuthZResult {
            val matched = PermissionMatcher.findMatch(context.permissions, context.requiredPermission)

            return if (matched != null) AuthZResult.allowed(source, matched) else AuthZResult.abstain()
        }
    }

    /**
     * A rule that takes a decision away once something has granted it. Abstains unless the request
     * carries the attribute, so every other scenario is left alone.
     */
    @Bean
    fun frozenDocumentPolicy() = object : AuthorizationEvaluator {
        override val source = AuthZSource.ABAC

        override suspend fun evaluate(context: EvaluationContext): AuthZResult =
            if (context.attributes["document.frozen"] == true) {
                AuthZResult.denied(reason = "The document is frozen", source = source)
            } else {
                AuthZResult.abstain()
            }
    }
}
