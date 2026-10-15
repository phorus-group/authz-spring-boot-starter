package group.phorus.authz.bdd2.steps

import group.phorus.authz.bdd2.app.RoleAssignmentTable
import group.phorus.authz.bdd2.app.RoleDefinitionTable
import group.phorus.authz.core.model.RoleName
import group.phorus.authz.core.model.Scope
import io.cucumber.java.en.Given
import io.cucumber.java.en.Then
import io.cucumber.java.en.When
import org.junit.jupiter.api.Assertions.assertEquals
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.core.ParameterizedTypeReference
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.test.web.reactive.server.EntityExchangeResult
import org.springframework.test.web.reactive.server.WebTestClient
import java.util.UUID

class DeploymentStepsDefinition {

    @Autowired
    private lateinit var client: WebTestClient

    @Autowired
    private lateinit var definitions: RoleDefinitionTable

    @Autowired
    private lateinit var assignments: RoleAssignmentTable

    private val subject = UUID.fromString("00000000-0000-0000-0000-0000000000aa")
    private var token: String? = null
    private lateinit var result: EntityExchangeResult<ByteArray>

    @Given("no token")
    fun noToken() {
        token = null
    }

    @Given("the role assignment table gives the subject {string} at {string}")
    fun assignRole(role: String, scope: String) {
        assignments.assignments[subject.toString()] =
            mapOf(Scope.parseOrNull(scope)!! to setOf(RoleName(role)))
        mint()
    }

    @Given("the subject has no row in the role assignment table")
    fun noAssignment() {
        assignments.assignments.remove(subject.toString())
        mint()
    }

    @Given("the role definition table grants {string} the permission {string}")
    fun grantPermission(role: String, permission: String) {
        definitions.grant(role, permission)
    }

    private fun mint() {
        val minted = client.post()
            .uri("/test/token")
            // the token carries no roles claim, so only the assignment table can supply them
            .bodyValue(mapOf("subjectId" to subject.toString(), "roles" to emptyList<String>(), "scope" to emptyList<String>()))
            .exchange()
            .expectStatus().isOk
            .expectBody(object : ParameterizedTypeReference<Map<String, String>>() {})
            .returnResult()
            .responseBody

        token = minted?.get("token") ?: error("The mint route answered without a token")
    }

    @When("the caller sends {word} to {string}")
    fun send(method: String, path: String) {
        val request = client.method(HttpMethod.valueOf(method)).uri(path)
        token?.let { request.header(HttpHeaders.AUTHORIZATION, "Bearer $it") }

        result = request.exchange().expectBody().returnResult()
    }

    @Then("the response status is {int}")
    fun statusIs(status: Int) {
        assertEquals(status, result.status.value(), String(result.responseBody ?: ByteArray(0)))
    }
}
