package group.phorus.authz.bdd.steps

import group.phorus.authz.core.evaluation.Authorizer
import io.cucumber.java.en.Given
import io.cucumber.java.en.Then
import io.cucumber.java.en.When
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.core.ParameterizedTypeReference
import org.springframework.http.HttpHeaders
import org.springframework.test.web.reactive.server.EntityExchangeResult
import org.springframework.test.web.reactive.server.WebTestClient

class GatingStepsDefinition {

    @Autowired
    private lateinit var client: WebTestClient

    private var token: String? = null
    private lateinit var result: EntityExchangeResult<ByteArray>

    @Given("no token")
    fun noToken() {
        token = null
    }

    @Given("a token holding the roles {string}")
    fun tokenWithRoles(roles: String) = mint(roles, Authorizer.UNRESTRICTED)

    @Given("a token holding the roles {string} and the scope {string}")
    fun tokenWithRolesAndScope(roles: String, scope: String) = mint(roles, scope)

    private fun mint(roles: String, scope: String) {
        val body = mapOf(
            "roles" to roles.split(",").filter { it.isNotEmpty() },
            "scope" to scope.split(" ").filter { it.isNotEmpty() },
        )

        val minted = client.post()
            .uri("/test/token")
            .bodyValue(body)
            .exchange()
            .expectStatus().isOk
            .expectBody(object : ParameterizedTypeReference<Map<String, String>>() {})
            .returnResult()
            .responseBody

        token = minted?.get("token") ?: error("The mint route answered without a token")
    }

    @When("the caller sends {word} to {string}")
    fun send(method: String, path: String) = send(method, path, emptyMap())

    @When("the caller sends {word} to {string} with the header {string} set to {string}")
    fun sendWithHeader(method: String, path: String, header: String, value: String) =
        send(method, path, mapOf(header to value))

    private fun send(method: String, path: String, headers: Map<String, String>) {
        val request = client.method(org.springframework.http.HttpMethod.valueOf(method)).uri(path)
        token?.let { request.header(HttpHeaders.AUTHORIZATION, "Bearer $it") }
        headers.forEach { (name, value) -> request.header(name, value) }

        result = request.exchange().expectBody().returnResult()
    }

    @Then("the response status is {int}")
    fun statusIs(status: Int) {
        assertEquals(status, result.status.value(), String(result.responseBody ?: ByteArray(0)))
    }

    @Then("the response says {string}")
    fun responseSays(text: String) {
        assertTrue(String(result.responseBody ?: ByteArray(0)).contains(text))
    }

    @Then("the response carries the header {string} saying {string}")
    fun headerSays(header: String, text: String) {
        val value = result.responseHeaders.getFirst(header)

        assertNotNull(value, "No $header header on the response")
        assertTrue(value!!.contains(text), "$header was \"$value\"")
    }
}
