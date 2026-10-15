package group.phorus.authz.bdd

import group.phorus.authz.bdd.app.TestApp
import io.cucumber.spring.CucumberContextConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient
import org.springframework.test.context.ActiveProfiles

@SpringBootTest(classes = [TestApp::class])
@CucumberContextConfiguration
@AutoConfigureWebTestClient(timeout = "30000")
@ActiveProfiles("test")
class CucumberSpringConfiguration
