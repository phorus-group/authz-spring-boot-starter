package group.phorus.authz.bdd2

import group.phorus.authz.bdd2.app.DeploymentApp
import io.cucumber.spring.CucumberContextConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient
import org.springframework.test.context.ActiveProfiles

@SpringBootTest(classes = [DeploymentApp::class])
@CucumberContextConfiguration
@AutoConfigureWebTestClient(timeout = "30000")
@ActiveProfiles("deployment")
class CucumberSpringConfiguration
