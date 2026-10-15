package group.phorus.authz.bdd2

import io.cucumber.junit.platform.engine.Constants.GLUE_PROPERTY_NAME
import org.junit.platform.suite.api.ConfigurationParameter
import org.junit.platform.suite.api.IncludeEngines
import org.junit.platform.suite.api.SelectClasspathResource
import org.junit.platform.suite.api.Suite

@Suite
@IncludeEngines("cucumber")
@SelectClasspathResource("features-deployment")
@ConfigurationParameter(key = GLUE_PROPERTY_NAME, value = "group.phorus.authz.bdd2")
internal class DeploymentIntegrationTest
