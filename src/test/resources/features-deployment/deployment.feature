Feature: Deployment choices

  A service can refuse every route it has not named, and can decide roles for itself rather than
  from configuration and the token. These need their own application, so they sit apart from the
  route gating feature.

  The roles here come from a role assignment table rather than the token's roles claim, and what
  each role grants comes from a role definition table rather than the roles property.

  Scenario: a route with a gate is reached by a caller the table gives the role to
    Given the role assignment table gives the subject "SUPERVISOR" at "organization:org_123"
    When the caller sends GET to "/documents/doc_1"
    Then the response status is 200

  Scenario: a caller the table gives no role to is refused
    Given the subject has no row in the role assignment table
    When the caller sends GET to "/documents/doc_1"
    Then the response status is 403

  Scenario: a route no gate names is refused under the deny policy
    Given the role assignment table gives the subject "SUPERVISOR" at "organization:org_123"
    When the caller sends GET to "/unlisted/thing"
    Then the response status is 403

  Scenario: an ignored route stays reachable under the deny policy
    Given no token
    When the caller sends GET to "/health"
    Then the response status is 200

  Scenario: a permission added to the definition table applies without a new token
    Given the role assignment table gives the subject "SUPERVISOR" at "organization:org_123"
    And the role definition table grants "SUPERVISOR" the permission "document:publish"
    When the caller sends GET to "/documents/doc_1"
    Then the response status is 200
