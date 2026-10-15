Feature: Route gating

  A gate refuses a caller before the handler runs. It reads the identity the token filter put on
  the request, so these scenarios go through a real token rather than a stubbed principal.

  Scenario: a caller holding the permission reaches the handler
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends POST to "/documents/doc_1/approve"
    Then the response status is 200

  Scenario: a caller the role falls short of is refused at the gate
    Given a token holding the roles "VIEWER@organization:org_123"
    When the caller sends POST to "/documents/doc_1/approve"
    Then the response status is 403
    And the response says "document:approve"

  Scenario: a request carrying no token is refused
    Given no token
    When the caller sends POST to "/documents/doc_1/approve"
    Then the response status is 401

  Scenario: a route no gate covers is reached without any permission
    Given a token holding the roles "VIEWER@organization:org_123"
    When the caller sends GET to "/documents/doc_1"
    Then the response status is 200

  Scenario: an ignored route is reached with no token at all
    Given no token
    When the caller sends GET to "/health"
    Then the response status is 200

  Scenario: a platform role passes a gate
    Given a token holding the roles "ADMIN"
    When the caller sends POST to "/documents/doc_1/approve"
    Then the response status is 200

  Scenario: a malformed role entry is dropped and the rest still count
    Given a token holding the roles "ADMIN@,ADMIN@organization:org_123"
    When the caller sends POST to "/documents/doc_1/approve"
    Then the response status is 200

  Scenario: the gate passes while the narrower check refuses
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends POST to "/documents/doc_other/approve"
    Then the response status is 403
    And the response says "org_456"

  Scenario: the chain reaches the same answer as the authorizer
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends POST to "/documents/doc_1/publish"
    Then the response status is 200

  Scenario: the chain refuses a document in another organization
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends POST to "/documents/doc_other/publish"
    Then the response status is 403

  Scenario: a gate covering a subtree applies to every route below it
    Given a token holding the roles "VIEWER@organization:org_123"
    When the caller sends GET to "/admin/users"
    Then the response status is 403

  Scenario: a gate covering a subtree lets the right role through
    Given a token holding the roles "SUPPORT@organization:org_123"
    When the caller sends GET to "/admin/users"
    Then the response status is 200

  Scenario: a route gated on scope alone is reached by a caller holding no role
    Given a token holding the roles "" and the scope "reports.read"
    When the caller sends GET to "/internal/reports"
    Then the response status is 200

  Scenario: a route gated on scope refuses a token whose scope falls short
    Given a token holding the roles "ADMIN" and the scope "reports.list"
    When the caller sends GET to "/internal/reports"
    Then the response status is 403
    And the response carries the header "WWW-Authenticate" saying "insufficient_scope"
    And the response carries the header "WWW-Authenticate" saying "scope=\"reports.read\""
    And the response says "insufficient_scope"

  Scenario: a direct login satisfies a gate that names a scope
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends GET to "/internal/reports"
    Then the response status is 200

  Scenario: one of several permissions is enough where a gate names requires-any
    Given a token holding the roles "SUPPORT@organization:org_123"
    When the caller sends GET to "/support/tickets"
    Then the response status is 200

  Scenario: the other of several permissions is also enough
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends GET to "/support/tickets"
    Then the response status is 200

  Scenario: holding neither of them is refused
    Given a token holding the roles "VIEWER@organization:org_123"
    When the caller sends GET to "/support/tickets"
    Then the response status is 403

  Scenario: every permission is needed where a gate names requires-all
    Given a token holding the roles "AUDITOR@organization:org_123,EXPORTER@organization:org_123"
    When the caller sends POST to "/exports/reports"
    Then the response status is 200

  Scenario: holding one of the required permissions is refused
    Given a token holding the roles "AUDITOR@organization:org_123"
    When the caller sends POST to "/exports/reports"
    Then the response status is 403
    And the response says "report:export"

  Scenario: a role granting a star passes every gate
    Given a token holding the roles "OWNER@organization:org_123"
    When the caller sends POST to "/exports/reports"
    Then the response status is 200

  Scenario: creating a resource is decided against the parent container
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends POST to "/organizations/org_123/documents"
    Then the response status is 200

  Scenario: creating in a container the caller holds no role at is refused
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends POST to "/organizations/org_456/documents"
    Then the response status is 403

  Scenario: listing is decided against the container itself
    Given a token holding the roles "VIEWER@organization:org_123"
    When the caller sends GET to "/organizations/org_123/documents"
    Then the response status is 200

  Scenario: listing a container the caller holds no role at is refused
    Given a token holding the roles "VIEWER@organization:org_123"
    When the caller sends GET to "/organizations/org_456/documents"
    Then the response status is 403

  Scenario: authority granted on one named object needs no role
    Given a token holding the roles ""
    When the caller sends POST to "/documents/doc_1/archive" with the header "X-Granted" set to "document/doc_1:archive"
    Then the response status is 200
    And the response says "REBAC"

  Scenario: a grant naming another object does not reach this one
    Given a token holding the roles ""
    When the caller sends POST to "/documents/doc_1/archive" with the header "X-Granted" set to "document/doc_2:archive"
    Then the response status is 403

  Scenario: an attribute policy takes away a decision the roles granted
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends POST to "/documents/doc_1/publish" with the header "X-Frozen" set to "true"
    Then the response status is 403
    And the response says "frozen"

  Scenario: a handler reads the subject off the context without resolving it again
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends GET to "/documents/doc_1/owner"
    Then the response status is 200
    And the response says "organization:org_123"

  Scenario: the context carries every scope a role entry named
    Given a token holding the roles "ADMIN@organization:org_123,VIEWER@project:proj_456"
    When the caller sends GET to "/documents/doc_1/owner"
    Then the response status is 200
    And the response says "project:proj_456"

  Scenario: a route outside every gate still carries the subject on the context
    Given a token holding the roles "ADMIN@organization:org_123"
    When the caller sends GET to "/documents/doc_1"
    Then the response status is 200
