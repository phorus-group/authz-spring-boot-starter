# authz-spring-boot-starter

[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/group.phorus/authz-spring-boot-starter)](https://mvnrepository.com/artifact/group.phorus/authz-spring-boot-starter)
[![codecov](https://codecov.io/gh/phorus-group/authz-spring-boot-starter/branch/main/graph/badge.svg)](https://codecov.io/gh/phorus-group/authz-spring-boot-starter)

Authorization library for Spring Boot WebFlux services. A request arrives carrying the roles its
caller holds and the authority the calling application was delegated. This library reads both,
stops the requests bound to fail before they reach a handler, and provides the check a handler
makes once it knows which object the request is about. Everything that decides a request is built
from the routes you list in configuration, and each piece steps aside for one you declare yourself.

For the framework-agnostic permission model and the checks a handler makes directly, see
[authz-core](https://github.com/phorus-group/authz-core).

### Notes

> The project runs a vulnerability analysis pipeline regularly,
> any found vulnerabilities will be fixed as soon as possible.

> The project dependencies are being regularly updated by [Renovate](https://github.com/phorus-group/renovate).

> The project has been thoroughly tested to ensure that it is safe to use in a production environment.

## Table of contents

- [What a gate decides](#what-a-gate-decides)
- [Getting started](#getting-started)
  - [Installation](#installation)
  - [Quick start](#quick-start)
- [How it works](#how-it-works)
  - [Where the identity is read](#where-the-identity-is-read)
  - [What a role entry looks like](#what-a-role-entry-looks-like)
- [Gating routes](#gating-routes)
  - [Requiring a permission](#requiring-a-permission)
  - [Requiring one of several permissions](#requiring-one-of-several-permissions)
  - [Requiring a scope](#requiring-a-scope)
  - [Letting a route through untouched](#letting-a-route-through-untouched)
  - [Requiring a gate on every route](#requiring-a-gate-on-every-route)
- [Deciding inside a handler](#deciding-inside-a-handler)
  - [Reading the subject](#reading-the-subject)
  - [Checking one object](#checking-one-object)
  - [Checking through the chain](#checking-through-the-chain)
- [Replacing what the starter builds](#replacing-what-the-starter-builds)
  - [Roles from a database](#roles-from-a-database)
  - [A different source of identity](#a-different-source-of-identity)
  - [Adding another authorization model](#adding-another-authorization-model)
- [What the service refuses to start on](#what-the-service-refuses-to-start-on)
- [Configuration reference](#configuration-reference)
- [Building and contributing](#building-and-contributing)
- [Authors and acknowledgment](#authors-and-acknowledgment)

## What a gate decides

A gate is a route and the permissions a caller needs to reach it. It runs before the handler, and
a caller passes where they hold the permission at **any** scope. The object the request concerns
takes no part, so a caller holding the permission over one container passes a gate on a route
about an object in a different one.

For example, where the routes below are gated on `document:approve` and a caller administers only
`organization:org_1`, they pass the gate on both:

```
POST /documents/doc_in_org_1/approve
POST /documents/doc_in_org_2/approve
```

A gate is a filter, and the decision comes later. Once the handler has loaded the object and knows
which container it sits in, it still has to check that the caller holds the permission *there*.
[Deciding inside a handler](#deciding-inside-a-handler) covers that second check, and a route
whose gate is its only check lets a caller reach objects in containers they hold no role at.

## Getting started

### Installation

Make sure that `mavenCentral` (or any of its mirrors) is added to the repository list of the project.

Binaries and dependency information for Maven and Gradle can be found at [http://search.maven.org](https://search.maven.org/search?q=g:group.phorus%20AND%20a:authz-spring-boot-starter).

<details open>
<summary>Gradle / Kotlin DSL</summary>

```kotlin
implementation("group.phorus:authz-spring-boot-starter:x.y.z")
```
</details>

<details open>
<summary>Maven</summary>

```xml
<dependency>
    <groupId>group.phorus</groupId>
    <artifactId>authz-spring-boot-starter</artifactId>
    <version>x.y.z</version>
</dependency>
```
</details>

This starter brings two libraries with it. It reads the authenticated request that
[authn-spring-boot-starter](https://github.com/phorus-group/authn-spring-boot-starter) produces, so
that starter has to be configured and its token filter turned on. It refuses a request by throwing,
and [exception-spring-boot-starter](https://github.com/phorus-group/exception-spring-boot-starter)
turns those throws into 401 and 403 responses. Both arrive as transitive dependencies, so the one
entry above covers all three.

### Quick start

**1. Name your roles and the routes they protect**

```yaml
group:
  phorus:
    security:
      filters:
        token:
          enabled: true

    authz:
      roles:
        ADMIN: [ "document:approve", "document:read" ]
        VIEWER: [ "document:read" ]

      gates:
        - path: /documents/{id}/approve
          method: POST
          requires-any: [ "document:approve" ]
```

A role name is a key and the permissions it grants are the list under it. A check compares a
required permission against that list by name, so the entry `document:approve` grants
`document:approve`. `*` instead grants every permission, and a `*` in either half stands for every
value of that half, so `document:*` grants every action on documents and `*:read` grants reading
every type.

A role name keeps the spelling written here, so `ADMIN` in the configuration matches `ADMIN` in a
token. Write a name holding a dot in square brackets, `"[service.admin]"`, so YAML reads the dot as
part of the name.

**2. Write the handler**

```kotlin
@RestController
class DocumentController(private val documents: DocumentRepository) {

    @PostMapping("/documents/{id}/approve")
    suspend fun approve(@PathVariable id: String): DocumentDTO {
        val document = documents.findById(id) ?: throw NotFound("No document $id")

        return documents.approve(document)
    }
}
```

**3. Send a request**

A caller whose token grants them the `ADMIN` role reaches the handler. A caller granted only
`VIEWER` is answered 403 before the handler runs. A caller sending the request anonymously is
answered 401.

The handler above is incomplete on purpose: it approves whatever document it is given. The gate only
established that this caller may approve *something*.
[Checking one object](#checking-one-object) finishes it.

## How it works

### Where the identity is read

The token filter from the authentication starter validates the bearer token and puts what it found
on the request. This library reads it one step later, at order `HIGHEST_PRECEDENCE + 3` against
that filter's `+ 2`, turns the role entries into the shape a permission check needs, and keeps the
token's delegated scope alongside them.

That reading is one bean, and
[a different source of identity](#a-different-source-of-identity) replaces it.

### What a role entry looks like

Each entry in the token's `roles` claim names a role and, after an `@`, where the caller holds it:

| Entry | Meaning |
|-------|---------|
| `ADMIN@organization:org_123` | The admin role, over that one organization |
| `ADMIN@project:proj_456` | The admin role, over that one project |
| `OWNER` | The owner role, everywhere |

An entry in any other shape is logged at warn level and dropped. One malformed entry therefore costs
the caller that one role while the rest stand, and the warning names the entry so the issuer can be
corrected.

## Gating routes

Every gate names a `path`, written as a
[Spring path pattern](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/util/pattern/PathPattern.html),
so `/documents/{id}/approve` covers one route and `/admin/**` covers everything below `/admin`. A
gate may also name a `method`; leaving it out covers every method.

Where more than one gate matches a request, all of them have to pass, so the order they are written
in changes which refusal is reported and leaves the outcome the same.

### Requiring a permission

```yaml
gates:
  - path: /documents/{id}/approve
    method: POST
    requires-any: [ "document:approve" ]
```

### Requiring one of several permissions

`requires-any` passes a caller holding at least one of the listed permissions. `requires-all` passes
only a caller holding every one of them. A gate may name both, and then both have to hold.

```yaml
gates:
  # Either permission gets in.
  - path: /admin/**
    requires-any: [ "admin:access", "support:access" ]

  # Both are needed.
  - path: /exports/**
    method: POST
    requires-all: [ "report:read", "report:export" ]
```

### Requiring a scope

Two separate things are called scope around this library, and this key means the second of them.
One is the container a role is held at, such as an organization or a project, which
[authz-core](https://github.com/phorus-group/authz-core) spells `Scope` and this starter reads out
of a role entry. The other is the OAuth `scope` claim, which records how far the application making
the call was trusted. The two are independent, and `requires-scope` reads the claim.

The two previous keys read the roles the person holds. `requires-scope` reads the authority the
application calling on their behalf was delegated, taken from the token's `scope` claim as defined
by [RFC 6749 §3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3). Every value listed
has to be present.

The two kinds of requirement are combined with and. An application granted a narrow scope
therefore reaches less than the person behind it.

A request the person makes directly, with no application in between, carries
`Authorizer.UNRESTRICTED` as its only scope value and satisfies any scope a gate names. Adding
this key to a route therefore leaves your own sign-in untouched.

```yaml
gates:
  # A person, through an application trusted with this much of their account.
  - path: /documents/**
    method: POST
    requires-any: [ "document:approve" ]
    requires-scope: [ "documents.write" ]

  # An application calling for itself, with nobody behind it.
  - path: /internal/reports/**
    method: GET
    requires-scope: [ "reports.read" ]
```

Scope values are written the way the issuer writes them. A gate compares them literally against the
claim, so an issuer spelling scopes as `Reports.Read` or `https://api.example.com/reports.read`
keeps that spelling here.

A gate naming only `requires-scope` decides from the claim alone. That is the second example above,
and it is how a route stays open to a client-credentials caller, which carries scope and acts for
itself.

A refusal caused by scope is answered differently from one caused by roles, following
[RFC 6750 §3.1](https://datatracker.ietf.org/doc/html/rfc6750#section-3.1):

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="documents.write"
```

The header names what was missing, so the calling application can request a token from its issuer
that reaches the route. The refusal also carries `insufficient_scope` as its error code, which
`exception-spring-boot-starter` puts in the response body. A role refusal leaves both off, since
the fix there belongs to whoever grants roles.

### Letting a route through untouched

A route outside every gate reaches its handler. To keep a route reachable as the rules change
around it, name it:

```yaml
group.phorus.authz:
  ignored-paths:
    - path: /health
    - path: /docs/**
```

An ignored route reaches its handler before any gate or policy is considered, so it stays open
under the policy below as well.

Under `default-policy: deny` an entry here has to name a route the token filter also lets through.
Skipping authorization while still demanding a token leaves a route open to everyone holding any
valid token, and closed to the caller holding a credential of its own, such as a webhook signature.
The service refuses to start on that pairing. A route meant for every authenticated caller belongs
in a gate naming a permission they all hold, which says so where a reader can see it.

The token filter lets a route through when it is switched off, when the route sits in its own
`ignored-paths`, and when it runs on a `protected-paths` list naming other routes. Its
`refresh-token-path` passes as well, since the filter accepts a refresh token on that path alone,
which is a credential belonging to that route.

### Requiring a gate on every route

By default a route outside every gate is allowed, which lets you protect routes one at a time. The
opposite policy refuses every route the gates leave out:

```yaml
group.phorus.authz:
  default-policy: deny
```

Under this policy every reachable route needs either a gate or an entry in `ignored-paths`. A new
route added by a colleague who skipped this file returns 403 until someone decides what it
requires.

## Deciding inside a handler

### Reading the subject

The filter resolves the subject once per request and puts it on `AuthorizationContext`, so a
handler reads it with nothing injected:

```kotlin
val principal = AuthorizationContext.context.get() ?: throw Unauthorized("No identity")
```

That mirrors `AuthenticationContext` from the authentication starter, which carries the token's
claims. This one carries the `Principal` those claims were parsed into.

The value is there on every request the filter ran on. Declare `PrincipalResolver` and call
`resolve()` instead where the filter is turned off, or where the subject is wanted outside a
request:

```kotlin
val principal = principals.resolve() ?: throw Unauthorized("No identity")
```

The examples below inject `PrincipalResolver`, so they read the same either way.

### Checking one object

The Kotlin type named `Scope` below is a place a role is held at, a resource type together with one
identifier. It is a separate thing from the `scope` claim a gate reads, and a parameter named
`scopes` always means the first.

Inject `Authorizer` and `PrincipalResolver`, and check once the object has been loaded and its
containers are known:

```kotlin
@RestController
class DocumentController(
    private val documents: DocumentRepository,
    private val principals: PrincipalResolver,
    private val authorizer: Authorizer,
) {

    @PostMapping("/documents/{id}/approve")
    suspend fun approve(@PathVariable id: String): DocumentDTO {
        val principal = principals.resolve() ?: throw Unauthorized("No identity on this request")
        val document = documents.findById(id) ?: throw NotFound("No document $id")

        val containers = listOf(
            Scope("organization", document.organizationId),
            Scope("project", document.projectId),
        )

        if (!authorizer.permits(principal, "document:approve", containers)) {
            throw NotFound("No document $id")
        }

        return documents.approve(document)
    }
}
```

The list is the chain of containers the document sits inside, outermost first. Both halves of a
`Scope` are strings, so an identifier your service holds as a `UUID` needs `toString()` here. The
caller passes where any role they hold at any of those containers grants `document:approve`, and
also where they hold such a role platform-wide, which is the scope a role entry carrying no `@`
lands at.

Returning 404 in place of 403 here hides the document's existence from a caller barred from reading
it. That is a choice about this route rather than a rule. Where the caller may already read the
document and only the stronger action is refused, 403 tells them which permission they lack and
reveals only what they could see anyway.

### Checking through the chain

`AuthorizationChain` runs the same check through every authorization model the service has, where
the call above reads roles alone. It is the call to make where another model might contribute, and
the one to keep while roles are the only model, since adding one later then leaves every handler
unchanged:

```kotlin
@RestController
class DocumentController(
    private val documents: DocumentRepository,
    private val principals: PrincipalResolver,
    private val chain: AuthorizationChain,
) {

    @PostMapping("/documents/{id}/approve")
    suspend fun approve(@PathVariable id: String): DocumentDTO {
        val principal = principals.resolve() ?: throw Unauthorized("No identity on this request")
        val document = documents.findById(id) ?: throw NotFound("No document $id")

        val containers = listOf(
            Scope("organization", document.organizationId),
            Scope("project", document.projectId),
        )

        val decision = chain.evaluate(
            EvaluationContext(
                principal = principal,
                requiredPermission = Permission.parse(
                    "organization/${document.organizationId}/document/$id:approve",
                ),
                scopes = containers,
            ),
        )

        if (!decision.allowed) throw Forbidden(decision.reason ?: "Not permitted to approve $id")

        return documents.approve(document)
    }
}
```

The required permission is spelled out in full here, as a path of types and identifiers followed by
the action. A role evaluator reads the last type and the action back out of it, so
`organization/org_1/document/doc_1:approve` reaches the same `document:approve` entry a gate
reaches, while another model in the chain can read the whole path.

Everything a check varies by travels in the context, so a single chain instance serves every
request the service handles.

Gates read roles directly and leave the chain aside, so a model added later constrains what your
handlers decide and leaves your gates as they were.

## Replacing what the starter builds

The starter creates every bean below, and each one steps aside for a bean of the same type the
application declares.

| Bean | What it does |
|------|--------------|
| `RoleCatalog` | Returns the permissions a role grants. Built from the `roles` property |
| `Authorizer` | Returns `true` where a subject holds a permission over a chain of containers |
| `ScopedRoleEvaluator` | The role model, as one evaluator the chain can hold |
| `AuthorizationChain` | Every evaluator in the context, arranged by the model each reports |
| `PrincipalResolver` | Reads the subject out of the authenticated request |
| `RouteAuthorizationFilter` | Enforces the gates |

An `AuthorizationEvaluator` the application declares adds to the chain rather than replacing what
is there. An evaluator reporting `AuthZSource.RBAC` is the exception and takes
`ScopedRoleEvaluator`'s place, since two role evaluators would leave the more permissive of the
pair deciding.

### Roles from a database

The `roles` property is one source of role definitions. Declare a `RoleCatalog` to read them from
wherever a product team edits them:

```kotlin
@Bean
fun roleCatalog(roles: RoleDefinitionRepository) = object : RoleCatalog {
    override fun permissions(role: RoleName): Set<String> = roles.permissionsOf(role.value)
}
```

Leave the `roles` property out entirely when you do this. Everything else is unchanged.

### A different source of identity

Declare a `PrincipalResolver` to decide the subject and its roles differently, for instance by
reading a role assignment table where the token carries the subject alone:

```kotlin
@Bean
fun principalResolver(assignments: RoleAssignmentRepository) = PrincipalResolver {
    AuthenticationContext.context.get()?.let { authenticated ->
        Principal(
            subjectId = authenticated.userId,
            roles = assignments.rolesOf(authenticated.userId),
            scope = authenticated.scope,
        )
    }
}
```

This is the bean to replace when roles live outside the token. `RoleCatalog` maps a role to
permissions; `PrincipalResolver` maps a request to a subject and the roles it holds.

### Adding another authorization model

Declare an `AuthorizationEvaluator` and the chain picks it up. The `source` it reports decides
where it lands:

| `source` | The model | Where it runs | What it can do |
|----------|-----------|---------------|----------------|
| `AuthZSource.RBAC` | Roles | First, in this order | The first allow among the three ends the search, and any of them can refuse outright |
| `AuthZSource.IMPLICIT` | What every authenticated caller may do | Second | As above |
| `AuthZSource.REBAC` | Relationships such as ownership | Third | As above |
| `AuthZSource.ABAC` | Attributes such as the time of day | After a grant | Any refusal overrides the grant |
| `AuthZSource.GRANT` | A standing grant recorded elsewhere | Last | Consulted where every phase above abstained |

```kotlin
private val workingHours = LocalTime.of(9, 0)..LocalTime.of(18, 0)

@Bean
fun workingHoursPolicy() = object : AuthorizationEvaluator {
    override val source = AuthZSource.ABAC

    override suspend fun evaluate(context: EvaluationContext) =
        if (LocalTime.now() in workingHours) AuthZResult.abstain()
        else AuthZResult.denied(reason = "Outside working hours", source = source)
}
```

An attribute policy takes a decision away and leaves the granting to the phase above it. An
attribute model standing alone therefore refuses every request.

A granting evaluator can refuse outright as well, and that refusal is final: it returns straight
away and the constraint phase never runs. An evaluator that abstains instead leaves the next one
free to decide, which is what the role evaluator does where the roles fall short.

## What the service refuses to start on

Each of these stops the context from starting, so the configuration is corrected before a request
reaches it:

| Configuration | Why it stops the service |
|---------------|-------------------|
| A gate requiring nothing | It reads as a restriction while leaving the route open |
| A gate with no path | The routes it covers stay unstated |
| A gate naming a blank permission | It matches no catalogue entry |
| A gate naming a blank scope | It matches no value of the claim |
| A method outside the standard HTTP methods | It matches zero requests |
| A method written in lower case | Same reason: the comparison is exact |
| A scope value containing a space | RFC 6749 separates scope values with spaces, so this is two written as one |
| Gates configured while the token filter is off | Requests arrive anonymous, so every gated route returns 401 |
| An `ignored-paths` entry the token filter still demands a token for, under `default-policy: deny` | The route is then open to everyone holding any valid token, and closed to the caller holding a credential of its own |

## Configuration reference

| Property | Default | Description |
|----------|---------|-------------|
| `group.phorus.authz.enabled` | `true` | Setting it to `false` creates none of the beans below and leaves every request to its handler |
| `group.phorus.authz.default-policy` | `allow` | What happens to a request outside every gate: `allow` or `deny` |
| `group.phorus.authz.roles` | empty | The permissions each role grants, keyed by role name. An entry of `*` grants every permission, and a `*` in either half stands for every value of that half, so `document:*` grants every action on documents and `*:read` grants reading every type |
| `group.phorus.authz.gates` | empty | The routes that require something. See below |
| `group.phorus.authz.ignored-paths` | empty | Routes that skip authorization entirely |

Each entry under `gates`:

| Property | Default | Description |
|----------|---------|-------------|
| `path` | required | A Spring path pattern |
| `method` | every method | One of the standard HTTP methods, upper case |
| `requires-any` | empty | Permissions of which the caller needs one |
| `requires-all` | empty | Permissions the caller needs all of |
| `requires-scope` | empty | Values the token's `scope` claim needs all of |

Each entry under `ignored-paths` takes `path` and an optional `method`, matching the authentication
starter's path lists.

A token issued to the subject directly carries `Authorizer.UNRESTRICTED` in its `scope` claim and
satisfies any `requires-scope` a gate names, so the key restricts applications rather than people.

## Building and contributing

See [Contributing Guidelines](CONTRIBUTING.md).

## Authors and acknowledgment

Developed and maintained by the [Phorus Group](https://phorus.group) team.
