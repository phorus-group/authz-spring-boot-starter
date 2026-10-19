import com.kageiit.jacobo.JacoboTask
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.springframework.boot.gradle.tasks.bundling.BootJar
import java.net.URI
import java.time.LocalDate

plugins {
    id("org.springframework.boot") version "4.0.7"
    id("io.spring.dependency-management") version "1.1.7"
    kotlin("plugin.spring") version "2.3.10"
    kotlin("jvm") version "2.3.10"
    kotlin("kapt") version "2.3.10"
    id("org.jetbrains.dokka").version("2.1.0")
    id("com.vanniktech.maven.publish") version "0.34.0"
    id("com.kageiit.jacobo") version "2.1.0"
    jacoco
}

ext["jackson-2-bom.version"] = "2.21.7"
ext["jackson-bom.version"] = "3.1.7"
ext["logback.version"] = "1.5.34"
ext["log4j2.version"] = "2.25.5"
ext["spring-framework.version"] = "7.0.9"
ext["netty.version"] = "4.2.17.Final"

group = "group.phorus"
description = "Spring Boot starter that gates routes on roles and token scope, and builds an authz principal from the authenticated request."
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
}

repositories {
    mavenCentral()
}

dependencies {
    // Phorus
    api("group.phorus:authz-core:1.0.2")
    api("group.phorus:authn-spring-boot-starter:2.0.1")
    api("group.phorus:exception-spring-boot-starter:1.1.2")

    // Spring
    kapt("org.springframework.boot:spring-boot-configuration-processor")
    implementation("org.springframework.boot:spring-boot-starter-webflux")

    // Kotlin
    implementation(kotlin("stdlib-jdk8"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")

    // Test
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-webtestclient")
    testImplementation("group.phorus:test-commons:1.1.10")
    testImplementation(kotlin("reflect"))
}

// Bouncy Castle arrives through the token libraries, micrometer through the metrics the
// authentication starter records, and jsoup and freemarker through Dokka's HTML generator. Jetty
// is pinned in the sibling build for WireMock and reaches no configuration here.
configurations.configureEach {
    resolutionStrategy.eachDependency {
        // CVE-2026-8763 (CRITICAL), CVE-2026-3505 (HIGH), CVE-2026-13506 (HIGH),
        // CVE-2026-5588 (MEDIUM), CVE-2026-0636 (MEDIUM)
        if (requested.group == "org.bouncycastle") {
            useVersion("1.85")
        }

        // CVE-2026-40983 (HIGH), CVE-2026-40984 (HIGH)
        if (requested.group == "io.micrometer" &&
            requested.name in listOf(
                "micrometer-core",
                "micrometer-commons",
                "micrometer-observation",
                "micrometer-registry-prometheus",
            )
        ) {
            useVersion("1.16.6")
        }

        // CVE-2026-84939 (CRITICAL)
        if (requested.group == "org.freemarker") {
            useVersion("2.3.35")
        }

        // CVE-2026-75140 (HIGH), CVE-2026-71497 (MEDIUM)
        if (requested.group == "org.jsoup") {
            useVersion("1.23.2")
        }
    }
}

val repoUrl = System.getenv("GITHUB_REPOSITORY")?.let { "https://github.com/$it" }
    ?: "https://github.com/phorus-group/authz-spring-boot-starter"

tasks {
    getByName<BootJar>("bootJar") {
        enabled = false
    }

    // Jacoco config
    jacocoTestReport {
        executionData.setFrom(fileTree(project.layout.buildDirectory).include("/jacoco/*.exec"))

        classDirectories.setFrom(
            sourceSets.main.get().output.classesDirs.map { dir ->
                fileTree(dir).exclude(
                    "**/model/**",
                    "**/dtos/**",
                    "**/config/**",
                    "**/repositories/**",
                    "**/*Application*",
                )
            }
        )


        reports {
            xml.required.set(true)
            csv.required.set(true)
        }

        finalizedBy("jacobo")
    }

    withType<Test> {
        useJUnitPlatform()

        finalizedBy(jacocoTestReport)

        // If parallel tests start failing, instead of disabling this, take a look at @Execution(ExecutionMode.SAME_THREAD)
        systemProperty("junit.jupiter.execution.parallel.enabled", "true")
        systemProperty("junit.jupiter.execution.parallel.mode.default", "same_thread")
        systemProperty("junit.jupiter.execution.parallel.mode.classes.default", "concurrent")

        finalizedBy(jacocoTestReport)
    }

    register<JacoboTask>("jacobo") {
        description = "Transforms jacoco xml report to cobertura"
        group = "verification"

        jacocoReport = file("${layout.buildDirectory.asFile.get()}/reports/jacoco/test/jacocoTestReport.xml")
        coberturaReport = file("${layout.buildDirectory.asFile.get()}/reports/cobertura/cobertura.xml")
        includeFileNames = emptySet()

        val field = JacoboTask::class.java.getDeclaredField("srcDirs")
        field.isAccessible = true
        field.set(this, sourceSets["main"].allSource.srcDirs.map { it.path }.toTypedArray())

        dependsOn(jacocoTestReport)
    }

    withType<KotlinCompile> {
        compilerOptions {
            freeCompilerArgs = listOf("-Xjsr305=strict")
            jvmTarget.set(JvmTarget.fromTarget(java.targetCompatibility.toString()))
        }
    }

    dokka {
        val branch = System.getenv("GITHUB_REF_NAME") ?: "main"
        val currentYear = LocalDate.now().year

        dokkaPublications.html {
            outputDirectory.set(layout.buildDirectory.dir("dokka/html"))
        }

        dokkaSourceSets.configureEach {
            reportUndocumented.set(true)
            jdkVersion.set(java.targetCompatibility.majorVersion.toInt())
            sourceRoots.from(file("src"))

            sourceLink {
                localDirectory.set(file("src/main/kotlin"))
                remoteUrl.set(URI("$repoUrl/tree/$branch/src/main/kotlin"))
                remoteLineSuffix.set("#L")
            }
        }

        pluginsConfiguration.html {
            footerMessage.set("© $currentYear Phorus Group - Licensed under the <a target=\"_blank\" href=\"$repoUrl/blob/$branch/LICENSE\">Apache 2 license</a>.")
        }
    }
}

afterEvaluate {
    tasks.named("generateMetadataFileForMavenPublication") {
        dependsOn("dokkaJavadocJar")
    }
}


mavenPublishing {
    coordinates(
        groupId = project.group.toString(),
        artifactId = project.name,
        version = project.version.toString()
    )

    pom {
        name.set(project.name)
        description.set(project.description ?: "")
        url.set(repoUrl)

        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }

        developers {
            developer {
                id.set("irios.phorus")
                name.set("Martin Rios")
                email.set("irios@phorus.group")
                organization.set("Phorus Group")
                organizationUrl.set("https://phorus.group")
            }
        }

        scm {
            url.set(repoUrl)
            connection.set("scm:git:$repoUrl.git")
            developerConnection.set("scm:git:$repoUrl.git")
        }
    }

    publishToMavenCentral(automaticRelease = true)
    signAllPublications()
}
