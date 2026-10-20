package com.strykerx.lab.scanner.web

import com.strykerx.lab.core.common.Severity

/**
 * Cherlogons' OWN web signature database — an original, clean-room catalogue of
 * well-known risky paths/files/endpoints and how to recognize them. It is NOT
 * copied from any other scanner's database (those are separately licensed); it is
 * written from general security knowledge and freely-licensed path lists
 * (e.g. SecLists, MIT). The matching model (status / body marker / header) is a
 * common technique, implemented here independently.
 */
object WebSignatures {

    enum class Cat(val label: String) {
        SENSITIVE_FILE("Sensitive file"),
        BACKUP("Backup / dump"),
        VCS("Version-control metadata"),
        CI_CONFIG("CI / build config"),
        SECRET("Secret / credentials file"),
        INFO("Information disclosure"),
        DEBUG("Debug / management endpoint"),
        CGI("CGI / script"),
        ADMIN("Admin console"),
        DEFAULT("Default / example content")
    }

    sealed interface Match {
        data class Code(val code: Int) : Match
        data class Body(val needle: String) : Match             // 200 + body contains needle
        data class CodeAndBody(val code: Int, val needle: String) : Match
        data class Header(val name: String, val needle: String) : Match
    }

    data class Sig(
        val path: String,
        val label: String,
        val cat: Cat,
        val severity: Severity,
        val match: Match,
        val cgiDir: Boolean = false
    )

    /** CGI directories a @cgi signature is expanded across. */
    val CGI_DIRS = listOf("/cgi-bin/", "/cgi/", "/scripts/", "/cgi-bin/cgi-bin/")

    private fun c(path: String, label: String, cat: Cat, sev: Severity, code: Int = 200) =
        Sig(path, label, cat, sev, Match.Code(code))

    private fun b(path: String, label: String, cat: Cat, sev: Severity, needle: String) =
        Sig(path, label, cat, sev, Match.CodeAndBody(200, needle))

    private fun cgi(name: String, label: String, sev: Severity, needle: String? = null) =
        Sig(name, label, Cat.CGI, sev, if (needle != null) Match.CodeAndBody(200, needle) else Match.Code(200), cgiDir = true)

    val ALL: List<Sig> = listOf(
        // --- Secret / credential files ---
        b("/.env", "Environment file (.env) exposed", Cat.SECRET, Severity.HIGH, "="),
        c("/.env.local", "Local environment file exposed", Cat.SECRET, Severity.HIGH),
        c("/.env.production", "Production environment file exposed", Cat.SECRET, Severity.HIGH),
        b("/config/database.yml", "Rails database config (credentials)", Cat.SECRET, Severity.HIGH, "adapter"),
        b("/config/secrets.yml", "Rails secrets file", Cat.SECRET, Severity.HIGH, "secret"),
        b("/application.yml", "Spring application.yml (may hold secrets)", Cat.SECRET, Severity.MEDIUM, ":"),
        b("/application.properties", "Spring properties (may hold secrets)", Cat.SECRET, Severity.MEDIUM, "="),
        b("/appsettings.json", "ASP.NET Core appsettings.json", Cat.SECRET, Severity.MEDIUM, "{"),
        c("/.npmrc", "npm config (.npmrc) — may hold auth tokens", Cat.SECRET, Severity.MEDIUM),
        c("/.aws/credentials", "AWS credentials file", Cat.SECRET, Severity.HIGH),
        c("/.ssh/id_rsa", "SSH private key exposed", Cat.SECRET, Severity.HIGH),
        b("/id_rsa", "SSH private key exposed", Cat.SECRET, Severity.HIGH, "PRIVATE KEY"),
        c("/.netrc", ".netrc credentials file", Cat.SECRET, Severity.HIGH),
        c("/.pgpass", "PostgreSQL password file", Cat.SECRET, Severity.HIGH),
        c("/secrets.json", "secrets.json exposed", Cat.SECRET, Severity.HIGH),
        c("/credentials.json", "credentials.json exposed", Cat.SECRET, Severity.HIGH),
        c("/.firebaserc", "Firebase project config", Cat.SECRET, Severity.LOW),
        b("/firebase.json", "Firebase hosting config", Cat.SECRET, Severity.LOW, "{"),

        // --- VCS metadata ---
        b("/.git/config", "Git repository config exposed", Cat.VCS, Severity.HIGH, "[core]"),
        b("/.git/HEAD", "Git HEAD exposed (repo downloadable)", Cat.VCS, Severity.HIGH, "ref:"),
        c("/.git/index", "Git index exposed", Cat.VCS, Severity.HIGH),
        b("/.svn/entries", "Subversion entries exposed", Cat.VCS, Severity.HIGH, ""),
        c("/.svn/wc.db", "Subversion wc.db exposed", Cat.VCS, Severity.HIGH),
        b("/.hg/requires", "Mercurial metadata exposed", Cat.VCS, Severity.MEDIUM, ""),
        c("/.bzr/branch/branch.conf", "Bazaar metadata exposed", Cat.VCS, Severity.MEDIUM),
        c("/CVS/Root", "CVS metadata exposed", Cat.VCS, Severity.MEDIUM),

        // --- CI / build / dependency config ---
        b("/Dockerfile", "Dockerfile exposed", Cat.CI_CONFIG, Severity.MEDIUM, "FROM "),
        b("/docker-compose.yml", "docker-compose.yml exposed", Cat.CI_CONFIG, Severity.MEDIUM, "services"),
        c("/.dockerignore", ".dockerignore exposed", Cat.CI_CONFIG, Severity.LOW),
        c("/.gitlab-ci.yml", "GitLab CI config exposed", Cat.CI_CONFIG, Severity.LOW),
        c("/.github/workflows/", "GitHub Actions workflows listing", Cat.CI_CONFIG, Severity.LOW),
        c("/.travis.yml", "Travis CI config exposed", Cat.CI_CONFIG, Severity.LOW),
        c("/.circleci/config.yml", "CircleCI config exposed", Cat.CI_CONFIG, Severity.LOW),
        c("/Jenkinsfile", "Jenkinsfile exposed", Cat.CI_CONFIG, Severity.LOW),
        b("/composer.json", "Composer manifest exposed", Cat.CI_CONFIG, Severity.LOW, "require"),
        c("/composer.lock", "Composer lockfile (exact versions)", Cat.CI_CONFIG, Severity.LOW),
        b("/package.json", "Node package manifest exposed", Cat.CI_CONFIG, Severity.LOW, "\"dependencies\""),
        c("/yarn.lock", "Yarn lockfile exposed", Cat.CI_CONFIG, Severity.LOW),
        c("/Gemfile.lock", "Ruby Gemfile.lock exposed", Cat.CI_CONFIG, Severity.LOW),
        c("/requirements.txt", "Python requirements.txt exposed", Cat.CI_CONFIG, Severity.LOW),

        // --- Backups / dumps ---
        c("/backup.zip", "Backup archive exposed", Cat.BACKUP, Severity.HIGH),
        c("/backup.tar.gz", "Backup archive exposed", Cat.BACKUP, Severity.HIGH),
        c("/backup.sql", "SQL backup exposed", Cat.BACKUP, Severity.HIGH),
        c("/dump.sql", "SQL dump exposed", Cat.BACKUP, Severity.HIGH),
        c("/database.sql", "SQL dump exposed", Cat.BACKUP, Severity.HIGH),
        c("/db.sql", "SQL dump exposed", Cat.BACKUP, Severity.HIGH),
        c("/site.tar.gz", "Site archive exposed", Cat.BACKUP, Severity.HIGH),
        c("/www.zip", "Web root archive exposed", Cat.BACKUP, Severity.HIGH),
        c("/wp-config.php.bak", "WordPress config backup (DB creds)", Cat.BACKUP, Severity.HIGH),
        c("/config.php.bak", "PHP config backup", Cat.BACKUP, Severity.HIGH),
        c("/config.php~", "PHP config editor backup", Cat.BACKUP, Severity.HIGH),
        c("/index.php.bak", "PHP source backup", Cat.BACKUP, Severity.MEDIUM),
        c("/.well-known/", "well-known directory listing", Cat.INFO, Severity.LOW),

        // --- Info disclosure ---
        b("/phpinfo.php", "phpinfo() exposed", Cat.INFO, Severity.HIGH, "phpinfo()"),
        b("/info.php", "phpinfo() exposed", Cat.INFO, Severity.HIGH, "phpinfo()"),
        b("/server-status", "Apache mod_status exposed", Cat.INFO, Severity.MEDIUM, "Apache Server Status"),
        b("/server-info", "Apache mod_info exposed", Cat.INFO, Severity.MEDIUM, "Apache Server Information"),
        b("/web.config", "ASP.NET web.config readable", Cat.INFO, Severity.HIGH, "<configuration"),
        b("/WEB-INF/web.xml", "Java web.xml readable", Cat.INFO, Severity.HIGH, "<web-app"),
        b("/WEB-INF/classes/", "Java WEB-INF classes listing", Cat.INFO, Severity.MEDIUM, "Index of"),
        c("/.DS_Store", "macOS .DS_Store metadata", Cat.INFO, Severity.LOW),
        c("/error_log", "Server error_log exposed", Cat.INFO, Severity.MEDIUM),
        c("/debug.log", "Debug log exposed", Cat.INFO, Severity.MEDIUM),
        c("/storage/logs/laravel.log", "Laravel log exposed", Cat.INFO, Severity.MEDIUM),
        b("/phpmyadmin/", "phpMyAdmin exposed", Cat.ADMIN, Severity.MEDIUM, "phpMyAdmin"),
        b("/adminer.php", "Adminer DB tool exposed", Cat.ADMIN, Severity.MEDIUM, "Adminer"),

        // --- Debug / management endpoints (frameworks) ---
        b("/actuator", "Spring Boot Actuator exposed", Cat.DEBUG, Severity.MEDIUM, "_links"),
        b("/actuator/health", "Actuator health endpoint", Cat.DEBUG, Severity.LOW, "status"),
        b("/actuator/env", "Actuator env (config/secrets) exposed", Cat.DEBUG, Severity.HIGH, "propertySources"),
        c("/actuator/heapdump", "Actuator heapdump downloadable (memory secrets)", Cat.DEBUG, Severity.HIGH),
        b("/actuator/mappings", "Actuator mappings (route disclosure)", Cat.DEBUG, Severity.MEDIUM, "handler"),
        b("/actuator/beans", "Actuator beans exposed", Cat.DEBUG, Severity.MEDIUM, "beans"),
        b("/metrics", "Prometheus/metrics endpoint exposed", Cat.DEBUG, Severity.LOW, "# HELP"),
        b("/debug/pprof/", "Go pprof profiling exposed", Cat.DEBUG, Severity.MEDIUM, "pprof"),
        b("/_profiler/", "Symfony profiler exposed", Cat.DEBUG, Severity.HIGH, "Symfony"),
        b("/telescope/requests", "Laravel Telescope exposed", Cat.DEBUG, Severity.HIGH, "Telescope"),
        b("/__clockwork/", "Clockwork debugger exposed", Cat.DEBUG, Severity.MEDIUM, "clockwork"),
        b("/wp-json/wp/v2/users", "WordPress REST user enumeration", Cat.INFO, Severity.MEDIUM, "\"slug\""),

        // --- Search / data platforms ---
        b("/solr/", "Apache Solr admin exposed", Cat.ADMIN, Severity.HIGH, "Solr"),
        b("/_cat/indices", "Elasticsearch _cat/indices exposed", Cat.ADMIN, Severity.HIGH, "health"),
        b("/_cluster/health", "Elasticsearch cluster health exposed", Cat.ADMIN, Severity.HIGH, "cluster_name"),
        b("/grafana/login", "Grafana login exposed", Cat.ADMIN, Severity.LOW, "Grafana"),
        b("/kibana/", "Kibana exposed", Cat.ADMIN, Severity.MEDIUM, "kibana"),
        b("/jenkins/", "Jenkins exposed", Cat.ADMIN, Severity.MEDIUM, "Jenkins"),
        b("/rundeck/", "Rundeck exposed", Cat.ADMIN, Severity.MEDIUM, "Rundeck"),

        // --- Default / example content ---
        b("/manual/", "Apache manual (default content) present", Cat.DEFAULT, Severity.LOW, "Apache"),
        b("/examples/servlets/", "Tomcat example servlets present", Cat.DEFAULT, Severity.MEDIUM, "Servlet"),
        b("/manager/html", "Tomcat Manager exposed", Cat.ADMIN, Severity.HIGH, "Tomcat"),
        b("/host-manager/html", "Tomcat Host Manager exposed", Cat.ADMIN, Severity.HIGH, "Tomcat"),
        c("/test.php", "Test script present", Cat.DEFAULT, Severity.LOW),
        c("/test.html", "Test page present", Cat.DEFAULT, Severity.LOW),
        c("/phpinfo/", "phpinfo directory present", Cat.INFO, Severity.MEDIUM),

        // --- Classic CGI / script checks (expanded across CGI dirs) ---
        cgi("test-cgi", "test-cgi script present (info disclosure)", Severity.MEDIUM),
        cgi("printenv", "printenv CGI present (environment disclosure)", Severity.MEDIUM),
        cgi("php-cgi", "php-cgi present (possible source disclosure/RCE)", Severity.HIGH),
        cgi("php.cgi", "php.cgi present", Severity.MEDIUM),
        cgi("status", "CGI status script present", Severity.LOW),
        cgi("info.cgi", "info.cgi present", Severity.LOW),
        cgi("admin.cgi", "admin.cgi present", Severity.MEDIUM),
        cgi("ViewPage.cgi", "ViewPage.cgi present", Severity.LOW),
        cgi("guestbook.cgi", "guestbook.cgi present (legacy, often vulnerable)", Severity.MEDIUM)
    )
}
