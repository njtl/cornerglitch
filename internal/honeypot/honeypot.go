package honeypot

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LureType classifies the kind of fake content to serve when a scanner probes a path.
type LureType int

const (
	LureAdminPanel  LureType = iota
	LureConfigFile
	LureBackupDump
	LureLoginPage
	LureAPIKey
	LureDebugInfo
	LureGitExposure
	LureEnvFile
	LureDBDump
	LureShellAccess
	LureWordPress
	LurePhpMyAdmin
)

// Honeypot detects scanner and hacker tools probing known paths, serves realistic
// lure responses, and generates a robots.txt that advertises enticing honeypot paths.
type Honeypot struct {
	paths         map[string]LureType
	scannerUAs    []string
	lures         *LureGenerator
	Hits          int64 // atomic counter for metrics
	initOnce      sync.Once
	mu            sync.RWMutex
	responseStyle string
}

// NewHoneypot creates a Honeypot with all known scanner paths and UA patterns registered.
func NewHoneypot() *Honeypot {
	h := &Honeypot{
		lures:         NewLureGenerator(),
		responseStyle: "realistic",
	}
	h.initOnce.Do(h.init)
	return h
}

// SetResponseStyle sets the honeypot response style in a thread-safe manner.
// Valid styles: "realistic", "minimal", "aggressive", "tarpit".
func (h *Honeypot) SetResponseStyle(style string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.responseStyle = style
}

// GetResponseStyle returns the current honeypot response style.
func (h *Honeypot) GetResponseStyle() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.responseStyle
}

func (h *Honeypot) init() {
	h.scannerUAs = []string{
		"sqlmap", "nikto", "nmap", "masscan", "burp", "dirbuster",
		"gobuster", "ffuf", "wfuzz", "nuclei", "acunetix", "nessus",
		"qualys", "openvas", "arachni", "w3af", "skipfish", "zaproxy",
		"zap", "havij", "sqlninja", "commix", "vega", "xsstrike",
		"dalfox", "tplmap", "joomscan", "wpscan", "droopescan", "whatweb",
		"metasploit", "hydra", "medusa", "dirb", "feroxbuster",
	}

	h.paths = make(map[string]LureType, 800)

	// ---------------------------------------------------------------
	// 1. Admin panels (~120 paths)
	// ---------------------------------------------------------------
	adminPaths := []string{
		"/admin", "/admin/", "/administrator", "/administrator/",
		"/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-login",
		"/admin/login", "/admin/dashboard", "/admin/index",
		"/admin/home", "/admin/config", "/admin/settings",
		"/admin/users", "/admin/logs", "/admin/console",
		"/admin.php", "/admin.html", "/admin/admin",
		"/cpanel", "/cpanel/", "/cPanel",
		"/manager", "/manager/", "/manager/html",
		"/console", "/console/", "/console/login",
		"/adminpanel", "/adminpanel/",
		"/backend", "/backend/", "/backend/login",
		"/panel", "/panel/", "/panel/login",
		"/control", "/controlpanel", "/control/",
		"/manage", "/manage/", "/management",
		"/dashboard", "/dashboard/", "/dashboard/login",
		"/siteadmin", "/siteadmin/", "/webadmin",
		"/_admin", "/_admin/", "/__admin",
		"/admin2", "/admin1", "/admin123",
		"/system", "/system/", "/system/admin",
		"/superadmin", "/super-admin", "/moderator",
		"/user/login", "/user/admin", "/users/sign_in",
		"/account/login", "/accounts/login",
		"/login", "/login/", "/signin", "/sign-in",
		"/auth", "/auth/login", "/auth/signin",
		"/portal", "/portal/", "/portal/login",
		"/cms", "/cms/admin", "/cms/login",
		"/webmaster", "/web-console",
		"/admin-panel", "/admin_area", "/admin_area/",
		"/admin/cp", "/admin/controlpanel",
		"/admin/admin-login", "/admin/admin_login",
		"/admin/account", "/admin/login.php",
		"/admin/login.html", "/admin/adminLogin",
		"/admin/secure", "/admin/security",
		"/admin/phpmyadmin", "/admin/sqladmin",
		"/admin/db", "/admin/database",
		"/admin/uploads", "/admin/upload",
		"/admin/filemanager", "/admin/file-manager",
		"/admin/editor", "/admin/tinymce",
		"/admin/ckeditor", "/admin/media",
		"/admin/assets", "/admin/content",
		"/admin/pages", "/admin/posts",
		"/admin/comments", "/admin/plugins",
		"/admin/themes", "/admin/modules",
		"/admin/backup", "/admin/export",
		"/admin/import", "/admin/update",
		"/admin/upgrade", "/admin/install",
		"/admin/setup", "/admin/wizard",
		"/admin/api", "/admin/rest",
		"/admin/graphql",
		"/adm", "/adm/", "/administer",
		"/site-admin", "/site_admin",
		"/admincp", "/admincp/",
		"/modcp", "/modcp/",
		"/fileadmin", "/fileadmin/",
		"/typo3", "/typo3/",
		"/bitrix/admin", "/bitrix/admin/",
		"/umbraco", "/umbraco/",
		"/sitefinity", "/kentico",
		"/sitecore/admin", "/sitecore/login",
		"/craft/admin", "/nova", "/nova/login",
		"/telescope", "/horizon",
	}
	for _, p := range adminPaths {
		h.paths[p] = LureAdminPanel
	}

	// ---------------------------------------------------------------
	// 2. Config / env files (~110 paths)
	// ---------------------------------------------------------------
	configPaths := []string{
		"/.env", "/.env.local", "/.env.production", "/.env.staging",
		"/.env.development", "/.env.test", "/.env.backup", "/.env.bak",
		"/.env.old", "/.env.save", "/.env.example", "/.env.sample",
		"/.env.dist", "/.env.dev", "/.env.prod", "/.env.swp",
		"/config.php", "/config.json", "/config.yml", "/config.yaml",
		"/config.xml", "/config.ini", "/config.inc.php", "/config.inc",
		"/configuration.php", "/configuration.php.bak",
		"/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
		"/wp-config.php.save", "/wp-config.php.swp", "/wp-config.php.txt",
		"/web.config", "/web.config.bak", "/web.config.old",
		"/app/config/parameters.yml", "/app/config/config.yml",
		"/app/config/database.yml", "/config/database.yml",
		"/config/secrets.yml", "/config/master.key",
		"/config/credentials.yml.enc",
		"/settings.py", "/settings.pyc", "/local_settings.py",
		"/application.properties", "/application.yml",
		"/application-prod.properties", "/application-dev.properties",
		"/.aws/credentials", "/.aws/config",
		"/.npmrc", "/.yarnrc", "/.pypirc",
		"/composer.json", "/composer.lock",
		"/package.json", "/package-lock.json",
		"/yarn.lock", "/Gemfile", "/Gemfile.lock",
		"/database.yml", "/secrets.yml", "/master.key",
		"/credentials.yml", "/storage.yml",
		"/appsettings.json", "/appsettings.Development.json",
		"/appsettings.Production.json",
		"/launchSettings.json",
		"/firebase.json", "/firebaseConfig.js",
		"/.firebaserc",
		"/wp-includes/version.php",
		"/sites/default/settings.php",
		"/app/etc/local.xml", "/app/etc/env.php",
		"/conf/server.xml", "/conf/tomcat-users.xml",
		"/WEB-INF/web.xml", "/WEB-INF/applicationContext.xml",
		"/META-INF/context.xml",
		"/phpunit.xml", "/phpunit.xml.dist",
		"/.babelrc", "/.eslintrc", "/.prettierrc",
		"/tsconfig.json", "/webpack.config.js",
		"/gruntfile.js", "/gulpfile.js",
		"/bower.json", "/.bowerrc",
		"/Makefile", "/Rakefile", "/build.gradle",
		"/pom.xml", "/build.xml",
		"/setup.cfg", "/setup.py", "/pyproject.toml",
		"/Cargo.toml", "/Cargo.lock",
		"/go.sum",
		"/mix.exs",
		"/.dockerignore", "/.editorconfig",
		"/robots.txt.bak", "/sitemap.xml.gz",
		"/crossdomain.xml", "/clientaccesspolicy.xml",
	}
	for _, p := range configPaths {
		h.paths[p] = LureConfigFile
	}

	// ---------------------------------------------------------------
	// 3. Backup files (~85 paths)
	// ---------------------------------------------------------------
	backupPaths := []string{
		"/backup.sql", "/backup.zip", "/backup.tar.gz", "/backup.tar",
		"/backup.gz", "/backup.rar", "/backup.7z",
		"/db.sql", "/db.sql.gz", "/db.sql.bak", "/db.sql.zip",
		"/dump.sql", "/dump.sql.gz", "/dump.sql.bak",
		"/database.sql", "/database.sql.gz", "/database.sql.bak",
		"/database.zip", "/database.tar.gz",
		"/backup/", "/backups/", "/bak/",
		"/db_backup.sql", "/db_backup.zip",
		"/mysql_backup.sql", "/mysql.sql", "/mysqldump.sql",
		"/site.zip", "/site.tar.gz", "/site.tar",
		"/www.zip", "/www.tar.gz", "/public.zip",
		"/html.zip", "/htdocs.zip", "/httpdocs.zip",
		"/web.zip", "/web.tar.gz",
		"/export.sql", "/export.zip", "/export.csv",
		"/data.sql", "/data.zip", "/data.json",
		"/old/", "/old.zip", "/archive/", "/archive.zip",
		"/temp/", "/temp.zip", "/tmp.zip",
		"/files.zip", "/files.tar.gz",
		"/sql.zip", "/sql/", "/sql/dump.sql",
		"/backup1.sql", "/backup2.sql",
		"/full-backup.zip", "/full-backup.tar.gz",
		"/daily-backup.sql", "/weekly-backup.sql",
		"/latest.sql", "/latest.zip", "/latest.tar.gz",
		"/snapshot.sql", "/snapshot.zip",
		"/migration.sql", "/migrate.sql",
		"/schema.sql", "/seed.sql", "/init.sql",
		"/production.sql", "/staging.sql",
		"/wp-content/backup-db/",
		"/wp-content/backups/",
		"/wp-content/uploads/backups/",
		"/.backup", "/.backup/", "/backup.bak",
		"/backup-db.sql", "/dbexport.sql",
		"/site-backup.zip", "/website-backup.zip",
		"/server-backup.tar.gz",
		"/home.tar.gz", "/home.zip",
		"/var.tar.gz", "/etc.tar.gz",
	}
	for _, p := range backupPaths {
		h.paths[p] = LureBackupDump
	}

	// ---------------------------------------------------------------
	// 4. Git / SVN / VCS exposure (~55 paths)
	// ---------------------------------------------------------------
	gitPaths := []string{
		"/.git/config", "/.git/HEAD", "/.git/index",
		"/.git/COMMIT_EDITMSG", "/.git/description",
		"/.git/info/exclude", "/.git/info/refs",
		"/.git/objects/", "/.git/objects/info/packs",
		"/.git/refs/", "/.git/refs/heads/", "/.git/refs/heads/master",
		"/.git/refs/heads/main", "/.git/refs/remotes/",
		"/.git/logs/HEAD", "/.git/logs/refs/",
		"/.git/packed-refs", "/.git/shallow",
		"/.git/hooks/", "/.git/",
		"/.gitignore", "/.gitattributes", "/.gitmodules",
		"/.svn/", "/.svn/entries", "/.svn/wc.db",
		"/.svn/pristine/", "/.svn/tmp/",
		"/.hg/", "/.hg/hgrc", "/.hg/store/",
		"/.bzr/", "/.bzr/branch/branch.conf",
		"/.cvs", "/CVS/Root", "/CVS/Entries",
		"/_darcs/", "/_darcs/prefs/",
		"/.fossil", "/.fossil-settings/",
		"/REVISION", "/version.txt", "/VERSION",
		"/RELEASE", "/CHANGES", "/CHANGELOG",
		"/CHANGELOG.md", "/CHANGES.md",
		"/.git-credentials", "/.gitconfig",
		"/.git/config~", "/.git/FETCH_HEAD",
		"/.git/ORIG_HEAD",
		"/deploy.log", "/revision.log",
		"/build.log", "/error.log",
	}
	for _, p := range gitPaths {
		h.paths[p] = LureGitExposure
	}

	// ---------------------------------------------------------------
	// 5. PHP / CMS (~110 paths)
	// ---------------------------------------------------------------
	phpPaths := []string{
		"/phpinfo.php", "/info.php", "/php_info.php", "/phpinfo",
		"/test.php", "/i.php", "/pi.php",
		"/phpmyadmin/", "/phpmyadmin", "/phpMyAdmin/", "/phpMyAdmin",
		"/pma/", "/pma", "/PMA/", "/myadmin/", "/myadmin",
		"/mysql/", "/mysql", "/mysqlmanager/",
		"/dbadmin/", "/dbadmin", "/db/", "/sqladmin/",
		"/sql/", "/sql", "/database/", "/adminer/", "/adminer.php",
		"/wp-includes/", "/wp-content/", "/wp-content/uploads/",
		"/wp-content/plugins/", "/wp-content/themes/",
		"/wp-json/", "/wp-json/wp/v2/users",
		"/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
		"/xmlrpc.php", "/wp-cron.php", "/wp-mail.php",
		"/wp-trackback.php", "/wp-signup.php",
		"/wp-activate.php", "/wp-comments-post.php",
		"/wp-blog-header.php", "/wp-load.php",
		"/wp-links-opml.php", "/wp-settings.php",
		"/readme.html", "/license.txt", "/wp-config-sample.php",
		"/joomla/", "/joomla/administrator/",
		"/administrator/index.php",
		"/drupal/", "/drupal/admin/",
		"/user/register", "/user/password",
		"/magento/", "/magento/admin/",
		"/downloader/", "/app/etc/local.xml",
		"/index.php/admin/", "/index.php/admin",
		"/typo3conf/", "/fileadmin/",
		"/wp-content/debug.log",
		"/error_log", "/errors.log",
		"/cgi-bin/php", "/cgi-bin/php5",
		"/cgi-bin/php-cgi",
		"/laravel/", "/artisan",
		"/storage/logs/laravel.log",
		"/storage/framework/sessions/",
		"/vendor/", "/vendor/autoload.php",
		"/vendor/phpunit/", "/vendor/phpunit/phpunit/",
		"/composer.phar",
		"/symfony/", "/bundles/", "/app_dev.php",
		"/app_dev.php/", "/app_dev.php/_profiler/",
		"/app.php", "/index.php",
		"/codeigniter/", "/fuel/", "/fuel/app/config/",
		"/craft/", "/craft/admin",
		"/concrete/", "/concrete5/",
		"/silverstripe/", "/silverstripe/admin/",
		"/prestashop/", "/prestashop/admin/",
		"/opencart/", "/opencart/admin/",
		"/moodle/", "/moodle/admin/",
		"/mediawiki/", "/wiki/", "/w/",
		"/owncloud/", "/nextcloud/",
		"/roundcube/", "/roundcubemail/",
		"/squirrelmail/", "/horde/",
		"/zimbra/", "/zentyal/",
		"/cacti/", "/nagios/", "/zabbix/",
		"/grafana/", "/kibana/",
		"/solr/", "/solr/admin/",
		"/elasticsearch/", "/_cat/indices",
		"/ckeditor/", "/tinymce/", "/fckeditor/",
	}
	for _, p := range phpPaths {
		h.paths[p] = LurePhpMyAdmin
	}

	// ---------------------------------------------------------------
	// 6. API / Debug (~90 paths)
	// ---------------------------------------------------------------
	debugPaths := []string{
		"/debug", "/debug/", "/debug/pprof", "/debug/pprof/",
		"/debug/vars", "/debug/requests",
		"/api/debug", "/api/debug/", "/api/v1/debug",
		"/_debug", "/_debug/", "/__debug__/",
		"/actuator", "/actuator/", "/actuator/health",
		"/actuator/info", "/actuator/env", "/actuator/beans",
		"/actuator/configprops", "/actuator/mappings",
		"/actuator/metrics", "/actuator/loggers",
		"/actuator/auditevents", "/actuator/httptrace",
		"/actuator/scheduledtasks", "/actuator/threaddump",
		"/actuator/heapdump", "/actuator/jolokia",
		"/actuator/prometheus",
		"/metrics", "/metrics/", "/_metrics",
		"/prometheus", "/prometheus/", "/prometheus/metrics",
		"/graphiql", "/graphiql/", "/graphql",
		"/graphql/", "/playground", "/altair",
		"/swagger", "/swagger/", "/swagger-ui/",
		"/swagger-ui.html", "/swagger.json", "/swagger.yaml",
		"/api-docs", "/api-docs/", "/v2/api-docs", "/v3/api-docs",
		"/openapi.json", "/openapi.yaml",
		"/server-status", "/server-status/", "/server-info",
		"/server-info/", "/.well-known/",
		"/.well-known/openid-configuration",
		"/.well-known/security.txt",
		"/.well-known/jwks.json",
		"/trace", "/trace.axd",
		"/elmah.axd", "/elmah.axd/",
		"/_profiler/", "/_profiler/phpinfo",
		"/_profiler/open",
		"/status", "/status/", "/health", "/health/",
		"/healthz", "/healthcheck", "/readyz", "/livez",
		"/info", "/info/", "/about",
		"/version", "/version/",
		"/ping", "/pong",
		"/env", "/env/", "/configprops",
		"/jolokia/", "/jolokia/list",
		"/hawtio/", "/jmx-console/",
		"/web-console/", "/invoker/",
		"/__clockwork/", "/__clockwork/latest",
		"/ray/", "/_ray/",
		"/telescope/requests",
		"/horizon/api/",
		"/admin/queues",
		"/sidekiq/", "/sidekiq",
		"/resque/", "/resque",
		"/flower/", "/flower",
	}
	for _, p := range debugPaths {
		h.paths[p] = LureDebugInfo
	}

	// ---------------------------------------------------------------
	// 7. Shells / Backdoors (~55 paths)
	// ---------------------------------------------------------------
	shellPaths := []string{
		"/shell.php", "/cmd.php", "/c99.php", "/r57.php",
		"/b374k.php", "/wso.php", "/mini.php",
		"/webshell.php", "/backdoor.php", "/hack.php",
		"/exec.php", "/eval.php", "/command.php",
		"/cmd", "/exec", "/eval", "/shell",
		"/remote", "/reverse", "/connect",
		"/uploads/shell.php", "/uploads/cmd.php",
		"/uploads/backdoor.php", "/uploads/webshell.php",
		"/images/shell.php", "/images/cmd.php",
		"/tmp/shell.php", "/tmp/cmd.php", "/tmp/backdoor.php",
		"/temp/shell.php", "/temp/cmd.php",
		"/cache/shell.php", "/cache/cmd.php",
		"/wp-content/uploads/shell.php",
		"/wp-content/uploads/cmd.php",
		"/wp-content/plugins/shell.php",
		"/wp-content/themes/shell.php",
		"/cgi-bin/test-cgi", "/cgi-bin/printenv",
		"/cgi-bin/env.cgi", "/cgi-bin/bash",
		"/cgi-bin/cmd.cgi", "/cgi-bin/shell.cgi",
		"/.bash_history", "/.sh_history", "/.zsh_history",
		"/proc/self/environ", "/proc/self/cmdline",
		"/proc/version", "/proc/cpuinfo",
		"/server/", "/.bashrc", "/.profile",
		"/terminal", "/terminal/",
		"/pty", "/ws-shell",
		"/reverse-shell", "/bind-shell",
	}
	for _, p := range shellPaths {
		h.paths[p] = LureShellAccess
	}

	// ---------------------------------------------------------------
	// 8. Cloud / DevOps (~65 paths)
	// ---------------------------------------------------------------
	cloudPaths := []string{
		"/.docker/config.json", "/Dockerfile", "/dockerfile",
		"/docker-compose.yml", "/docker-compose.yaml",
		"/docker-compose.override.yml",
		"/docker-compose.prod.yml", "/docker-compose.dev.yml",
		"/kubernetes/", "/k8s/",
		"/.kube/config", "/.kube/",
		"/kube-system/", "/api/v1/namespaces",
		"/terraform.tfstate", "/terraform.tfstate.backup",
		"/terraform.tfvars", "/.terraform/",
		"/ansible/", "/ansible.cfg", "/playbook.yml",
		"/inventory", "/hosts",
		"/Vagrantfile", "/vagrant/",
		"/.travis.yml", "/.travis.yaml",
		"/.github/", "/.github/workflows/",
		"/.github/workflows/ci.yml",
		"/.github/workflows/deploy.yml",
		"/.gitlab-ci.yml", "/.gitlab/",
		"/Jenkinsfile", "/jenkins/", "/jenkins",
		"/Procfile", "/Procfile.dev",
		"/.circleci/", "/.circleci/config.yml",
		"/.drone.yml", "/bitbucket-pipelines.yml",
		"/cloudbuild.yaml", "/appveyor.yml",
		"/serverless.yml", "/serverless.yaml",
		"/sam.yaml", "/template.yaml",
		"/cdk.json", "/amplify.yml",
		"/.ebextensions/", "/Dockerrun.aws.json",
		"/ecs-task-definition.json",
		"/kubernetes/deployment.yml",
		"/kubernetes/service.yml",
		"/kubernetes/ingress.yml",
		"/helm/", "/charts/", "/Chart.yaml",
		"/values.yaml", "/values-prod.yaml",
		"/skaffold.yaml", "/tilt.json",
		"/fly.toml", "/render.yaml",
		"/heroku.yml", "/app.json",
		"/netlify.toml", "/vercel.json",
		"/now.json", "/firebase.json",
		"/.gcloudignore", "/app.yaml",
	}
	for _, p := range cloudPaths {
		h.paths[p] = LureConfigFile
	}

	// ---------------------------------------------------------------
	// 9. Credentials / Keys (~55 paths)
	// ---------------------------------------------------------------
	credPaths := []string{
		"/id_rsa", "/id_rsa.pub", "/id_dsa", "/id_dsa.pub",
		"/id_ecdsa", "/id_ed25519",
		"/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/id_ecdsa",
		"/.ssh/id_ed25519", "/.ssh/authorized_keys",
		"/.ssh/known_hosts", "/.ssh/config",
		"/private.key", "/private.pem", "/privkey.pem",
		"/server.key", "/server.crt", "/server.pem",
		"/cert.pem", "/fullchain.pem", "/chain.pem",
		"/ssl/private.key", "/ssl/server.key", "/ssl/cert.pem",
		"/ssl/server.crt",
		"/.htpasswd", "/.htaccess",
		"/passwd", "/shadow",
		"/etc/passwd", "/etc/shadow", "/etc/hosts",
		"/etc/hostname", "/etc/resolv.conf",
		"/etc/nginx/nginx.conf", "/etc/apache2/apache2.conf",
		"/etc/httpd/httpd.conf",
		"/etc/mysql/my.cnf", "/etc/redis/redis.conf",
		"/api_keys.txt", "/api_keys.json",
		"/secrets.json", "/secrets.yaml", "/secrets.txt",
		"/credentials", "/credentials.json", "/credentials.xml",
		"/token", "/token.json", "/tokens.json",
		"/auth.json", "/auth.yaml",
		"/jwt.key", "/jwt.pem", "/jwt_secret",
		"/oauth-private.key", "/oauth-public.key",
		"/.pgpass", "/.my.cnf", "/.netrc",
		"/.docker/config.json",
	}
	for _, p := range credPaths {
		h.paths[p] = LureAPIKey
	}

	// ---------------------------------------------------------------
	// 10. Common vulnerability probes (~55 paths)
	// ---------------------------------------------------------------
	vulnPaths := []string{
		"/cgi-bin/", "/cgi-bin/test-cgi", "/cgi-bin/status",
		"/test", "/test/", "/test.html",
		"/install.php", "/install/", "/install",
		"/setup.php", "/setup/", "/setup",
		"/upgrade.php", "/upgrade/", "/upgrade",
		"/update.php", "/update/", "/update",
		"/init/", "/initialize/",
		"/_profiler/", "/_profiler/phpinfo", "/_profiler/latest",
		"/debug/default/view", "/debug/default/view.html",
		"/elmah.axd", "/trace.axd",
		"/wp-admin/install.php", "/wp-admin/setup-config.php",
		"/wp-admin/upgrade.php",
		"/install/index.php", "/install/install.php",
		"/setup/index.php", "/installer/",
		"/INSTALL", "/INSTALL.txt", "/INSTALL.md",
		"/UPGRADE", "/UPGRADE.txt",
		"/crossdomain.xml", "/clientaccesspolicy.xml",
		"/security.txt", "/.well-known/security.txt",
		"/sitemap.xml", "/sitemap_index.xml",
		"/ads.txt", "/app-ads.txt",
		"/humans.txt", "/manifest.json",
		"/browserconfig.xml", "/apple-app-site-association",
		"/.well-known/apple-app-site-association",
		"/assetlinks.json",
		"/.well-known/assetlinks.json",
		"/favicon.ico",
		"/thumbs.db", "/Thumbs.db",
		"/desktop.ini", "/Desktop.ini",
		"/.DS_Store", "/.DS_Store?",
		"/wp-content/debug.log",
		"/debug.log", "/error.log", "/access.log",
		"/logs/", "/log/", "/log",
	}
	for _, p := range vulnPaths {
		h.paths[p] = LureDebugInfo
	}

	// ---------------------------------------------------------------
	// 11. Login pages (common auth endpoints)
	// ---------------------------------------------------------------
	loginPaths := []string{
		"/wp-login.php", "/user/login", "/users/login",
		"/accounts/login", "/account/login",
		"/signin", "/sign-in", "/sign_in",
		"/auth/login", "/auth/signin",
		"/oauth/authorize", "/oauth/token",
		"/oauth2/authorize", "/oauth2/token",
		"/saml/login", "/saml2/login",
		"/cas/login", "/openid/login",
		"/j_security_check", "/j_spring_security_check",
	}
	for _, p := range loginPaths {
		h.paths[p] = LureLoginPage
	}

	// ---------------------------------------------------------------
	// 12. WordPress-specific paths
	// ---------------------------------------------------------------
	wpPaths := []string{
		"/wordpress/", "/wordpress/wp-admin/",
		"/wordpress/wp-login.php",
		"/wp/", "/wp/wp-admin/", "/wp/wp-login.php",
		"/blog/", "/blog/wp-admin/", "/blog/wp-login.php",
		"/wp-content/uploads/", "/wp-content/plugins/",
		"/wp-content/themes/", "/wp-content/themes/twentytwentyone/",
		"/wp-includes/js/", "/wp-includes/css/",
		"/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php",
		"/wp-admin/options.php", "/wp-admin/theme-editor.php",
		"/wp-admin/plugin-editor.php",
	}
	for _, p := range wpPaths {
		h.paths[p] = LureWordPress
	}

	// ---------------------------------------------------------------
	// 13. Database dumps (additional DB-specific paths)
	// ---------------------------------------------------------------
	dbPaths := []string{
		"/phpmyadmin/export.php", "/phpmyadmin/import.php",
		"/phpmyadmin/sql.php", "/phpmyadmin/db_export.php",
		"/phpmyadmin/server_export.php",
		"/adminer.php", "/adminer/",
		"/db/", "/database/", "/databases/",
		"/mongo/", "/mongodb/", "/redis/",
		"/couchdb/", "/cassandra/",
		"/neo4j/", "/neo4j/browser/",
		"/influxdb/", "/graphite/",
	}
	for _, p := range dbPaths {
		h.paths[p] = LureDBDump
	}

	// ---------------------------------------------------------------
	// 14. Env file variants
	// ---------------------------------------------------------------
	envPaths := []string{
		"/.env.php", "/.env.js", "/.env.json",
		"/.env.yml", "/.env.yaml", "/.env.xml",
		"/.env.ini", "/.env.cfg",
		"/.env.docker", "/.env.vagrant",
		"/.env.testing", "/.env.ci",
		"/env.js", "/env.json", "/env.php",
		"/.flaskenv", "/.env.flask",
	}
	for _, p := range envPaths {
		h.paths[p] = LureEnvFile
	}

	// ---------------------------------------------------------------
	// 15. Firecrawl-targeted paths (JS configs and API endpoints)
	// ---------------------------------------------------------------
	firecrawlPaths := []string{
		"/assets/config.js", "/assets/app.config.js",
		"/api/internal/config", "/api/internal/keys",
		"/_next/data/config.json", "/api/v1/internal/status",
		"/api/internal/health", "/api/private/tokens",
	}
	for _, p := range firecrawlPaths {
		h.paths[p] = LureConfigFile
	}

	// ---------------------------------------------------------------
	// 16. Oxylabs-targeted paths (data APIs and scraping endpoints)
	// ---------------------------------------------------------------
	oxylabsPaths := []string{
		"/api/data/export", "/api/scrape/results",
		"/api/v2/data/bulk", "/api/crawl/queue",
		"/data/feed.json", "/api/search/results.json",
		"/api/products/all.json", "/api/listings/feed",
	}
	for _, p := range oxylabsPaths {
		h.paths[p] = LureAPIKey
	}
}

// ShouldHandle returns true if the request path matches a known scanner probe path
// or is /robots.txt.
func (h *Honeypot) ShouldHandle(path string) bool {
	if path == "/robots.txt" {
		return true
	}
	_, ok := h.paths[path]
	return ok
}

// IsScanner returns true if the request's User-Agent contains a known scanner tool
// signature (case-insensitive match).
func (h *Honeypot) IsScanner(r *http.Request) bool {
	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		return false
	}
	for _, scanner := range h.scannerUAs {
		if strings.Contains(ua, scanner) {
			return true
		}
	}
	return false
}

// ServeHTTP handles a honeypot request by dispatching to the appropriate lure based
// on the path's LureType. Returns the HTTP status code written.
func (h *Honeypot) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	atomic.AddInt64(&h.Hits, 1)

	if r.URL.Path == "/robots.txt" {
		return h.ServeRobotsTxt(w, r)
	}

	w.Header().Set("X-Glitch-Honeypot", "true")

	lureType, ok := h.paths[r.URL.Path]
	if !ok {
		// Shouldn't happen if ShouldHandle was called first, but be safe.
		http.Error(w, "Not Found", http.StatusNotFound)
		return http.StatusNotFound
	}

	style := h.GetResponseStyle()

	switch style {
	case "minimal":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("<!DOCTYPE html><html><body><h1>Page</h1></body></html>"))
		return 200

	case "aggressive":
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		return h.lures.Serve(w, r, lureType)

	case "tarpit":
		time.Sleep(time.Duration(1+rand.Intn(4)) * time.Second)
		return h.lures.Serve(w, r, lureType)

	default: // "realistic"
		return h.lures.Serve(w, r, lureType)
	}
}

// ServeRobotsTxt returns a robots.txt that advertises honeypot paths as disallowed
// entries, enticing scanners to probe them.
func (h *Honeypot) ServeRobotsTxt(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Glitch-Honeypot", "true")
	w.WriteHeader(http.StatusOK)

	var sb strings.Builder
	sb.WriteString("# robots.txt\n")
	sb.WriteString("# Please respect our crawling guidelines\n\n")
	sb.WriteString("User-agent: *\n")
	sb.WriteString("Allow: /\n\n")

	// Disallow entries that are enticing honeypot paths
	disallowed := []string{
		"/admin/",
		"/admin/config",
		"/admin/dashboard",
		"/admin/users",
		"/admin/backup",
		"/administrator/",
		"/cpanel/",
		"/wp-admin/",
		"/wp-login.php",
		"/phpmyadmin/",
		"/backup/",
		"/backups/",
		"/database/",
		"/db/",
		"/dump.sql",
		"/backup.sql",
		"/backup.zip",
		"/.env",
		"/.git/",
		"/.svn/",
		"/config.php",
		"/wp-config.php",
		"/debug/",
		"/api/debug",
		"/actuator/",
		"/server-status",
		"/private/",
		"/secret/",
		"/internal/",
		"/staging/",
		"/dev/",
		"/test/",
		"/old/",
		"/temp/",
		"/.ssh/",
		"/credentials/",
		"/api_keys.txt",
		"/storage/logs/",
		"/vendor/",
		"/console/",
		"/shell/",
		"/cgi-bin/",
		"/install/",
		"/setup/",
		"/terraform.tfstate",
		"/docker-compose.yml",
		"/.aws/",
	}

	for _, path := range disallowed {
		fmt.Fprintf(&sb, "Disallow: %s\n", path)
	}

	sb.WriteString("\n# Crawl-delay: 10\n")
	sb.WriteString("\nSitemap: /sitemap.xml\n")

	w.Write([]byte(sb.String()))
	return http.StatusOK
}
