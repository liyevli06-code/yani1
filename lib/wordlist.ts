/**
 * Common subdomain prefixes, tried by direct DNS resolution rather than any external index.
 * This exists specifically for domains (often on ccTLDs with little public certificate-
 * transparency or passive-DNS coverage, like many .az sites) where the CT-log/passive-DNS
 * sources below find little or nothing — a direct DNS guess-and-check still works there
 * because it doesn't depend on any third party having already seen the name.
 */
export const COMMON_SUBDOMAINS = [
  "www", "mail", "webmail", "smtp", "pop", "imap", "mx", "ns1", "ns2", "ns3", "ns4",
  "ftp", "sftp", "ssh", "vpn", "remote", "rdp",
  "api", "api1", "api2", "apidocs", "docs", "developer", "dev", "dev1", "dev2",
  "staging", "stage", "test", "test1", "testing", "qa", "uat", "preprod", "beta", "demo", "sandbox",
  "admin", "administrator", "manage", "management", "panel", "cpanel", "whm", "webadmin",
  "portal", "dashboard", "console", "backend", "internal", "intranet", "extranet",
  "sso", "auth", "login", "login1", "account", "accounts", "id", "idp", "oauth",
  "secure", "security", "vault",
  "app", "apps", "mobile", "m", "web", "web1", "web2", "www1", "www2", "old", "new", "legacy",
  "shop", "store", "cart", "checkout", "pay", "payment", "payments", "billing",
  "blog", "news", "forum", "community", "support", "help", "helpdesk", "status", "statuspage",
  "cdn", "static", "assets", "media", "images", "img", "files", "download", "downloads", "upload",
  "git", "gitlab", "github", "svn", "jenkins", "ci", "build", "jira", "confluence", "wiki",
  "grafana", "kibana", "prometheus", "monitor", "monitoring", "metrics", "logs", "logging",
  "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "es", "elastic",
  "backup", "backups", "bak", "dr", "disaster-recovery",
  "crm", "erp", "hr", "finance", "accounting", "office", "intra",
  "video", "stream", "live", "chat", "meet", "conference", "voip", "sip", "pbx",
  "iot", "device", "devices", "camera", "cctv", "router", "switch", "printer", "ntp", "time",
  "edu", "e-services", "e-gov", "e-dovlet", "elektron", "online", "client", "clients", "partner", "partners",
  "promo", "landing", "lp", "pages", "page", "preview", "sandbox2", "beta2",
];
