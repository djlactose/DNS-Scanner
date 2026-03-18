'use strict';

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'SOA'];

const HEALTH_STATUS = {
  ALIVE: 'alive',
  DEAD: 'dead',
  TIMEOUT: 'timeout',
  ERROR: 'error',
  SKIPPED: 'skipped',
  TAKEOVER_RISK: 'takeover_risk',
  NO_IPV6: 'no_ipv6',
};

const SCAN_STATUS = {
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed',
};

const SCAN_TRIGGER = {
  SCHEDULED: 'scheduled',
  MANUAL: 'manual',
};

const USER_ROLES = {
  ADMIN: 'admin',
  VIEWER: 'viewer',
};

const SKIPPED_RECORD_TYPES = ['TXT', 'CAA', 'SOA'];

const COMMON_PORTS = [
  { port: 443, name: 'HTTPS' },
  { port: 80, name: 'HTTP' },
  { port: 22, name: 'SSH' },
  { port: 8443, name: '8443' },
  { port: 8080, name: '8080' },
  { port: 3389, name: 'RDP' },
  { port: 21, name: 'FTP' },
];

const FULL_SCAN_PORTS = [
  { port: 21, name: 'FTP' },
  { port: 22, name: 'SSH' },
  { port: 23, name: 'Telnet' },
  { port: 25, name: 'SMTP' },
  { port: 53, name: 'DNS' },
  { port: 80, name: 'HTTP' },
  { port: 110, name: 'POP3' },
  { port: 111, name: 'RPCBind' },
  { port: 135, name: 'MSRPC' },
  { port: 139, name: 'NetBIOS' },
  { port: 143, name: 'IMAP' },
  { port: 389, name: 'LDAP' },
  { port: 443, name: 'HTTPS' },
  { port: 445, name: 'SMB' },
  { port: 465, name: 'SMTPS' },
  { port: 514, name: 'Syslog' },
  { port: 587, name: 'Submission' },
  { port: 636, name: 'LDAPS' },
  { port: 993, name: 'IMAPS' },
  { port: 995, name: 'POP3S' },
  { port: 1433, name: 'MSSQL' },
  { port: 1521, name: 'Oracle' },
  { port: 2049, name: 'NFS' },
  { port: 2082, name: 'cPanel' },
  { port: 2083, name: 'cPanel SSL' },
  { port: 2086, name: 'WHM' },
  { port: 2087, name: 'WHM SSL' },
  { port: 3306, name: 'MySQL' },
  { port: 3389, name: 'RDP' },
  { port: 5432, name: 'PostgreSQL' },
  { port: 5900, name: 'VNC' },
  { port: 5985, name: 'WinRM' },
  { port: 6379, name: 'Redis' },
  { port: 6443, name: 'K8s API' },
  { port: 8000, name: 'HTTP Alt' },
  { port: 8080, name: 'HTTP Proxy' },
  { port: 8443, name: 'HTTPS Alt' },
  { port: 8888, name: 'HTTP Alt2' },
  { port: 9090, name: 'Prometheus' },
  { port: 9200, name: 'Elasticsearch' },
  { port: 9443, name: 'HTTPS Alt2' },
  { port: 27017, name: 'MongoDB' },
];

const MX_PORTS = [
  { port: 25, name: 'SMTP' },
  { port: 587, name: 'Submission' },
  { port: 465, name: 'SMTPS' },
];

const CONSECUTIVE_FAILURES_THRESHOLD = 3;

const HEALTH_CHECK_TIMEOUT_MS = 10000;
const SCAN_TIMEOUT_MS = 60000;
const MAX_CONCURRENT_CHECKS = 10;
const MAX_CONCURRENT_SCANS = 3;

const PRIVATE_RANGES_V4 = [
  { start: '10.0.0.0', mask: 8 },
  { start: '172.16.0.0', mask: 12 },
  { start: '192.168.0.0', mask: 16 },
  { start: '127.0.0.0', mask: 8 },
  { start: '169.254.0.0', mask: 16 },
  { start: '0.0.0.0', mask: 8 },
];

const PRIVATE_RANGES_V6 = ['::1', 'fc00::/7', 'fe80::/10'];

const PUBLIC_RESOLVERS = [
  { name: 'Google', ip: '8.8.8.8' },
  { name: 'Cloudflare', ip: '1.1.1.1' },
  { name: 'Quad9', ip: '9.9.9.9' },
  { name: 'OpenDNS', ip: '208.67.222.222' },
];

const TAKEOVER_FINGERPRINTS = [
  { service: 'AWS S3', cname: '.s3.amazonaws.com', fingerprint: 'NoSuchBucket' },
  { service: 'AWS S3 (website)', cname: '.s3-website', fingerprint: 'NoSuchBucket' },
  { service: 'GitHub Pages', cname: '.github.io', fingerprint: "There isn't a GitHub Pages site here" },
  { service: 'Heroku', cname: '.herokuapp.com', fingerprint: 'no-such-app' },
  { service: 'Heroku', cname: '.herokudns.com', fingerprint: 'no-such-app' },
  { service: 'Azure', cname: '.azurewebsites.net', fingerprint: 'not found' },
  { service: 'Azure TrafficManager', cname: '.trafficmanager.net', fingerprint: 'not found' },
  { service: 'Netlify', cname: '.netlify.app', fingerprint: 'Not Found' },
  { service: 'Netlify', cname: '.netlify.com', fingerprint: 'Not Found' },
  { service: 'Pantheon', cname: '.pantheonsite.io', fingerprint: '404 error unknown site' },
  { service: 'Shopify', cname: '.myshopify.com', fingerprint: 'Sorry, this shop is currently unavailable' },
  { service: 'Surge.sh', cname: '.surge.sh', fingerprint: 'project not found' },
  { service: 'Ghost', cname: '.ghost.io', fingerprint: 'Domain error' },
  { service: 'Fly.io', cname: '.fly.dev', fingerprint: 'not found' },
  { service: 'CloudFront', cname: '.cloudfront.net', fingerprint: 'Bad request' },
  { service: 'Tumblr', cname: '.tumblr.com', fingerprint: "There's nothing here" },
  { service: 'WordPress.com', cname: '.wordpress.com', fingerprint: 'Do you want to register' },
  { service: 'Fastly', cname: '.fastly.net', fingerprint: 'Fastly error: unknown domain' },
  { service: 'Zendesk', cname: '.zendesk.com', fingerprint: 'Help Center Closed' },
  { service: 'Readme.io', cname: '.readme.io', fingerprint: 'Project doesnt exist' },
  { service: 'Cargo', cname: '.cargocollective.com', fingerprint: '404 Not Found' },
  { service: 'Bitbucket', cname: '.bitbucket.io', fingerprint: 'Repository not found' },
  { service: 'Unbounce', cname: '.unbouncepages.com', fingerprint: 'The requested URL was not found' },
  { service: 'Agile CRM', cname: '.agilecrm.com', fingerprint: 'Sorry, this page is no longer available' },
  { service: 'Tilda', cname: '.tilda.ws', fingerprint: 'Please renew your subscription' },
];

const WEBHOOK_EVENT_TYPES = [
  'record.dead',
  'record.recovered',
  'record.takeover_risk',
  'domain.expiry_warning',
  'scan.completed',
  'propagation.inconsistent',
  'dns.changed',
];

const EXPIRY_WARNING_DAYS = [90, 30, 14, 7];

const COMMON_SUBDOMAINS = [
  // Web & apps
  'www', 'app', 'api', 'cdn', 'static', 'assets', 'media', 'images', 'img',
  'portal', 'admin', 'panel', 'dashboard', 'login', 'sso', 'auth', 'oauth',
  'dev', 'staging', 'stage', 'uat', 'qa', 'test', 'sandbox', 'demo', 'beta', 'preview',
  'blog', 'shop', 'store', 'pay', 'checkout', 'docs', 'wiki', 'help', 'support', 'kb',
  'status', 'monitor', 'health', 'uptime',
  // Mail
  'mail', 'smtp', 'pop', 'pop3', 'imap', 'webmail', 'mx', 'mx1', 'mx2', 'mx3',
  'email', 'autodiscover', 'autoconfig', 'mailgw', 'relay',
  // DNS & infrastructure
  'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
  'ftp', 'sftp', 'ssh', 'vpn', 'remote', 'rdp', 'citrix', 'gateway', 'gw',
  'proxy', 'cache', 'edge', 'lb', 'waf',
  'cpanel', 'whm', 'plesk', 'webmin',
  // Dev & CI/CD
  'git', 'gitlab', 'github', 'bitbucket', 'ci', 'cd', 'jenkins', 'build',
  'docker', 'registry', 'npm', 'repo', 'packages', 'artifactory',
  'grafana', 'prometheus', 'kibana', 'elastic', 'logs', 'sentry', 'jaeger',
  // Services
  'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'search',
  'mq', 'rabbitmq', 'kafka', 'queue',
  'crm', 'erp', 'jira', 'confluence', 'slack', 'teams',
  // DNS records (underscore-prefixed)
  '_dmarc', '_domainkey', '_spf',
  '_sip._tls', '_sipfederationtls._tcp', '_autodiscover._tcp',
  '_caldav._tcp', '_carddav._tcp', '_imap._tcp', '_imaps._tcp',
  '_pop3._tcp', '_pop3s._tcp', '_submission._tcp',
  // DKIM selectors (common providers)
  'default._domainkey', 'google._domainkey', 'selector1._domainkey', 'selector2._domainkey',
  'k1._domainkey', 'k2._domainkey', 'k3._domainkey', 'mail._domainkey',
  's1._domainkey', 's2._domainkey', 'dkim._domainkey', 'mandrill._domainkey',
  'smtp._domainkey', 'cm._domainkey', 'pm._domainkey', 'em._domainkey',
  // Microsoft 365
  'lyncdiscover', 'sip', 'enterpriseregistration', 'enterpriseenrollment',
  'msoid', '_sipfederationtls._tcp',
  // Cloud provider verification
  '_amazonses', '_acme-challenge',
  // Network
  'intranet', 'extranet', 'internal', 'private', 'public', 'corp', 'office',
  'backup', 'bak', 'old', 'new', 'legacy', 'archive',
  'www2', 'www3', 'web', 'web1', 'web2', 'server', 'host',
  'ns', 'resolver', 'time', 'ntp', 'ldap', 'ad', 'dc',
];

const DOMAIN_REGEX = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$/;

module.exports = {
  RECORD_TYPES,
  HEALTH_STATUS,
  SCAN_STATUS,
  SCAN_TRIGGER,
  USER_ROLES,
  SKIPPED_RECORD_TYPES,
  COMMON_PORTS,
  MX_PORTS,
  CONSECUTIVE_FAILURES_THRESHOLD,
  HEALTH_CHECK_TIMEOUT_MS,
  SCAN_TIMEOUT_MS,
  MAX_CONCURRENT_CHECKS,
  MAX_CONCURRENT_SCANS,
  PRIVATE_RANGES_V4,
  PRIVATE_RANGES_V6,
  PUBLIC_RESOLVERS,
  TAKEOVER_FINGERPRINTS,
  WEBHOOK_EVENT_TYPES,
  FULL_SCAN_PORTS,
  EXPIRY_WARNING_DAYS,
  DOMAIN_REGEX,
  COMMON_SUBDOMAINS,
};
