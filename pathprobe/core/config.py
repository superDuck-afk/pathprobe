"""Central configuration — constants, signatures, patterns, thresholds.

This module contains *data only* — no functions, no classes.  Any
logic that operates on these data structures lives in the module that
owns the concern (e.g. response_analyzer uses SIGNATURES, payload_engine
uses TARGET_FILES).
"""

from __future__ import annotations

# ─────────────────────────────────────────────
#  ANSI COLORS
# ─────────────────────────────────────────────
R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
M    = "\033[95m"
C    = "\033[96m"
W    = "\033[97m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RST  = "\033[0m"

BANNER = f"""
{R}██████╗  █████╗ ████████╗██╗  ██╗
{Y}██╔══██╗██╔══██╗╚══██╔══╝██║  ██║
{G}██████╔╝███████║   ██║   ███████║
{C}██╔═══╝ ██╔══██║   ██║   ██╔══██║
{B}██║     ██║  ██║   ██║   ██║  ██║
{M}╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝{RST}
{DIM}██████╗ ██████╗  ██████╗ ██████╗ ███████╗
{DIM}██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
{DIM}██████╔╝██████╔╝██║   ██║██████╔╝█████╗
{DIM}██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
{DIM}██║     ██║  ██║╚██████╔╝██████╔╝███████╗
{DIM}╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝{RST}

  {W}Path Traversal Testing Framework{RST}  {DIM}v3.0 | Adaptive Fuzzing + WAF Bypass{RST}
  {'─'*58}
"""

# ─────────────────────────────────────────────
#  CONTENT SIGNATURES  (Layer 1 — known file contents)
# ─────────────────────────────────────────────
SIGNATURES = {
    # Linux
    "linux_passwd":    {"pattern": r"root:x:0:0|root:[^:]*:[0-9]+:[0-9]+",                 "description": "/etc/passwd exposed",        "severity": "CRITICAL", "os": "Linux"},
    "linux_shadow":    {"pattern": r"root:\$[0-9a-z]\$|root:\*:",                           "description": "/etc/shadow exposed",        "severity": "CRITICAL", "os": "Linux"},
    "linux_hosts":     {"pattern": r"127\.0\.0\.1\s+localhost|::1\s+localhost",              "description": "/etc/hosts exposed",         "severity": "HIGH",     "os": "Linux"},
    "linux_proc_env":  {"pattern": r"HOME=/|PATH=/usr|HOSTNAME=|USER=",                     "description": "/proc/self/environ exposed", "severity": "CRITICAL", "os": "Linux"},
    "linux_proc_ver":  {"pattern": r"Linux version [0-9]+\.[0-9]+",                         "description": "/proc/version exposed",      "severity": "HIGH",     "os": "Linux"},
    "linux_crontab":   {"pattern": r"#\s*m h dom mon dow|SHELL=/bin/",                      "description": "crontab file exposed",       "severity": "HIGH",     "os": "Linux"},
    "ssh_private_key": {"pattern": r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",     "description": "SSH private key exposed",    "severity": "CRITICAL", "os": "Linux"},
    "bash_history":    {"pattern": r"sudo |ssh |mysql |psql |curl |wget ",                  "description": "bash_history exposed",       "severity": "HIGH",     "os": "Linux"},
    "linux_resolv":    {"pattern": r"nameserver\s+\d+\.\d+\.\d+\.\d+",                     "description": "/etc/resolv.conf exposed",   "severity": "MEDIUM",   "os": "Linux"},
    # Windows
    "windows_ini":     {"pattern": r"\[fonts\]|\[extensions\]|\[mci extensions\]",          "description": "Windows win.ini exposed",    "severity": "HIGH",     "os": "Windows"},
    "windows_boot":    {"pattern": r"\[boot loader\]|multi\(0\)disk\(0\)",                  "description": "Windows boot.ini exposed",   "severity": "HIGH",     "os": "Windows"},
    "windows_sam":     {"pattern": r"Administrator:500:|Guest:501:",                        "description": "Windows SAM file exposed",   "severity": "CRITICAL", "os": "Windows"},
    "web_config":      {"pattern": r"<configuration>|<connectionStrings>|<appSettings>",    "description": "web.config exposed",         "severity": "CRITICAL", "os": "Windows"},
    "windows_hosts":   {"pattern": r"#.*Copyright.*Microsoft|localhost\s+name\s+resolution","description": "Windows hosts file exposed", "severity": "HIGH",     "os": "Windows"},
    # Cross-platform
    "env_file":        {"pattern": r"DB_PASSWORD=|APP_KEY=|SECRET_KEY=|API_KEY=|DATABASE_URL=|JWT_SECRET=",
                        "description": ".env file exposed",          "severity": "CRITICAL", "os": "Any"},
    "php_config":      {"pattern": r"\$db_password\s*=|define\('DB_PASSWORD'|'password'\s*=>\s*'",
                        "description": "PHP config exposed",         "severity": "CRITICAL", "os": "Any"},
    "php_source":      {"pattern": r"<\?php\s|<\?=",
                        "description": "PHP source code exposed",    "severity": "HIGH",     "os": "Any"},
    "apache_log":      {"pattern": r'"[A-Z]+ /[^\s]+ HTTP/',
                        "description": "Apache/Nginx log exposed",   "severity": "HIGH",     "os": "Linux"},
    "appsettings":     {"pattern": r'"ConnectionStrings"|"DefaultConnection"',
                        "description": "appsettings.json exposed",   "severity": "CRITICAL", "os": "Windows"},
    "git_config":      {"pattern": r"\[core\]\s*repositoryformatversion|\[remote",
                        "description": ".git/config exposed",        "severity": "HIGH",     "os": "Any"},
    "git_head":        {"pattern": r"ref: refs/heads/",
                        "description": ".git/HEAD exposed",          "severity": "MEDIUM",   "os": "Any"},
    "laravel_log":     {"pattern": r"\[20[0-9]{2}-[0-9]{2}-[0-9]{2}.*local\]",
                        "description": "Laravel log exposed",        "severity": "HIGH",     "os": "Any"},
    "aws_creds":       {"pattern": r"aws_access_key_id|aws_secret_access_key",
                        "description": "AWS credentials exposed",    "severity": "CRITICAL", "os": "Any"},
    "django_settings": {"pattern": r"DJANGO_SECRET_KEY|DATABASES\s*=\s*\{",
                        "description": "Django settings exposed",    "severity": "CRITICAL", "os": "Any"},
    "rails_secrets":   {"pattern": r"secret_key_base:|production:\s*secret",
                        "description": "Rails secrets exposed",      "severity": "CRITICAL", "os": "Any"},
    "htpasswd":        {"pattern": r"[a-zA-Z0-9_]+:\$apr1\$|[a-zA-Z0-9_]+:\{SHA\}",
                        "description": ".htpasswd file exposed",     "severity": "CRITICAL", "os": "Any"},
    "docker_compose":  {"pattern": r"(services|volumes):\s*\n\s+\w+:",
                        "description": "docker-compose.yml exposed", "severity": "HIGH",     "os": "Any"},
    "kube_config":     {"pattern": r"apiVersion:\s*v1\s*\nkind:\s*(Config|Secret)",
                        "description": "Kubernetes config exposed",  "severity": "CRITICAL", "os": "Any"},
}

# ─────────────────────────────────────────────
#  ERROR-BASED SIGNATURES  (Layer 2 — server errors that prove traversal)
# ─────────────────────────────────────────────
ERROR_SIGNATURES = {
    "no_such_file":      r"No such file or directory",
    "failed_open":       r"failed to open stream",
    "open_basedir":      r"open_basedir restriction in effect",
    "include_failed":    r"include\(\).*Failed opening|require\(\).*Failed opening",
    "file_get_contents": r"Warning.*file_get_contents|file_get_contents\(.*\).*failed",
    "fopen_warning":     r"Warning.*fopen\(|fopen\(.*\).*failed",
    "java_fnf":          r"java\.io\.FileNotFoundException",
    "dotnet_fnf":        r"System\.IO\.FileNotFoundException|Could not find file",
    "access_denied":     r"Access is denied|Access denied",
    "permission_denied": r"Permission denied",
    "path_disclosed":    r"(fopen|file_get_contents|include|require)\s*\(['\"']?(/[a-z/]+|[A-Z]:\\\\)",
    "ruby_errno":        r"Errno::ENOENT|No such file or directory.*\.rb",
    "python_ioerror":    r"\[Errno 2\] No such file or directory",
    "nodejs_enoent":     r"ENOENT.*no such file or directory",
    "iis_error":         r"The system cannot find the (file|path) specified",
    "asp_error":         r"System\.IO\.DirectoryNotFoundException",
    "tomcat_error":      r"java\.io\.IOException.*Invalid file path|getResource\(\).*not found",
    "spring_error":      r"TemplateInputException|Could not resolve view with name",
}

# Regex for extracting paths from error messages (free intelligence)
PATH_EXTRACTION_PATTERNS = [
    r"fopen\(['\"]?(/[^\s'\")\]]+)",                  # PHP fopen path
    r"include\(['\"]?(/[^\s'\")\]]+)",                 # PHP include path
    r"require\(['\"]?(/[^\s'\")\]]+)",                 # PHP require path
    r"file_get_contents\(['\"]?(/[^\s'\")\]]+)",       # PHP file_get_contents
    r"FileNotFoundException:\s*(/[^\s]+|[A-Z]:\\[^\s]+)",  # Java/C# path
    r"ENOENT.*?'(/[^']+)'",                           # Node.js path
    r"No such file or directory.*?['\"](/[^'\"]+)",    # Generic Unix
    r"([A-Z]:\\[^\s'\"<>|*?]+)",                       # Windows path
    r"open_basedir.*?(/[^\s'\"<>]+)",                  # PHP basedir leak
]

# ─────────────────────────────────────────────
#  VALUE-BASED PARAMETER DETECTION
# ─────────────────────────────────────────────
VALUE_PATTERNS = {
    "file_path":      r"^\.{0,2}/[a-zA-Z0-9_./ -]+$",
    "windows_path":   r"^[A-Z]:\\|^\.{0,2}\\[a-zA-Z0-9_.\\-]+$",
    "has_extension":  r"\.(php|jsp|asp|aspx|txt|pdf|xml|json|html|htm|tpl|inc|conf|cfg|ini|log|yml|yaml|env|bak|old|zip|tar|gz|md|csv|sql|db|sqlite|properties|toml)$",
    "directory":      r"^/[a-z]+(/[a-z_-]+)*/?$",
    "base64_path":    r"^[A-Za-z0-9+/]{8,}={0,2}$",
    "url_encoded":    r"%2[eEfF]|%5[cC]",
}

FILE_PARAM_HINTS = {
    "file", "path", "page", "template", "doc", "download",
    "view", "load", "dir", "folder", "resource", "include",
    "src", "filename", "filepath", "module", "target", "name",
    "document", "location", "read", "retrieve", "fetch", "get",
    "import", "config", "conf", "img", "image", "attachment",
    "cat", "action", "board", "date", "detail", "display",
    "lang", "layout", "open", "pdf", "report", "show", "style",
    "theme", "url", "val", "content", "data",
}

STATIC_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".pdf", ".zip", ".gz",
    ".bmp", ".tiff", ".flac", ".ogg",
}

# ─────────────────────────────────────────────
#  TARGET FILES (for payload generation)
# ─────────────────────────────────────────────
TARGET_FILES = {
    "linux": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/resolv.conf",
        "/proc/self/environ",
        "/proc/version",
        "/proc/self/cmdline",
        "/proc/self/status",
        "/proc/self/fd/0",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/home/user/.ssh/id_rsa",
        "/home/ubuntu/.bash_history",
        "/root/.bash_history",
        "/root/.ssh/id_rsa",
    ],
    "windows": [
        "windows/win.ini",
        "windows/system32/drivers/etc/hosts",
        "boot.ini",
        "inetpub/wwwroot/web.config",
        "windows/system32/config/SAM",
        "windows/debug/NetSetup.LOG",
        "windows/iis.log",
        "windows/system32/inetsrv/config/applicationHost.config",
    ],
    "webapp": [
        ".env",
        "../.env",
        "config.php",
        "configuration.php",
        "wp-config.php",
        "config/database.php",
        "application/config/database.php",
        "sites/default/settings.php",
        "config/database.yml",
        "config/secrets.yml",
        "appsettings.json",
        ".git/config",
        ".git/HEAD",
        ".htpasswd",
        ".htaccess",
        "storage/logs/laravel.log",
        "database.yml",
        "docker-compose.yml",
        ".dockerenv",
    ],
}

# ─────────────────────────────────────────────
#  USER-AGENT POOL
# ─────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

# ─────────────────────────────────────────────
#  SCORING THRESHOLDS
# ─────────────────────────────────────────────
# Parameter priority thresholds (cumulative probe score)
PARAM_SCORE_HIGH   = 5
PARAM_SCORE_MEDIUM = 3

# Finding confidence score weights
SCORE_WEIGHT_SIGNATURE_CRITICAL = 40
SCORE_WEIGHT_SIGNATURE_HIGH     = 30
SCORE_WEIGHT_SIGNATURE_MEDIUM   = 20
SCORE_WEIGHT_ERROR_DETECTED     = 15
SCORE_WEIGHT_SIM_VERY_LOW       = 15   # sim < 0.50
SCORE_WEIGHT_SIM_LOW            = 10   # sim < 0.70
SCORE_WEIGHT_SIM_MEDIUM         = 5    # sim < 0.90
SCORE_WEIGHT_SIZE_ANOMALY       = 5
SCORE_WEIGHT_CT_CHANGED         = 10
SCORE_WEIGHT_VERIFIED           = 15
SCORE_PENALTY_SINGLE_HIT        = -10  # only 1 hit out of 20+ payloads

# Short-circuit: stop deep-fuzzing a param after N confirmed HIGH findings
MAX_HIGH_FINDINGS_PER_PARAM = 3

# Verification: re-send payload this many times
VERIFY_COUNT   = 2
VERIFY_DELAY_S = 0.5

# Similarity thresholds
SIM_THRESHOLD_VERY_DIFF = 0.50
SIM_THRESHOLD_DIFF      = 0.70
SIM_THRESHOLD_SIMILAR   = 0.90

# Size anomaly: response must be > this factor × baseline AND > min bytes
SIZE_ANOMALY_FACTOR   = 1.5
SIZE_ANOMALY_MIN_BYTES = 200

# Maximum response body to keep for evidence
EVIDENCE_MAX_BYTES = 500

# SimHash chunk size for large-response comparison
SIMHASH_CHUNK_SIZE = 64
SIMHASH_THRESHOLD  = 16384  # bytes; above this, use simhash instead of SequenceMatcher

# ─────────────────────────────────────────────
#  IP-SPOOFING HEADERS
# ─────────────────────────────────────────────
SPOOF_HEADERS = {
    "X-Forwarded-For":    "127.0.0.1",
    "X-Real-IP":          "127.0.0.1",
    "X-Originating-IP":   "127.0.0.1",
    "X-Remote-IP":        "127.0.0.1",
    "X-Remote-Addr":      "127.0.0.1",
    "X-Client-IP":        "127.0.0.1",
    "X-Host":             "localhost",
    "Forwarded":          "for=127.0.0.1;host=localhost;proto=https",
    "True-Client-IP":     "127.0.0.1",
    "CF-Connecting-IP":   "127.0.0.1",
}
