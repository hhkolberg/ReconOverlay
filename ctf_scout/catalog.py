from __future__ import annotations

import time
from typing import Dict, List, Optional

from .config import CATALOG_FILE, load_json, save_json
from .utils import norm_key

SEED_PRODUCTS = [
    {"name": "apache", "aliases": ["apache http server", "httpd"], "category": "webserver"},
    {"name": "nginx", "aliases": ["engine x"], "category": "webserver"},
    {"name": "iis", "aliases": ["microsoft iis"], "category": "webserver"},
    {"name": "caddy", "aliases": [], "category": "webserver"},
    {"name": "lighttpd", "aliases": [], "category": "webserver"},
    {"name": "openresty", "aliases": [], "category": "webserver"},
    {"name": "tomcat", "aliases": ["apache tomcat"], "category": "appserver"},
    {"name": "wordpress", "aliases": ["wp"], "category": "cms"},
    {"name": "drupal", "aliases": [], "category": "cms"},
    {"name": "joomla", "aliases": [], "category": "cms"},
    {"name": "chamilo", "aliases": ["chamilo lms"], "category": "lms"},
    {"name": "moodle", "aliases": [], "category": "lms"},
    {"name": "jenkins", "aliases": [], "category": "ci"},
    {"name": "mediawiki", "aliases": [], "category": "wiki"},
    {"name": "dotnetnuke", "aliases": ["dnn"], "category": "cms"},
    {"name": "typo3", "aliases": [], "category": "cms"},
    {"name": "concretecms", "aliases": ["concrete5"], "category": "cms"},
    {"name": "octobercms", "aliases": [], "category": "cms"},
    {"name": "phpmyadmin", "aliases": ["php my admin"], "category": "admin"},
    {"name": "adminer", "aliases": [], "category": "admin"},
    {"name": "roundcube", "aliases": ["roundcube webmail"], "category": "mail"},
    {"name": "zimbra", "aliases": ["zimbra collaboration"], "category": "mail"},
    {"name": "gitlab", "aliases": [], "category": "devops"},
    {"name": "gitea", "aliases": [], "category": "devops"},
    {"name": "grafana", "aliases": [], "category": "monitoring"},
    {"name": "kibana", "aliases": [], "category": "monitoring"},
    {"name": "sonarqube", "aliases": ["sonar qube"], "category": "devops"},
    {"name": "nexus", "aliases": ["nexus repository", "nexus repository manager"], "category": "repo"},
    {"name": "artifactory", "aliases": ["jfrog artifactory"], "category": "repo"},
    {"name": "laravel", "aliases": [], "category": "framework"},
    {"name": "symfony", "aliases": [], "category": "framework"},
    {"name": "codeigniter", "aliases": [], "category": "framework"},
    {"name": "django", "aliases": [], "category": "framework"},
    {"name": "flask", "aliases": [], "category": "framework"},
    {"name": "express", "aliases": ["expressjs", "express.js"], "category": "framework"},
    {"name": "spring", "aliases": ["spring boot", "spring framework"], "category": "framework"},
    {"name": "struts", "aliases": ["apache struts"], "category": "framework"},
    {"name": "asp.net", "aliases": ["aspnet", "asp net"], "category": "framework"},
    {"name": "rails", "aliases": ["ruby on rails"], "category": "framework"},
    {"name": "next.js", "aliases": ["nextjs", "next js"], "category": "framework"},
    {"name": "nuxt", "aliases": ["nuxt.js", "nuxtjs"], "category": "framework"},
    {"name": "fastapi", "aliases": ["fast api"], "category": "framework"},
    {"name": "swagger ui", "aliases": ["swaggerui", "swagger"], "category": "api"},
    {"name": "openapi", "aliases": ["open api"], "category": "api"},
    {"name": "graphql", "aliases": [], "category": "api"},
    {"name": "kong", "aliases": ["kong gateway"], "category": "gateway"},
    {"name": "traefik", "aliases": [], "category": "gateway"},
    {"name": "envoy", "aliases": ["envoy proxy"], "category": "gateway"},
    {"name": "mysql", "aliases": [], "category": "database"},
    {"name": "mariadb", "aliases": [], "category": "database"},
    {"name": "postgresql", "aliases": ["postgres", "pgsql"], "category": "database"},
    {"name": "mongodb", "aliases": ["mongo"], "category": "database"},
    {"name": "redis", "aliases": [], "category": "cache"},
    {"name": "elasticsearch", "aliases": ["elastic search", "elastic"], "category": "search"},
    {"name": "solr", "aliases": ["apache solr"], "category": "search"},
    {"name": "openssh", "aliases": ["open ssh", "ssh"], "category": "service"},
    {"name": "samba", "aliases": ["smb"], "category": "service"},
    {"name": "vsftpd", "aliases": [], "category": "service"},
    {"name": "proftpd", "aliases": [], "category": "service"},
    {"name": "postfix", "aliases": [], "category": "mail"},
    {"name": "exim", "aliases": [], "category": "mail"},
    {"name": "dovecot", "aliases": [], "category": "mail"},
    {"name": "bind", "aliases": ["named"], "category": "dns"},
    {"name": "cups", "aliases": [], "category": "printing"},
    {"name": "weblogic", "aliases": ["oracle weblogic"], "category": "appserver"},
    {"name": "websphere", "aliases": ["ibm websphere"], "category": "appserver"},
    {"name": "jboss", "aliases": [], "category": "appserver"},
    {"name": "wildfly", "aliases": [], "category": "appserver"},
    {"name": "glassfish", "aliases": [], "category": "appserver"},
    {"name": "coldfusion", "aliases": ["adobe coldfusion"], "category": "appserver"},
    {"name": "openvpn", "aliases": [], "category": "vpn"},
    {"name": "citrix adc", "aliases": ["citrix netscaler", "netscaler"], "category": "appliance"},
    {"name": "fortinet", "aliases": ["fortigate"], "category": "appliance"},
    {"name": "pulse secure", "aliases": [], "category": "appliance"},
    {"name": "ivanti", "aliases": ["ivanti connect secure"], "category": "appliance"},
    {"name": "confluence", "aliases": ["atlassian confluence"], "category": "collaboration"},
    {"name": "jira", "aliases": ["atlassian jira"], "category": "collaboration"},
]


class SoftwareCatalog:
    def __init__(self, path: str = CATALOG_FILE):
        self.path = path
        self.data = self._build_initial_data()
        self.save()

    def _build_initial_data(self) -> dict:
        data = load_json(self.path, None)
        if not isinstance(data, dict) or "products" not in data:
            data = {
                "schema_version": 1,
                "products": [],
                "manual_vulnerability_notes": [],
                "metadata": {
                    "created_at": int(time.time()),
                    "updated_at": int(time.time()),
                    "catalog_path": self.path,
                },
            }
        data.setdefault("products", [])
        data.setdefault("manual_vulnerability_notes", [])
        data.setdefault("metadata", {})
        data["metadata"].setdefault("created_at", int(time.time()))
        data["metadata"]["catalog_path"] = self.path
        self._merge_seeds(data)
        return data

    def _merge_seeds(self, data: dict):
        existing = {norm_key(p.get("name", "")) for p in data.get("products", [])}
        now = int(time.time())
        for seed in SEED_PRODUCTS:
            nk = norm_key(seed["name"])
            if nk in existing:
                continue
            data["products"].append({
                "name": seed["name"].lower(),
                "aliases": [a.lower() for a in seed.get("aliases", [])],
                "known_versions": [],
                "category": seed.get("category", "unknown"),
                "notes": "seed",
                "added_at": now,
                "updated_at": now,
                "source": "seed",
            })
            existing.add(nk)

    def save(self):
        self.data.setdefault("metadata", {})["updated_at"] = int(time.time())
        save_json(self.path, self.data)

    def all_names(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for prod in self.data.get("products", []):
            name = (prod.get("name") or "").lower()
            if not name:
                continue
            out[norm_key(name)] = name
            for alias in prod.get("aliases", []):
                if alias:
                    out[norm_key(alias)] = name
        return out

    def product_count(self) -> int:
        return len(self.data.get("products", []))

    def add_product(self, name: str, version: str = "", vulnerability_note: str = "", aliases: Optional[List[str]] = None, notes: str = "", category: str = "manual") -> str:
        aliases = aliases or []
        name = name.strip().lower()
        if not name:
            raise ValueError("Product name required")
        nk = norm_key(name)
        now = int(time.time())
        target = None
        for prod in self.data.get("products", []):
            if norm_key(prod.get("name", "")) == nk:
                target = prod
                break
            if any(norm_key(a) == nk for a in prod.get("aliases", [])):
                target = prod
                break
        if not target:
            target = {
                "name": name,
                "aliases": [],
                "known_versions": [],
                "category": category or "manual",
                "notes": notes.strip(),
                "added_at": now,
                "updated_at": now,
                "source": "manual",
            }
            self.data["products"].append(target)
        else:
            target["updated_at"] = now
            if notes.strip():
                old = (target.get("notes") or "").strip()
                target["notes"] = old + (" | " if old else "") + notes.strip()
        existing_aliases = {a.lower() for a in target.get("aliases", [])}
        for alias in aliases:
            alias = alias.strip().lower()
            if alias and alias != target["name"] and alias not in existing_aliases:
                target.setdefault("aliases", []).append(alias)
                existing_aliases.add(alias)
        version = version.strip()
        if version:
            versions = set(target.get("known_versions", []))
            if version not in versions:
                target.setdefault("known_versions", []).append(version)
        if vulnerability_note.strip():
            self.data.setdefault("manual_vulnerability_notes", []).append({
                "software": target["name"],
                "version": version,
                "note": vulnerability_note.strip(),
                "added_at": now,
                "source": "manual",
            })
        self.save()
        return target["name"]
