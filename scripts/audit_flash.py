#!/usr/bin/env python3
"""
Audit Flash v5.0 Windows Edition - NSE Scripts + CVE Database + Banner Grabbing
Support SMB, DNS, LDAP + Cyberscore CVSS réel + CDP/LLDP
Corrélation NVD/CVE en temps réel + Cache local + Base CPE locale
Scripts NSE Nmap (vuln, safe, smb-vuln, ssl, http-vuln, auth, discovery)
Banner Grabbing automatique pour détection produit/version
Compatible Windows, Linux, macOS
"""

import logging
import socket
import ftplib

# Configuration du logger principal
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
)
try:
    import telnetlib
    HAS_TELNETLIB = True
except ImportError:
    HAS_TELNETLIB = False
    print("[!] telnetlib non disponible (Python 3.13+) - Tests Telnet désactivés")
import paramiko
import requests
import json
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
import argparse
import ipaddress
import re
import sys
import platform
import struct
import os
from dataclasses import dataclass, field, replace as dc_replace

# Barre de progression
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("[!] tqdm non installé - pas de barre de progression (pip install tqdm)")

# Désactiver les avertissements SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Détection de l'OS
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'

# Import conditionnel de Nmap (optionnel)
try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
    print("[!] python-nmap non installé - scan basique utilisé")

# Import conditionnel de ReportLab (PDF)
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm, cm
    from reportlab.lib.colors import HexColor, black, white, grey
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, Image
    )
    from reportlab.graphics.shapes import Drawing, Rect, String, Circle
    from reportlab.graphics import renderPDF
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("[!] reportlab non installé - export PDF désactivé (pip install reportlab)")


# ============================================================================
# INTÉGRATION BASE DE DONNÉES CVE (NVD - NIST)
# ============================================================================

@dataclass
class CVEEntry:
    """Représente une entrée CVE"""
    cve_id: str
    description: str
    cvss_v3_score: float = 0.0
    cvss_v3_vector: str = ""
    cvss_v2_score: float = 0.0
    severity: str = "UNKNOWN"
    published: str = ""
    modified: str = ""
    references: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    nvd_url: str = ""
    confidence: str = ""   # CONFIRMED / PROBABLE / GENERIC


class CVEDatabase:
    """
    Interface avec la base de données CVE du NIST (NVD)
    API: https://services.nvd.nist.gov/rest/json/cves/2.0

    Fonctionnalités:
    - Recherche CVE par produit/version
    - Cache local SQLite (TTL 24h) pour éviter les requêtes répétées
    - Corrélation automatique avec les services détectés
    - Scoring CVSS officiel v3.1 / v3.0 / v2 (fallback)
    """
    
    # API NVD NIST v2.0
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Délai entre les requêtes (sans clé API: 6s, avec clé: 0.6s)
    API_RATE_LIMIT = 6.0  # secondes
    API_RATE_LIMIT_WITH_KEY = 0.6
    
    # Durée de validité du cache (24h)
    CACHE_TTL_HOURS = 24
    
    # Mapping service -> mots-clés CPE pour la recherche CVE
    SERVICE_TO_CPE = {
        'ftp':          ['vsftpd', 'proftpd', 'filezilla_server', 'iis_ftp'],
        'ssh':          ['openssh', 'dropbear_ssh', 'bitvise_ssh'],
        'telnet':       ['telnet', 'inetutils_telnet'],
        'http':         ['apache_http_server', 'nginx', 'iis', 'apache2', 'lighttpd'],
        'https':        ['apache_http_server', 'nginx', 'iis', 'openssl'],
        'smb':          ['samba', 'windows_server', 'cifs'],
        'microsoft-ds': ['samba', 'windows_server'],
        'netbios-ssn':  ['samba', 'windows_server'],
        'dns':          ['bind', 'unbound', 'powerdns', 'windows_dns'],
        'domain':       ['bind', 'unbound', 'powerdns'],
        'ldap':         ['openldap', 'active_directory', 'ldap'],
        'ms-wbt-server':['remote_desktop_protocol', 'rdp', 'windows_server'],
        'rdp':          ['remote_desktop_protocol', 'rdp'],
        'mysql':        ['mysql', 'mariadb'],
        'redis':        ['redis'],
        'mongodb':      ['mongodb'],
        'postgresql':   ['postgresql'],
        'vnc':          ['tightvnc', 'realvnc', 'ultravnc', 'libvncserver'],
        'smtp':         ['postfix', 'sendmail', 'exim', 'exchange_server'],
        'imap':         ['dovecot', 'courier_imap', 'exchange_server'],
        'pop3':         ['dovecot', 'courier_pop3'],
        'mssql':        ['sql_server', 'mssql'],
        '1433':         ['sql_server'],
        'elasticsearch':['elasticsearch'],
        'kibana':       ['kibana'],
        'tomcat':       ['tomcat'],
        'jenkins':      ['jenkins'],
        'docker':       ['docker'],
    }
    
    # CVEs critiques connus par service (fallback sans API)
    KNOWN_CVES = {
        'ftp_anonymous': [
            CVEEntry(
                cve_id="CVE-1999-0497",
                description="Anonymous FTP is enabled allowing unauthorized access to files.",
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity="HIGH",
                published="1999-01-01",
                cwe_ids=["CWE-306"]
            )
        ],
        'ftp_exposed': [
            CVEEntry(
                cve_id="CWE-319",
                description="FTP transmits credentials and data in cleartext over the network.",
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity="HIGH",
                cwe_ids=["CWE-319", "CWE-312"]
            )
        ],
        'telnet_exposed': [
            CVEEntry(
                cve_id="CVE-1999-0619",
                description="Telnet service transmits credentials in cleartext over the network.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                published="1999-01-01",
                cwe_ids=["CWE-319", "CWE-312"]
            )
        ],
        'telnet_default_creds': [
            CVEEntry(
                cve_id="CWE-798",
                description="Use of Hard-coded/Default Credentials - Telnet accepts default login.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                cwe_ids=["CWE-798", "CWE-319"]
            ),
            CVEEntry(
                cve_id="CVE-1999-0619",
                description="Telnet service transmits credentials in cleartext over the network.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                published="1999-01-01",
                cwe_ids=["CWE-319", "CWE-312"]
            )
        ],
        'smb_null_session': [
            CVEEntry(
                cve_id="CVE-2017-0144",
                description="EternalBlue - SMBv1 remote code execution vulnerability used by WannaCry.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                published="2017-03-14",
                references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144"],
                cwe_ids=["CWE-119"]
            ),
            CVEEntry(
                cve_id="CVE-2020-0796",
                description="SMBGhost - Windows SMBv3 Client/Server remote code execution.",
                cvss_v3_score=10.0,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                severity="CRITICAL",
                published="2020-03-12",
                cwe_ids=["CWE-119"]
            )
        ],
        'smb_v1': [
            CVEEntry(
                cve_id="CVE-2017-0145",
                description="Windows SMB Remote Code Execution Vulnerability (EternalRomance).",
                cvss_v3_score=8.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                severity="HIGH",
                published="2017-03-14",
                cwe_ids=["CWE-119"]
            )
        ],
        'rdp_exposed': [
            CVEEntry(
                cve_id="CVE-2019-0708",
                description="BlueKeep - Remote Desktop Services Remote Code Execution (pre-auth).",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                published="2019-05-14",
                references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708"],
                cwe_ids=["CWE-416"]
            ),
            CVEEntry(
                cve_id="CVE-2019-1181",
                description="DejaBlue - Remote Desktop Services Remote Code Execution.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                published="2019-08-13",
                cwe_ids=["CWE-416"]
            )
        ],
        'ssh_default_creds': [
            CVEEntry(
                cve_id="CWE-798",
                description="Use of Hard-coded Credentials - Default SSH credentials accepted.",
                cvss_v3_score=8.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                severity="HIGH",
                cwe_ids=["CWE-798", "CWE-255"]
            )
        ],
        'mysql_no_password': [
            CVEEntry(
                cve_id="CVE-2012-2122",
                description="MySQL authentication bypass when using certain hashing methods.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                published="2012-06-26",
                cwe_ids=["CWE-306", "CWE-287"]
            )
        ],
        'redis_no_auth': [
            CVEEntry(
                cve_id="CVE-2022-0543",
                description="Redis Lua sandbox escape vulnerability allowing remote code execution.",
                cvss_v3_score=10.0,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                severity="CRITICAL",
                published="2022-02-18",
                cwe_ids=["CWE-862"]
            ),
            CVEEntry(
                cve_id="CVE-2015-4335",
                description="Redis eval command allows remote code execution when no auth required.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                published="2015-06-09",
                cwe_ids=["CWE-264"]
            )
        ],
        'mongodb_no_auth': [
            CVEEntry(
                cve_id="CVE-2013-2132",
                description="MongoDB allows unauthenticated remote access exposing all databases.",
                cvss_v3_score=8.6,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                severity="HIGH",
                published="2013-08-05",
                cwe_ids=["CWE-306"]
            )
        ],
        'ldap_anonymous': [
            CVEEntry(
                cve_id="CVE-2020-28196",
                description="LDAP anonymous bind allows information disclosure of directory contents.",
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity="HIGH",
                published="2020-11-06",
                cwe_ids=["CWE-200", "CWE-306"]
            )
        ],
        'http_sensitive_paths': [
            CVEEntry(
                cve_id="CVE-2021-41773",
                description="Apache HTTP Server path traversal and RCE vulnerability.",
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity="HIGH",
                published="2021-10-04",
                cwe_ids=["CWE-22"]
            )
        ],
        'http_default_creds': [
            CVEEntry(
                cve_id="CWE-798",
                description="Use of Hard-coded/Default Credentials on HTTP Basic Auth endpoint.",
                cvss_v3_score=9.1,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                severity="CRITICAL",
                cwe_ids=["CWE-798", "CWE-287"]
            )
        ],
        'mysql_default_creds': [
            CVEEntry(
                cve_id="CWE-798",
                description="Use of Hard-coded/Default Credentials on MySQL database server.",
                cvss_v3_score=9.1,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                severity="CRITICAL",
                cwe_ids=["CWE-798", "CWE-287"]
            )
        ],
        'dns_zone_transfer': [
            CVEEntry(
                cve_id="CVE-1999-0532",
                description="DNS server allows zone transfers to arbitrary hosts, exposing network topology.",
                cvss_v3_score=5.3,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                severity="MEDIUM",
                published="1999-01-01",
                cwe_ids=["CWE-200"]
            )
        ],
        'http_info_disclosure': [
            CVEEntry(
                cve_id="CWE-200",
                description="Information Exposure - Server version banner leaks software details.",
                cvss_v3_score=3.7,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                severity="LOW",
                cwe_ids=["CWE-200"]
            )
        ],
        'smb_guest_access': [
            CVEEntry(
                cve_id="CVE-2017-7494",
                description="SambaCry - Samba remote code execution via writable share.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                published="2017-05-24",
                cwe_ids=["CWE-20"]
            )
        ],
        'smb_default_creds': [
            CVEEntry(
                cve_id="CWE-798",
                description="Use of Hard-coded/Default Credentials on SMB file sharing service.",
                cvss_v3_score=9.1,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                severity="CRITICAL",
                cwe_ids=["CWE-798", "CWE-287"]
            )
        ],
        'postgresql_default_creds': [
            CVEEntry(
                cve_id="CWE-798",
                description="Use of Hard-coded/Default Credentials on PostgreSQL database server.",
                cvss_v3_score=9.1,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                severity="CRITICAL",
                cwe_ids=["CWE-798", "CWE-287"]
            )
        ],
        'postgresql_no_password': [
            CVEEntry(
                cve_id="CWE-306",
                description="PostgreSQL accepts connections without password authentication.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                cwe_ids=["CWE-306", "CWE-287"]
            )
        ],
        'mssql_default_creds': [
            CVEEntry(
                cve_id="CWE-798",
                description="Use of Hard-coded/Default Credentials on Microsoft SQL Server.",
                cvss_v3_score=9.1,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                severity="CRITICAL",
                cwe_ids=["CWE-798", "CWE-287"]
            )
        ],
        'smtp_open_relay': [
            CVEEntry(
                cve_id="CVE-1999-0512",
                description="SMTP server configured as open relay allowing spam and spoofing.",
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                severity="HIGH",
                published="1999-01-01",
                cwe_ids=["CWE-269"]
            )
        ],
        'vnc_exposed': [
            CVEEntry(
                cve_id="CVE-2006-2369",
                description="VNC server exposed without adequate authentication.",
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity="HIGH",
                cwe_ids=["CWE-306"]
            )
        ],
        'vnc_no_auth': [
            CVEEntry(
                cve_id="CVE-2006-2369",
                description="VNC server accessible without any authentication.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                cwe_ids=["CWE-306", "CWE-287"]
            )
        ],
        'snmp_default_community': [
            CVEEntry(
                cve_id="CVE-1999-0517",
                description="SNMP agent uses default community string allowing information disclosure.",
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity="HIGH",
                published="1999-01-01",
                cwe_ids=["CWE-798", "CWE-200"]
            ),
            CVEEntry(
                cve_id="CVE-1999-0186",
                description="SNMP community string guessed, allowing remote management access.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                published="1999-01-01",
                cwe_ids=["CWE-798", "CWE-287"]
            )
        ],
        'snmp_write_community': [
            CVEEntry(
                cve_id="CVE-1999-0186",
                description="SNMP community string with write access allows remote device reconfiguration.",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="CRITICAL",
                published="1999-01-01",
                cwe_ids=["CWE-798", "CWE-287"]
            )
        ]
    }
    
    def __init__(self, api_key: str = None, cache_file: str = None, use_api: bool = True):
        """
        :param api_key:    Clé API NVD (optionnel, augmente les limites de requêtes)
        :param cache_file: Fichier JSON de cache CVE (TTL 24h). None = désactivé.
        :param use_api:    Utiliser l'API NVD (désactiver pour mode offline)
        """
        self.api_key = api_key
        self.cache_file = cache_file  # None => cache désactivé
        self.use_api = use_api
        self.cache: Dict[str, dict] = {}
        self.last_api_call = 0.0
        self.api_calls_count = 0
        self.rate_limit = self.API_RATE_LIMIT_WITH_KEY if api_key else self.API_RATE_LIMIT

        # Session HTTP persistante — réutilise les connexions TLS vers NVD
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': 'AuditFlash/5.0 Security Scanner'})
        if api_key:
            self._session.headers['apiKey'] = api_key

        # Charger le cache depuis le fichier si disponible
        if self.cache_file:
            self.cache = self._load_cache()

        if use_api:
            cache_status = f"cache activé ({self.cache_file})" if self.cache_file else "cache désactivé"
            print(f"[+] Base CVE NVD activée (NIST) - "
                  f"{'avec clé API' if api_key else 'sans clé (6s/requête)'} | {cache_status}")
        else:
            print("[+] Base CVE locale activée (mode offline)")
    
    def _load_cache(self) -> Dict:
        """Charge le cache CVE depuis un fichier JSON, ne garde que les entrées non expirées."""
        if not self.cache_file or not os.path.exists(self.cache_file):
            return {}
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                cache = json.load(f)
            # Nettoyage du cache expiré
            now = time.time()
            ttl = self.CACHE_TTL_HOURS * 3600
            cleaned = {k: v for k, v in cache.items() if now - v.get('fetched_at', 0) < ttl}
            if len(cleaned) != len(cache):
                # Sauvegarde le cache nettoyé
                with open(self.cache_file, 'w', encoding='utf-8') as f:
                    json.dump(cleaned, f, indent=2, ensure_ascii=False)
            return cleaned
        except Exception as e:
            print(f"[!] Erreur lecture cache CVE: {e}")
            return {}

    def _save_cache(self):
        """Sauvegarde le cache CVE dans un fichier JSON."""
        if not self.cache_file:
            return
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2, ensure_ascii=False)
            print(f"[i] Cache CVE sauvegardé dans {os.path.abspath(self.cache_file)} (entrées: {len(self.cache)})")
        except Exception as e:
            print(f"[!] Erreur écriture cache CVE: {e}")
    
    def _get_cache_key(self, product: str, version: str = "") -> str:
        """Génère une clé de cache"""
        return hashlib.md5(f"{product.lower()}:{version.lower()}".encode()).hexdigest()
    
    def _rate_limit_wait(self):
        """Respecte le rate limit de l'API NVD"""
        elapsed = time.time() - self.last_api_call
        if elapsed < self.rate_limit:
            wait_time = self.rate_limit - elapsed
            time.sleep(wait_time)
    
    def _find_cpe_prefix(self, product: str) -> str:
        """Cherche le préfixe CPE dans CPE_DATABASE pour un produit détecté"""
        product_lower = product.lower().strip()
        for key, entry in CPE_DATABASE.items():
            if key in product_lower or product_lower in key:
                return entry.get('cpe_prefix', '')
        return ''
    
    def _fetch_cve_detail(self, cve_id: str) -> Optional[CVEEntry]:
        """Récupère les détails d'un CVE spécifique via l'API NVD v2.0.
        Utilise le cache mémoire pour éviter les appels redondants.
        """
        if not self.use_api:
            return None

        # Vérifier le cache mémoire
        cache_key = f"detail:{cve_id}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            # Vérifier TTL
            if time.time() - cached.get('fetched_at', 0) < self.CACHE_TTL_HOURS * 3600:
                return cached.get('entry')  # peut être None si CVE non trouvé

        self._rate_limit_wait()
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = self._session.get(url, timeout=30)
            self.last_api_call = time.time()
            self.api_calls_count += 1


            if response.status_code == 200:
                data = response.json()
                cves = self._parse_nvd_response(data)
                entry = cves[0] if cves else None
                # Mettre en cache (y compris None pour éviter de re-fetcher un CVE inexistant)
                self.cache[cache_key] = {'entry': entry, 'fetched_at': time.time()}
                if entry:
                    score_display = entry.cvss_v3_score or entry.cvss_v2_score
                    if score_display > 0.0:
                        logging.info("[NVD] %s : CVSSv3=%.1f | Severity=%s",
                                     cve_id, entry.cvss_v3_score, entry.severity)
                    else:
                        # CVE récent ou pas encore scoré par NVD — on retourne quand même l'entrée
                        logging.warning("[NVD] %s : pas de score CVSS (CVE récent ou réservé)", cve_id)
                    return entry
                return None

            elif response.status_code == 404:
                self.cache[cache_key] = {'entry': None, 'fetched_at': time.time()}
                return None
            elif response.status_code == 403:
                logging.warning("[NVD] Limite de taux atteinte pour %s — attente 30s", cve_id)
                time.sleep(30)
            else:
                logging.warning("[NVD] API error %d pour %s", response.status_code, cve_id)
        except Exception as e:
            logging.error("[NVD] Erreur récupération pour %s: %s", cve_id, e)
        return None
    
    def search_cve_by_cpe(self, cpe_prefix: str, version: str = "",
                           max_results: int = 10) -> List[CVEEntry]:
        """
        Recherche CVE par nom CPE exact (plus précis que keywordSearch)

        :param cpe_prefix: Préfixe CPE (ex: 'cpe:2.3:a:openbsd:openssh')
        :param version: Version du produit
        :param max_results: Nombre max de résultats
        """
        if not self.use_api:
            return []

        cache_key = f"cpe:{cpe_prefix}:{version}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.get('fetched_at', 0) < self.CACHE_TTL_HOURS * 3600:
                return cached.get('entries', [])

        self._rate_limit_wait()
        try:
            cpe_name = (f"{cpe_prefix}:{version}:*:*:*:*:*:*:*"
                        if version else f"{cpe_prefix}:*:*:*:*:*:*:*:*")
            params = {'cpeName': cpe_name, 'resultsPerPage': max_results, 'startIndex': 0}
            response = self._session.get(self.NVD_API_BASE, params=params, timeout=30)
            self.last_api_call = time.time()
            self.api_calls_count += 1

            if response.status_code == 200:
                data = response.json()
                entries = self._parse_nvd_response(data)
                self.cache[cache_key] = {'entries': entries, 'fetched_at': time.time()}
                return entries
            elif response.status_code == 403:
                logging.warning("  [NVD] Limite de taux (CPE: %s) — attente 30s", cpe_prefix)
                time.sleep(30)
            return []
        except requests.exceptions.Timeout:
            logging.warning("  [NVD] Timeout (CPE: %s)", cpe_prefix)
            return []
        except Exception:
            return []
    
    def search_cve_by_product(self, product: str, version: str = "",
                               max_results: int = 10) -> List[CVEEntry]:
        """
        Recherche des CVE pour un produit/version via l'API NVD

        :param product: Nom du produit (ex: 'openssh', 'nginx')
        :param version: Version du produit (ex: '7.4')
        :param max_results: Nombre max de résultats
        :return: Liste de CVEEntry triés par score CVSS
        """
        if not self.use_api:
            return []

        keyword = f"{product} {version}".strip() if version else product
        cache_key = f"product:{keyword}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.get('fetched_at', 0) < self.CACHE_TTL_HOURS * 3600:
                return cached.get('entries', [])

        self._rate_limit_wait()
        try:
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': max_results,
                'startIndex': 0,
            }
            response = self._session.get(self.NVD_API_BASE, params=params, timeout=30)
            self.last_api_call = time.time()
            self.api_calls_count += 1

            if response.status_code == 200:
                data = response.json()
                entries = self._parse_nvd_response(data)
                self.cache[cache_key] = {'entries': entries, 'fetched_at': time.time()}
                return entries
            elif response.status_code == 403:
                logging.warning("  [NVD] Limite de taux pour %s — attente 30s", product)
                time.sleep(30)
                return []
            elif response.status_code == 404:
                return []
            else:
                logging.warning("  [NVD] API erreur %d pour %s", response.status_code, product)
                return []

        except requests.exceptions.ConnectionError:
            logging.warning("  [NVD] Impossible de contacter l'API (pas d'internet?)")
            return []
        except requests.exceptions.Timeout:
            logging.warning("  [NVD] Timeout pour %s", product)
            return []
        except Exception as e:
            logging.error("  [NVD] Erreur inattendue pour %s: %s", product, e)
            return []
    
    def _parse_nvd_response(self, data: Dict) -> List[CVEEntry]:
        """Parse la réponse JSON de l'API NVD v2.0.

        Supporte :
          - CVSS v4.0 (cvssMetricV40)  — CVEs 2024+
          - CVSS v3.1 (cvssMetricV31)  — standard actuel
          - CVSS v3.0 (cvssMetricV30)  — fallback
          - CVSS v2   (cvssMetricV2)   — legacy
        Pour chaque version, sélectionne d'abord l'entrée de type "Primary"
        (fournie par NVD elle-même) avant de tomber sur la première entrée disponible.
        """
        cves = []

        def pick_primary(items: list) -> dict:
            """Retourne l'item 'Primary' en priorité, sinon le premier disponible."""
            for item in items:
                if item.get('type') == 'Primary':
                    return item
            return items[0] if items else {}

        vulnerabilities = data.get('vulnerabilities', [])

        for vuln_data in vulnerabilities:
            cve_data = vuln_data.get('cve', {})

            cve_id = cve_data.get('id', '')

            # Description (anglais de préférence)
            descriptions = cve_data.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and descriptions:
                description = descriptions[0].get('value', '')

            # ── Scores CVSS ──────────────────────────────────────────────────
            cvss_v3_score = 0.0
            cvss_v3_vector = ""
            cvss_v2_score = 0.0
            severity = "UNKNOWN"

            metrics = cve_data.get('metrics', {})

            # CVSS v4.0 — CVEs récents 2024+ (stocké dans cvss_v3_score pour compatibilité)
            if 'cvssMetricV40' in metrics:
                item = pick_primary(metrics['cvssMetricV40'])
                d = item.get('cvssData', {})
                s = d.get('baseScore', 0.0)
                if s > 0.0:
                    cvss_v3_score = s
                    cvss_v3_vector = d.get('vectorString', '')
                    severity = d.get('baseSeverity', 'UNKNOWN')

            # CVSS v3.1 (prioritaire si pas de v4)
            if cvss_v3_score == 0.0 and 'cvssMetricV31' in metrics:
                item = pick_primary(metrics['cvssMetricV31'])
                d = item.get('cvssData', {})
                cvss_v3_score = d.get('baseScore', 0.0)
                cvss_v3_vector = d.get('vectorString', '')
                severity = d.get('baseSeverity', 'UNKNOWN')

            # CVSS v3.0 (fallback v3)
            if cvss_v3_score == 0.0 and 'cvssMetricV30' in metrics:
                item = pick_primary(metrics['cvssMetricV30'])
                d = item.get('cvssData', {})
                cvss_v3_score = d.get('baseScore', 0.0)
                cvss_v3_vector = d.get('vectorString', '')
                severity = d.get('baseSeverity', 'UNKNOWN')

            # CVSS v2 (legacy — toujours récupéré en fallback de sévérité)
            if 'cvssMetricV2' in metrics:
                item = pick_primary(metrics['cvssMetricV2'])
                d = item.get('cvssData', {})
                cvss_v2_score = d.get('baseScore', 0.0)
                if severity == "UNKNOWN":
                    # baseSeverity est un champ de l'item, pas de cvssData pour v2
                    severity = item.get('baseSeverity', 'UNKNOWN')

            # Références
            references = [ref.get('url', '')
                          for ref in cve_data.get('references', [])[:5]]

            # CWE
            cwe_ids = []
            for weakness in cve_data.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_ids.append(desc.get('value', ''))

            # Dates
            published = cve_data.get('published', '').split('T')[0]
            modified = cve_data.get('lastModified', '').split('T')[0]

            # Produits affectés (CPE)
            affected_products = []
            configurations = cve_data.get('configurations', [])
            for config in configurations[:2]:
                for node in config.get('nodes', [])[:3]:
                    for cpe_match in node.get('cpeMatch', [])[:3]:
                        cpe = cpe_match.get('criteria', '')
                        if cpe:
                            parts = cpe.split(':')
                            if len(parts) > 4:
                                product_name = f"{parts[3]} {parts[4]}"
                                if len(parts) > 5 and parts[5] != '*':
                                    product_name += f" {parts[5]}"
                                affected_products.append(product_name)

            cve_entry = CVEEntry(
                cve_id=cve_id,
                description=description[:500],
                cvss_v3_score=cvss_v3_score,
                cvss_v3_vector=cvss_v3_vector,
                cvss_v2_score=cvss_v2_score,
                severity=severity,
                published=published,
                modified=modified,
                references=references,
                affected_products=affected_products[:5],
                cwe_ids=cwe_ids[:3]
            )
            cves.append(cve_entry)

        # Trier par score CVSS décroissant
        cves.sort(key=lambda x: x.cvss_v3_score or x.cvss_v2_score, reverse=True)
        return cves[:10]  # Top 10
    
    @staticmethod
    def _build_nvd_url(cve_id: str) -> str:
        """Génère l'URL NVD/MITRE pour un identifiant CVE ou CWE"""
        if cve_id.upper().startswith('CVE-'):
            return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if cve_id.upper().startswith('CWE-'):
            num = cve_id.split('-', 1)[1]
            return f"https://cwe.mitre.org/data/definitions/{num}.html"
        return ""

    @staticmethod
    def _parse_cvss_vector(vector: str) -> Dict:
        """Parse un vecteur CVSS v3 et retourne les métriques d'exploitabilité."""
        result = {
            'remotely_exploitable': False,   # AV:N
            'no_auth_required': False,        # PR:N
            'no_user_interaction': False,     # UI:N
        }
        if not vector:
            return result
        try:
            metrics = {}
            for part in vector.split('/')[1:]:  # ignorer le préfixe 'CVSS:3.x'
                if ':' in part:
                    k, v = part.split(':', 1)
                    metrics[k] = v
            result['remotely_exploitable']  = metrics.get('AV') == 'N'
            result['no_auth_required']      = metrics.get('PR') == 'N'
            result['no_user_interaction']   = metrics.get('UI') == 'N'
        except Exception:
            pass
        return result

    def _cve_to_dict(self, cve: CVEEntry, confidence: str = None) -> Dict:
        """Convertit un CVEEntry en dict enrichi (confidence + exploitabilité)."""
        vector_info = self._parse_cvss_vector(cve.cvss_v3_vector)
        # Fallback explicite : si v3 = 0, prendre v2
        if cve.cvss_v3_score and cve.cvss_v3_score > 0:
            score = cve.cvss_v3_score
        elif cve.cvss_v2_score and cve.cvss_v2_score > 0:
            score = cve.cvss_v2_score
        else:
            score = 0.0
        nvd_comment = ""
        if (score == 0.0 or cve.severity == "UNKNOWN") and cve.cve_id.upper().startswith("CVE-"):
            nvd_comment = "CVE inconnu ou inexistant dans la base NVD"
        return {
            'cve_id': cve.cve_id,
            'description': cve.description,
            'cvss_v3_score': cve.cvss_v3_score,
            'cvss_v3_vector': cve.cvss_v3_vector,
            'cvss_v2_score': cve.cvss_v2_score,
            'severity': cve.severity,
            'published': cve.published,
            'modified': cve.modified,
            'references': cve.references,
            'affected_products': cve.affected_products,
            'cwe_ids': cve.cwe_ids,
            'nvd_url': self._build_nvd_url(cve.cve_id),
            # Nouveaux champs
            'confidence':            confidence or cve.confidence or 'GENERIC',
            'remotely_exploitable':  vector_info['remotely_exploitable'],
            'no_auth_required':      vector_info['no_auth_required'],
            'no_user_interaction':   vector_info['no_user_interaction'],
            # Approche 5 : facteur d'âge CVE
            'age_factor':            self._compute_age_factor(cve.published),
            'cvss_age_weighted':     round(
                score * self._compute_age_factor(cve.published), 2
            ),
            'nvd_comment': nvd_comment,
        }

    @staticmethod
    def _compute_age_factor(published: str) -> float:
        """
        Approche 5 — Facteur d'âge CVE (0.5 – 1.0).
        Un CVE de plus de 10 ans vaut au minimum 50% de son score CVSS.
        Formule : max(0.5, 1.0 - années × 0.05)
        """
        if not published:
            return 1.0
        try:
            pub_year = int(published[:4])
            age = max(0, datetime.now().year - pub_year)
            return round(max(0.5, 1.0 - age * 0.05), 2)
        except Exception:
            return 1.0

    def get_cves_for_vulnerability(self, vuln_type: str, service: str = "", 
                                    product: str = "", version: str = "") -> List[CVEEntry]:
        """
        Obtient les CVE pour une vulnérabilité détectée.
        Priorité : base CPE locale (précis) > API NVD par CPE > KNOWN_CVES (générique)
        
        :param vuln_type: Type de vulnérabilité (ex: 'ftp_anonymous')
        :param service: Nom du service (ex: 'ftp')
        :param product: Produit détecté (ex: 'vsftpd')
        :param version: Version détectée (ex: '3.0.3')
        :return: Liste de CVE pertinents
        """
        all_cves = []
        has_product_specific = False
        
        # 1. Si produit/version détecté → base CPE locale (le plus précis)
        if product:
            cpe_cve_ids = lookup_cpe_database(product, version)
            if cpe_cve_ids:
                has_product_specific = True
                print(f"    [~] CVE locaux (CPE) pour {product} {version}: {', '.join(cpe_cve_ids[:3])}")
                for cve_id in cpe_cve_ids:
                    all_cves.append(CVEEntry(
                        cve_id=cve_id,
                        description=f"Vulnérabilité connue pour {product} {version}",
                        severity="HIGH",
                        nvd_url=self._build_nvd_url(cve_id),
                        confidence="CONFIRMED"
                    ))
                # Enrichir via UNE SEULE requête API par CPE (au lieu de N requêtes par CVE)
                if self.use_api:
                    cpe_prefix = self._find_cpe_prefix(product)
                    if cpe_prefix and version:
                        api_cves = self.search_cve_by_cpe(cpe_prefix, version, max_results=10)
                        if api_cves:
                            api_map = {c.cve_id: c for c in api_cves}
                            local_ids = {c.cve_id for c in all_cves}
                            enriched = []
                            for cve_entry in all_cves:
                                # Garder CONFIRMED si entrée locale enrichie par l'API
                                merged = api_map.get(cve_entry.cve_id, cve_entry)
                                enriched.append(dc_replace(merged, confidence="CONFIRMED"))
                            for cve in api_cves:
                                if cve.cve_id not in local_ids:
                                    enriched.append(dc_replace(cve, confidence="PROBABLE"))
                            all_cves = enriched
        
        # 2. Si produit détecté mais pas de CVE locaux → recherche API par CPE
        if product and not has_product_specific and self.use_api:
            product_clean = product.lower().strip()
            skip_words = ['the', 'server', 'service', 'daemon', 'version']
            for word in skip_words:
                product_clean = product_clean.replace(f' {word}', '').strip()
            
            api_cves = []
            if len(product_clean) > 2:
                # Chercher le préfixe CPE dans la base locale
                cpe_prefix = self._find_cpe_prefix(product_clean)
                if cpe_prefix and version:
                    print(f"    [~] Recherche CVE API (CPE): {cpe_prefix}:{version}")
                    api_cves = self.search_cve_by_cpe(
                        cpe_prefix, version, max_results=5
                    )
                    if api_cves:
                        has_product_specific = True
                else:
                    print(f"    [~] Recherche CVE API pour: {product_clean} {version}")
                    api_cves = self.search_cve_by_product(
                        product_clean, version, max_results=5
                    )
                    if api_cves:
                        has_product_specific = True
                
                existing_ids = {c.cve_id for c in all_cves}
                for cve in api_cves:
                    if cve.cve_id not in existing_ids:
                        all_cves.append(dc_replace(cve, confidence="PROBABLE"))
                        existing_ids.add(cve.cve_id)
        
        # 3. KNOWN_CVES seulement si pas de données produit-spécifiques
        if not has_product_specific and vuln_type in self.KNOWN_CVES:
            existing_ids = {c.cve_id for c in all_cves}
            for cve in self.KNOWN_CVES[vuln_type]:
                if cve.cve_id not in existing_ids:
                    # Copier pour ne pas modifier l'instance de classe partagée
                    all_cves.append(dc_replace(cve, confidence="GENERIC"))
                    existing_ids.add(cve.cve_id)
        
        # 4. Recherche générique par service seulement en dernier recours
        if not all_cves and service and self.use_api:
            service_lower = service.lower()
            if service_lower in self.SERVICE_TO_CPE:
                keywords = self.SERVICE_TO_CPE[service_lower]
                if keywords:
                    print(f"    [~] Recherche CVE générique pour: {service_lower}")
                    api_cves = self.search_cve_by_product(keywords[0], version, max_results=5)
                    all_cves.extend(dc_replace(c, confidence="GENERIC") for c in api_cves)
        
        # Trier par score CVSS
        all_cves.sort(key=lambda x: x.cvss_v3_score or x.cvss_v2_score, reverse=True)
        return all_cves[:10]
    
    def get_max_cvss_score(self, cves: List[CVEEntry]) -> float:
        """Retourne le score CVSS maximum d'une liste de CVE"""
        if not cves:
            return 0.0
        return max(cve.cvss_v3_score or cve.cvss_v2_score for cve in cves)
    
    def get_stats(self) -> Dict:
        """Retourne les statistiques d'utilisation"""
        return {
            'api_calls': self.api_calls_count,
            'cache_entries': len(self.cache),
            'rate_limit': self.rate_limit
        }


# ============================================================================
# PROFILS DE SCAN PRÉDÉFINIS
# ============================================================================

SCAN_PROFILES = {
    'top-10': {
        'name': 'Top 10 Nmap',
        'ports': [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139],
        'timeout': 2,
        'threads': 100,
        'description': 'Les 10 ports les plus courants selon Nmap',
        'color': '🔟'
    },
    'top-20': {
        'name': 'Top 20 Nmap',
        'ports': [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
                  143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900],
        'timeout': 2,
        'threads': 100,
        'description': 'Les 20 ports les plus courants selon Nmap',
        'color': '🔝'
    },
    'top-100': {
        'name': 'Top 100 Nmap',
        'ports': [
            80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
            143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
            1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
            10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
            26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000,
            5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
            2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
            544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
            7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9200, 6646,
            49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37
        ],
        'timeout': 3,
        'threads': 100,
        'description': 'Les 100 ports les plus courants selon Nmap',
        'color': '💯'
    },
    'windows': {
        'name': 'Scan Windows',
        'ports': [135, 139, 445, 389, 636, 3268, 88, 53, 3389, 5985, 5986, 1433],
        'timeout': 3,
        'description': 'Ports spécifiques Windows/Active Directory',
        'threads': 50,
        'color': '🪟'
    },
    'linux': {
        'name': 'Scan Linux',
        'ports': [21, 22, 23, 25, 110, 143, 80, 443, 8080, 3306, 5432, 6379, 27017, 9200, 9300],
        'timeout': 3,
        'description': 'Ports courants serveurs Linux',
        'threads': 50,
        'color': '🐧'
    },
    'web': {
        'name': 'Scan Web',
        'ports': [80, 443, 8000, 8080, 8443, 3000, 5000, 4200, 4443, 9000, 9090],
        'timeout': 2,
        'description': 'Serveurs et applications web',
        'threads': 100,
        'color': '🌐'
    },
    'full': {
        'name': 'Scan Complet',
        'ports': list(range(1, 1025)),
        'timeout': 3,
        'description': 'Scan complet ports 1-1024 (⚠️ LENT)',
        'threads': 200,
        'color': '🔴'
    },
    'all': {
        'name': 'Scan Tous Ports',
        'ports': list(range(1, 65536)),
        'timeout': 5,
        'description': 'Scan complet des 65535 ports TCP (⚠️ TRÈS LENT)',
        'threads': 200,
        'color': '⚠️'
    }
}


# ============================================================================
# DÉCOUVERTE VLAN - CDP & LLDP
# ============================================================================

CDP_MULTICAST_MAC = "01:00:0c:cc:cc:cc"
CDP_ETHERTYPE = 0x2000
LLDP_MULTICAST_MAC = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88cc
CDP_TLV_DEVICE_ID = 0x0001
CDP_TLV_ADDRESS = 0x0002
CDP_TLV_PORT_ID = 0x0003
CDP_TLV_PLATFORM = 0x0006
CDP_TLV_NATIVE_VLAN = 0x000a
LLDP_TLV_CHASSIS_ID = 1
LLDP_TLV_PORT_ID = 2
LLDP_TLV_SYSTEM_NAME = 5
LLDP_TLV_SYSTEM_DESC = 6
LLDP_TLV_MGMT_ADDR = 8
LLDP_TLV_ORG_SPECIFIC = 127
IEEE_8021_OUI = b'\x00\x80\xc2'


@dataclass
class VLANInfo:
    vlan_id: int
    vlan_name: str = ""
    protocol: str = ""
    native_vlan: bool = False
    switch_name: str = ""
    switch_ip: str = ""
    switch_port: str = ""
    switch_model: str = ""
    discovered_at: str = ""


class VLANDiscovery:
    def __init__(self, interface: str = None, timeout: int = 65):
        self.interface = interface or self._get_default_interface()
        self.timeout = timeout
        self.discovered_vlans: List[VLANInfo] = []
    
    def _get_default_interface(self) -> str:
        if IS_WINDOWS:
            return "Ethernet"
        if IS_LINUX:
            # Lire la route par défaut depuis le noyau (sans dépendance externe)
            try:
                with open('/proc/net/route') as f:
                    for line in f.readlines()[1:]:
                        fields = line.strip().split()
                        # Destination=00000000 (0.0.0.0) = route par défaut
                        if fields[1] == '00000000' and fields[7] == '00000000':
                            return fields[0]
            except Exception:
                pass
            # Fallback : première interface non-loopback
            try:
                for _, name in socket.if_nameindex():
                    if name != 'lo':
                        return name
            except Exception:
                pass
            return "eth0"
        return "en0"
    
    def discover_vlans(self) -> List[VLANInfo]:
        print(f"\n[*] Découverte VLAN sur {self.interface} ({self.timeout}s)...")
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((self.interface, 0))
            sock.settimeout(self.timeout)
            start_time = datetime.now()
            packets_captured = 0
            while (datetime.now() - start_time).total_seconds() < self.timeout:
                try:
                    packet = sock.recv(65535)
                    packets_captured += 1
                    vlan_info = self._parse_cdp(packet)
                    if not vlan_info:
                        vlan_info = self._parse_lldp(packet)
                    if vlan_info and not self._is_duplicate(vlan_info):
                        self.discovered_vlans.append(vlan_info)
                        print(f"  [+] VLAN {vlan_info.vlan_id} - {vlan_info.vlan_name or 'Sans nom'}")
                        print(f"      Switch: {vlan_info.switch_name} ({vlan_info.switch_ip})")
                except socket.timeout:
                    break
                except Exception:
                    continue
            sock.close()
            print(f"  [i] {packets_captured} paquets analysés")
        except PermissionError:
            print("  [!] Permissions root/admin requises pour découverte VLAN")
        except AttributeError:
            print("  [!] Découverte VLAN non disponible sur Windows (nécessite WinPcap/Npcap)")
        except OSError as e:
            print(f"  [!] Interface '{self.interface}' non trouvée: {e}")
        return self.discovered_vlans
    
    def _is_duplicate(self, vlan: VLANInfo) -> bool:
        return any(v.vlan_id == vlan.vlan_id and v.switch_name == vlan.switch_name 
                   for v in self.discovered_vlans)
    
    def _parse_cdp(self, packet: bytes) -> Optional[VLANInfo]:
        try:
            if len(packet) < 26:
                return None
            dst_mac = ':'.join(f'{b:02x}' for b in packet[0:6])
            if dst_mac.lower() != CDP_MULTICAST_MAC.lower():
                return None
            # Bytes 12-13 = longueur 802.3 (trame CDP utilise 802.3 + LLC/SNAP, pas Ethernet II)
            length = struct.unpack('!H', packet[12:14])[0]
            if length >= 0x0600:
                return None  # Ethernet II, pas une trame 802.3 CDP
            # Vérifier LLC : DSAP=0xAA, SSAP=0xAA
            if packet[14] != 0xAA or packet[15] != 0xAA:
                return None
            # Vérifier SNAP OUI Cisco (00:00:0C) et PID CDP (0x2000)
            if packet[17:20] != b'\x00\x00\x0c':
                return None
            snap_pid = struct.unpack('!H', packet[20:22])[0]
            if snap_pid != CDP_ETHERTYPE:
                return None
            # Sauter le header CDP (version 1B + TTL 1B + checksum 2B) → offset 26
            cdp_data = packet[26:]
            vlan_info = VLANInfo(vlan_id=0, protocol="CDP", discovered_at=datetime.now().isoformat())
            offset = 0
            while offset < len(cdp_data) - 4:
                tlv_type = struct.unpack('!H', cdp_data[offset:offset+2])[0]
                tlv_length = struct.unpack('!H', cdp_data[offset+2:offset+4])[0]
                if tlv_length < 4 or offset + tlv_length > len(cdp_data): break
                tlv_value = cdp_data[offset+4:offset+tlv_length]
                if tlv_type == CDP_TLV_DEVICE_ID:
                    vlan_info.switch_name = tlv_value.decode('ascii', errors='ignore').strip()
                elif tlv_type == CDP_TLV_PORT_ID:
                    vlan_info.switch_port = tlv_value.decode('ascii', errors='ignore').strip()
                elif tlv_type == CDP_TLV_PLATFORM:
                    vlan_info.switch_model = tlv_value.decode('ascii', errors='ignore').strip()
                elif tlv_type == CDP_TLV_ADDRESS and len(tlv_value) >= 9:
                    ip_bytes = tlv_value[-4:]
                    vlan_info.switch_ip = '.'.join(str(b) for b in ip_bytes)
                elif tlv_type == CDP_TLV_NATIVE_VLAN and len(tlv_value) >= 2:
                    vlan_info.vlan_id = struct.unpack('!H', tlv_value[0:2])[0]
                    vlan_info.native_vlan = True
                offset += tlv_length
            return vlan_info if vlan_info.vlan_id > 0 else None
        except Exception:
            return None

    def _parse_lldp(self, packet: bytes) -> Optional[VLANInfo]:
        try:
            dst_mac = ':'.join(f'{b:02x}' for b in packet[0:6])
            if dst_mac.lower() != LLDP_MULTICAST_MAC.lower(): return None
            ethertype = struct.unpack('!H', packet[12:14])[0]
            if ethertype != LLDP_ETHERTYPE: return None
            lldp_data = packet[14:]
            vlan_info = VLANInfo(vlan_id=0, protocol="LLDP", discovered_at=datetime.now().isoformat())
            offset = 0
            while offset < len(lldp_data) - 2:
                tlv_header = struct.unpack('!H', lldp_data[offset:offset+2])[0]
                tlv_type = (tlv_header >> 9) & 0x7F
                tlv_length = tlv_header & 0x1FF
                if tlv_length == 0 or offset + 2 + tlv_length > len(lldp_data): break
                tlv_value = lldp_data[offset+2:offset+2+tlv_length]
                if tlv_type == LLDP_TLV_CHASSIS_ID and len(tlv_value) > 1:
                    if tlv_value[0] == 7:
                        vlan_info.switch_name = tlv_value[1:].decode('ascii', errors='ignore')
                elif tlv_type == LLDP_TLV_PORT_ID and len(tlv_value) > 1:
                    vlan_info.switch_port = tlv_value[1:].decode('ascii', errors='ignore').strip()
                elif tlv_type == LLDP_TLV_SYSTEM_NAME:
                    vlan_info.switch_name = tlv_value.decode('ascii', errors='ignore').strip()
                elif tlv_type == LLDP_TLV_SYSTEM_DESC:
                    vlan_info.switch_model = tlv_value.decode('ascii', errors='ignore').strip()
                elif tlv_type == LLDP_TLV_MGMT_ADDR and len(tlv_value) >= 6:
                    if tlv_value[1] == 1 and tlv_value[0] == 5:
                        vlan_info.switch_ip = '.'.join(str(b) for b in tlv_value[2:6])
                elif tlv_type == LLDP_TLV_ORG_SPECIFIC and len(tlv_value) >= 6:
                    if tlv_value[0:3] == IEEE_8021_OUI and tlv_value[3] == 1:
                        vlan_info.vlan_id = struct.unpack('!H', tlv_value[4:6])[0]
                offset += 2 + tlv_length
                if tlv_type == 0: break
            return vlan_info if vlan_info.vlan_id > 0 else None
        except Exception:
            return None


# ============================================================================
# CYBERSCORE - 100% piloté par les CVE/CVSS réels
# ============================================================================

class CyberScore:
    """
    Système de notation cybersécurité A-E basé sur les CVE réels.
    Prend en compte TOUS les CVE : services testés + scripts NSE.

    Principe de calcul (0 à 100) :
    ─────────────────────────────────────────────────────────────────────────
    1. COMPOSANTE GRAVITÉ PONDÉRÉE (0-50 pts)
       contribution = CVSS × rang_décroissant × age_factor × confidence
                      × finding_weight × ip_multiplier
       • rang_décroissant : 1er CVE 100%, 2e 70%, 3e 50%, puis −5%
       • age_factor (A)   : 0.5–1.0 selon ancienneté CVE (−5%/an)
       • confidence (A)   : CONFIRMED 1.0 | PROBABLE 0.7 | GENERIC 0.3
       • finding_weight (B): CONFIRMED 1.0 | EXPOSED 0.7 | INFORMATIONAL 0.3
       • ip_multiplier (C): ×1.3 si IP publique, ×1.0 sinon

    2. COMPOSANTE VOLUME (0-25 pts) — nombre de CVE distincts
       1-2 CVE → 5 pts | 3-5 → 10 pts | 6-15 → 15 pts
       16-50 → 20 pts | >50 → 25 pts

    3. COMPOSANTE EXPOSITION (0-15 pts) — surface d'attaque (D)
       Diversité : 3 pts par type de service distinct (max 12)
       Étendue   : +1 pt par couple (IP, service) au-delà (max 3)

    4. COMPOSANTE CVSS MAX (0-10 pts) — pire CVE individuel
       Bonus proportionnel au score CVSS le plus élevé

    Score final = min(100, gravité + volume + exposition + cvss_max)

    Grilles de notes :
       A (0-19)   : Aucune CVE critique, risque minimal
       B (20-39)  : Quelques CVE de faible/moyenne gravité
       C (40-59)  : CVE modérés ou accumulation de faibles
       D (60-79)  : CVE élevés ou multiples CVE modérés
       E (80-100) : CVE critiques ou accumulation sévère
    ─────────────────────────────────────────────────────────────────────────
    """

    SCORE_LEVELS = {
        'A': {'label': 'EXCELLENT', 'color': 'vert',   'min': 0,  'max': 19,  'emoji': '🟢'},
        'B': {'label': 'BON',       'color': 'bleu',   'min': 20, 'max': 39,  'emoji': '🔵'},
        'C': {'label': 'MOYEN',     'color': 'jaune',  'min': 40, 'max': 59,  'emoji': '🟡'},
        'D': {'label': 'MAUVAIS',   'color': 'orange', 'min': 60, 'max': 79,  'emoji': '🟠'},
        'E': {'label': 'CRITIQUE',  'color': 'rouge',  'min': 80, 'max': 100, 'emoji': '🔴'},
    }

    # Poids de confiance CVE (proposition A)
    CONFIDENCE_WEIGHT = {'CONFIRMED': 1.0, 'PROBABLE': 0.7, 'GENERIC': 0.3}
    # Poids du type de finding (proposition B)
    FINDING_WEIGHT = {'CONFIRMED': 1.0, 'EXPOSED': 0.7, 'INFORMATIONAL': 0.3}

    # Points attribués par sévérité CVSS (composante base)
    SEVERITY_POINTS = {
        'CRITICAL': 60,
        'HIGH':     40,
        'MEDIUM':   20,
        'LOW':       8,
        'NONE':      0,
        'UNKNOWN':   5,
    }

    # Barème volume CVE uniques (composante volume)
    VOLUME_THRESHOLDS = [
        (1,  2,  5),
        (3,  5,  10),
        (6,  15, 15),
        (16, 50, 20),
        (51, 99999, 25),
    ]

    @staticmethod
    def _cvss_to_severity(cvss: float) -> str:
        """Convertit un score CVSS numérique en label de sévérité."""
        if cvss == 0.0:           return 'NONE'
        elif cvss < 4.0:          return 'LOW'
        elif cvss < 7.0:          return 'MEDIUM'
        elif cvss < 9.0:          return 'HIGH'
        else:                     return 'CRITICAL'

    @staticmethod
    def _collect_unique_cves(vulnerabilities: List[Dict],
                             extra_cves: List[Dict] = None) -> List[Dict]:
        """Collecte tous les CVE uniques, tagués avec le contexte du résultat parent."""
        seen = set()
        unique = []
        # CVE des tests de services — on tague chaque CVE avec
        # _finding_type et _ip_context du résultat parent (propositions B/C)
        for vuln in vulnerabilities:
            ft = vuln.get('finding_type', 'INFORMATIONAL')
            ctx = vuln.get('ip_context', 'private')
            for cve in vuln.get('test_result', {}).get('cves', []):
                cve_id = cve.get('cve_id', '')
                if cve_id and cve_id not in seen:
                    seen.add(cve_id)
                    cve['_finding_type'] = ft
                    cve['_ip_context'] = ctx
                    unique.append(cve)
        # CVE additionnels (NSE, API, etc.) — détection script = CONFIRMED
        if extra_cves:
            for cve in extra_cves:
                cve_id = cve.get('cve_id', '')
                if cve_id and cve_id not in seen:
                    seen.add(cve_id)
                    cve.setdefault('_finding_type', 'CONFIRMED')
                    cve.setdefault('_ip_context', 'private')
                    unique.append(cve)
        # Trier par score CVSS décroissant
        unique.sort(
            key=lambda c: c.get('cvss_v3_score') or c.get('cvss_v2_score') or 0,
            reverse=True
        )
        return unique

    @staticmethod
    def calculate_score(vulnerabilities: List[Dict],
                        extra_cves: List[Dict] = None,
                        extra_ports: int = 0) -> Dict:
        """
        Calcule le Cyberscore 0-100 à partir de TOUS les CVE réels.

        :param vulnerabilities: résultats vulnérables (test_result avec cves)
        :param extra_cves: CVE additionnels (NSE, etc.) à inclure dans le calcul
        :param extra_ports: nombre de ports supplémentaires affectés (NSE)
        :return: dict complet du score
        """
        # ── Cas trivial ───────────────────────────────────────────────────
        unique_cves = CyberScore._collect_unique_cves(vulnerabilities,
                                                       extra_cves)
        if not unique_cves:
            return {
                'final_score':          0,
                'grade':                'A',
                'label':                'EXCELLENT',
                'emoji':                '🟢',
                'color':                'vert',
                'base_score':           0,
                'volume_score':         0,
                'exposure_score':       0,
                'cvss_max_score':       0,
                'total_vulnerabilities': 0,
                'total_cves':           0,
                'cve_by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'worst_cvss':           0.0,
                'worst_severity':       'NONE',
                'top_cves':             [],
                'vulnerability_counts': {},
            }

        # ── 1. Statistiques par sévérité ──────────────────────────────────
        cve_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        worst_cvss = 0.0

        for cve in unique_cves:
            raw_score = cve.get('cvss_v3_score') or cve.get('cvss_v2_score') or 0.0
            worst_cvss = max(worst_cvss, raw_score)

            declared_sev = (cve.get('severity') or '').upper()
            if declared_sev not in cve_by_severity:
                declared_sev = CyberScore._cvss_to_severity(raw_score)
            if declared_sev in cve_by_severity:
                cve_by_severity[declared_sev] += 1

        worst_severity = CyberScore._cvss_to_severity(worst_cvss)

        # ── 2. Composante GRAVITÉ PONDÉRÉE (0-50 pts) ─────────────────────
        # unique_cves est déjà trié par CVSS décroissant
        weighted_sum = 0.0
        for i, cve in enumerate(unique_cves):
            raw_cvss = cve.get('cvss_v3_score') or cve.get('cvss_v2_score') or 0.0
            # Facteur décroissant par rang
            if i == 0:
                rank_f = 1.0
            elif i == 1:
                rank_f = 0.7
            elif i == 2:
                rank_f = 0.5
            else:
                rank_f = max(0.1, 0.4 - (i - 3) * 0.05)
            # (A) Facteur d'âge × poids de confiance
            af = cve.get('age_factor', 1.0)
            cw = CyberScore.CONFIDENCE_WEIGHT.get(
                cve.get('confidence', ''), 0.5)
            # (B) Poids du type de finding
            fw = CyberScore.FINDING_WEIGHT.get(
                cve.get('_finding_type', ''), 0.5)
            # (C) Multiplicateur IP publique
            ip_mult = 1.3 if cve.get('_ip_context') == 'public' else 1.0

            weighted_sum += raw_cvss * rank_f * af * cw * fw * ip_mult
        # Normaliser : 1 CVE CRITICAL CONFIRMED frais → ~10 → 50 pts
        base_score = min(50, int(weighted_sum * 5.0))

        # ── 3. Composante VOLUME (0-25 pts) ───────────────────────────────
        n_cves = len(unique_cves)
        volume_score = 0
        for lo, hi, pts in CyberScore.VOLUME_THRESHOLDS:
            if lo <= n_cves <= hi:
                volume_score = pts
                break

        # ── 4. Composante EXPOSITION (0-15 pts) — proposition D ─────────
        # Diversité : types de services distincts (SSH ≠ FTP ≠ RDP)
        # Étendue   : couples (IP, service) au-delà de la diversité pure
        service_types = set()
        ip_service_pairs = set()
        vulnerability_counts = {}
        for vuln in vulnerabilities:
            t = vuln.get('test_result', {})
            svc = t.get('service', 'unknown')
            vtype = t.get('vulnerability_type', 'unknown')
            ip = vuln.get('ip', '')
            service_types.add(svc)
            if ip:
                ip_service_pairs.add((ip, svc))
            vulnerability_counts[vtype] = vulnerability_counts.get(vtype, 0) + 1

        n_types = len(service_types) + extra_ports
        n_pairs = len(ip_service_pairs) + extra_ports
        # 3 pts par type de service distinct (max 12)
        diversity_pts = min(12, n_types * 3)
        # +1 pt par couple (IP, service) au-delà des types (max 3)
        breadth_pts = min(3, max(0, n_pairs - n_types))
        exposure_score = min(15, diversity_pts + breadth_pts)

        # ── 5. Composante CVSS MAX (0-10 pts) ─────────────────────────────
        # Bonus proportionnel au pire score CVSS individuel
        cvss_max_score = min(10, int(worst_cvss))

        # ── 6. Score final ─────────────────────────────────────────────────
        final_score = min(100, base_score + volume_score + exposure_score + cvss_max_score)

        # ── 7. Détermination de la note ────────────────────────────────────
        grade = 'E'
        for lvl, info in CyberScore.SCORE_LEVELS.items():
            if info['min'] <= final_score <= info['max']:
                grade = lvl
                break

        level_info = CyberScore.SCORE_LEVELS[grade]

        return {
            'final_score':           final_score,
            'grade':                 grade,
            'label':                 level_info['label'],
            'emoji':                 level_info['emoji'],
            'color':                 level_info['color'],
            # Détail composantes (transparence totale)
            'base_score':            base_score,
            'volume_score':          volume_score,
            'exposure_score':        exposure_score,
            'cvss_max_score':        cvss_max_score,
            # Statistiques CVE
            'total_vulnerabilities': len(vulnerabilities),
            'total_cves':            n_cves,
            'cve_by_severity':       cve_by_severity,
            'worst_cvss':            round(worst_cvss, 1),
            'worst_severity':        worst_severity,
            'top_cves':              unique_cves[:10],
            'vulnerability_counts':  vulnerability_counts,
        }


# ============================================================================
# BANNER GRABBER — Détection produit/version par bannière réseau
# ============================================================================

class BannerGrabber:
    """
    Récupère les bannières réseau des services ouverts pour identifier
    le logiciel et la version, puis corrèle avec les CVE.
    """

    # Regex de détection produit/version à partir des bannières
    BANNER_PATTERNS = {
        'ssh': [
            (re.compile(r'SSH-[\d.]+-OpenSSH[_]([\d.p]+)', re.I), 'OpenSSH'),
            (re.compile(r'SSH-[\d.]+-dropbear[_]([\d.]+)', re.I), 'Dropbear'),
            (re.compile(r'SSH-[\d.]+-libssh[_-]([\d.]+)', re.I), 'libssh'),
        ],
        'ftp': [
            (re.compile(r'vsftpd\s+([\d.]+)', re.I), 'vsftpd'),
            (re.compile(r'ProFTPD\s+([\d.]+)', re.I), 'ProFTPD'),
            (re.compile(r'FileZilla Server\s+([\d.]+)', re.I), 'FileZilla Server'),
            (re.compile(r'Pure-FTPd', re.I), 'Pure-FTPd'),
            (re.compile(r'Microsoft FTP Service', re.I), 'Microsoft FTP'),
        ],
        'smtp': [
            (re.compile(r'Postfix', re.I), 'Postfix'),
            (re.compile(r'Exim\s+([\d.]+)', re.I), 'Exim'),
            (re.compile(r'Sendmail[/ ]([\d.]+)', re.I), 'Sendmail'),
            (re.compile(r'Microsoft .* ESMTP', re.I), 'Exchange'),
        ],
        'http': [
            (re.compile(r'Apache/([\d.]+)', re.I), 'Apache'),
            (re.compile(r'nginx/([\d.]+)', re.I), 'nginx'),
            (re.compile(r'Microsoft-IIS/([\d.]+)', re.I), 'IIS'),
            (re.compile(r'lighttpd/([\d.]+)', re.I), 'lighttpd'),
        ],
        'mysql': [
            (re.compile(r'([\d.]+)-MariaDB', re.I), 'MariaDB'),
            (re.compile(r'mysql[_-]native[_ ]password', re.I), 'MySQL'),
        ],
        'redis': [
            (re.compile(r'redis_version:([\d.]+)', re.I), 'Redis'),
        ],
        'telnet': [
            (re.compile(r'Ubuntu|Debian|CentOS|Red Hat|Fedora', re.I), 'Linux Telnet'),
            (re.compile(r'Microsoft Telnet', re.I), 'Microsoft Telnet'),
        ],
    }

    def __init__(self, timeout: int = 3):
        self.timeout = timeout

    def grab_banner(self, ip: str, port: int) -> Dict:
        """
        Tente de récupérer la bannière d'un service.
        Retourne {'banner': str, 'product': str, 'version': str}
        """
        result = {'banner': '', 'product': '', 'version': ''}
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                # Envoie un retour chariot pour provoquer une réponse
                try:
                    sock.sendall(b'\r\n')
                except Exception:
                    pass
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    banner = ''

            if banner:
                result['banner'] = banner[:500]
                product, version = self._parse_banner(banner, port)
                result['product'] = product
                result['version'] = version
        except Exception:
            pass
        return result

    def _parse_banner(self, banner: str, port: int) -> Tuple[str, str]:
        """Extrait le produit et la version depuis une bannière"""
        # Déterminer le type de service par port
        port_to_service = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'http',
            3306: 'mysql', 5432: 'postgresql', 6379: 'redis',
            8080: 'http', 8443: 'http',
        }
        service_type = port_to_service.get(port, '')

        # Chercher d'abord dans les patterns du service
        if service_type and service_type in self.BANNER_PATTERNS:
            for pattern, product_name in self.BANNER_PATTERNS[service_type]:
                match = pattern.search(banner)
                if match:
                    version = match.group(1) if match.lastindex else ''
                    return product_name, version

        # Fallback: chercher dans tous les patterns
        for patterns in self.BANNER_PATTERNS.values():
            for pattern, product_name in patterns:
                match = pattern.search(banner)
                if match:
                    version = match.group(1) if match.lastindex else ''
                    return product_name, version

        return '', ''

    def grab_banners_for_ports(self, ip: str, open_ports: List[Tuple[int, str]],
                                max_workers: int = 10) -> Dict[int, Dict]:
        """
        Récupère les bannières pour une liste de ports ouverts en parallèle.
        Retourne {port: {'banner': ..., 'product': ..., 'version': ...}}
        """
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.grab_banner, ip, port): port
                for port, _ in open_ports
            }
            for future in as_completed(futures):
                port = futures[future]
                try:
                    results[port] = future.result()
                except Exception:
                    results[port] = {'banner': '', 'product': '', 'version': ''}
        return results


# ============================================================================
# NMAP NSE SCANNER — Scripts de vulnérabilités Nmap
# ============================================================================

class NmapNSEScanner:
    """
    Interface pour les scripts NSE (Nmap Scripting Engine).
    Permet de lancer des scripts de détection de vulnérabilités
    et de parser les résultats (CVE-ID, descriptions, etc.).

    Catégories NSE supportées :
      - vuln     : Détection de vulnérabilités connues
      - safe     : Scripts non intrusifs
      - default  : Scripts standard Nmap
      - Personnalisé : Chemin ou nom de script spécifique
    """

    # Catégories NSE prédéfinies
    NSE_CATEGORIES = {
        'vuln': {
            'name': 'Vulnérabilités',
            'scripts': 'vuln',
            'description': 'Détection de vulnérabilités connues (SMB, SSL, HTTP...)',
            'intrusive': True,
        },
        'safe': {
            'name': 'Safe scripts',
            'scripts': 'safe',
            'description': 'Scripts non intrusifs et non dangereux',
            'intrusive': False,
        },
        'default': {
            'name': 'Default',
            'scripts': 'default',
            'description': 'Scripts Nmap par défaut',
            'intrusive': False,
        },
        'discovery': {
            'name': 'Découverte',
            'scripts': 'discovery',
            'description': 'Découverte d\'informations (DNS, SNMP, SMB...)',
            'intrusive': False,
        },
        'smb-vuln': {
            'name': 'SMB Vulnerabilities',
            'scripts': 'smb-vuln-*',
            'description': 'EternalBlue, SMBGhost, SambaCry, etc.',
            'intrusive': True,
        },
        'ssl': {
            'name': 'SSL/TLS Audit',
            'scripts': 'ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-cert',
            'description': 'Audit complet SSL/TLS (Heartbleed, POODLE, ciphers faibles)',
            'intrusive': False,
        },
        'http-vuln': {
            'name': 'HTTP Vulnerabilities',
            'scripts': 'http-vuln-*',
            'description': 'Vulnérabilités web (Shellshock, path traversal...)',
            'intrusive': True,
        },
        'auth': {
            'name': 'Authentification',
            'scripts': 'auth',
            'description': 'Tests d\'authentification faible',
            'intrusive': True,
        },
    }

    # Regex pour extraire les CVE-ID depuis les sorties NSE
    CVE_PATTERN = re.compile(r'(CVE-\d{4}-\d{4,})', re.I)

    # Mots-clés indiquant une vulnérabilité confirmée (output NSE)
    VULN_INDICATORS = [
        'VULNERABLE', 'State: VULNERABLE', 'is vulnerable',
        'LIKELY VULNERABLE', 'potentially vulnerable',
    ]

    NOT_VULN_INDICATORS = [
        'NOT VULNERABLE', 'State: NOT VULNERABLE',
        'not vulnerable', 'Could not determine',
    ]

    def __init__(self, cve_db: CVEDatabase = None):
        self.cve_db = cve_db

    @staticmethod
    def list_categories() -> str:
        """Retourne une description formatée des catégories NSE"""
        lines = [f"\n{'='*70}", "CATÉGORIES DE SCRIPTS NSE DISPONIBLES", f"{'='*70}\n"]
        for key, cat in NmapNSEScanner.NSE_CATEGORIES.items():
            intrusive = '⚠️  INTRUSIF' if cat['intrusive'] else '✅ SAFE'
            lines.append(f"  {key:15} {cat['name']:25} {intrusive}")
            lines.append(f"  {'':15} {cat['description']}")
            lines.append(f"  {'':15} Script(s): {cat['scripts']}")
            lines.append("")
        return '\n'.join(lines)

    def get_nmap_script_args(self, script_categories: List[str]) -> str:
        """
        Construit les arguments Nmap --script à partir des catégories choisies.
        Accepte des noms de catégories prédéfinies ou des noms de scripts libres.
        """
        scripts = []
        for cat in script_categories:
            if cat in self.NSE_CATEGORIES:
                scripts.append(self.NSE_CATEGORIES[cat]['scripts'])
            else:
                # Script personnalisé (ex: 'smb-vuln-ms17-010')
                scripts.append(cat)
        return ','.join(scripts)

    def build_scripts_arg(self, script_categories: List[str]) -> str:
        """Alias public pour construire la chaîne --script depuis les catégories."""
        return self.get_nmap_script_args(script_categories)

    def parse_nse_results(self, script_output: Dict) -> List[Dict]:
        """
        Parse les résultats des scripts NSE pour un port donné.

        :param script_output: dict {script_name: output_text} de python-nmap
        :return: liste de résultats NSE structurés
        """
        nse_results = []
        if not script_output:
            return nse_results

        for script_name, output in script_output.items():
            result = {
                'script_name': script_name,
                'output': output[:2000],
                'cve_ids': [],
                'is_vulnerable': False,
                'severity': 'INFO',
            }

            # Extraire les CVE-ID
            cve_matches = self.CVE_PATTERN.findall(output)
            result['cve_ids'] = list(set(cve_matches))

            # Déterminer si vulnérable
            output_upper = output.upper()
            for indicator in self.NOT_VULN_INDICATORS:
                if indicator.upper() in output_upper:
                    result['is_vulnerable'] = False
                    break
            else:
                for indicator in self.VULN_INDICATORS:
                    if indicator.upper() in output_upper:
                        result['is_vulnerable'] = True
                        break

            # Estimer la sévérité
            if result['is_vulnerable']:
                if result['cve_ids']:
                    result['severity'] = 'HIGH'
                else:
                    result['severity'] = 'MEDIUM'

            nse_results.append(result)

        return nse_results

    def enrich_nse_cves(self, nse_results: List[Dict]) -> List[Dict]:
        """
        Enrichit les résultats NSE avec les détails CVE depuis la base NVD.
        Recherche chaque CVE-ID trouvé dans les scripts pour obtenir
        le score CVSS, la description, etc.
        """
        if not self.cve_db:
            return nse_results

        for nse_result in nse_results:
            enriched_cves = []
            for cve_id in nse_result.get('cve_ids', []):
                # Récupérer les détails du CVE via l'API NVD
                detail = self.cve_db._fetch_cve_detail(cve_id)
                if detail:
                    cve_dict = self.cve_db._cve_to_dict(detail)
                    enriched_cves.append(cve_dict)
                    # Mettre à jour la sévérité du résultat NSE
                    if detail.severity == 'CRITICAL':
                        nse_result['severity'] = 'CRITICAL'
                    elif detail.severity == 'HIGH' and nse_result['severity'] != 'CRITICAL':
                        nse_result['severity'] = 'HIGH'
                    elif detail.severity == 'MEDIUM' and nse_result['severity'] not in ('CRITICAL', 'HIGH'):
                        nse_result['severity'] = 'MEDIUM'
                else:
                    # CVE non trouvé dans NVD (récent, réservé, ou réseau indisponible)
                    # On conserve l'entrée pour ne pas perdre l'information du script NSE
                    enriched_cves.append({
                        'cve_id': cve_id,
                        'description': f'Détecté par script NSE: {nse_result["script_name"]} '
                                       f'(score NVD non disponible — CVE récent ou réseau)',
                        'cvss_v3_score': 0.0,
                        'cvss_v2_score': 0.0,
                        'severity': 'UNKNOWN',
                        'nvd_url': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                        'confidence': 'GENERIC',
                    })
            nse_result['cve_details'] = enriched_cves

        return nse_results

    def run_nse_scan(self, nm, target: str, ports: List[int],
                     script_categories: List[str]) -> Dict:
        """
        Lance un scan NSE Nmap sur une cible.

        :param nm: Instance nmap.PortScanner
        :param target: IP cible
        :param ports: Liste des ports
        :param script_categories: Catégories de scripts à exécuter
        :return: Résultats NSE par port
        """
        scripts_arg = self.get_nmap_script_args(script_categories)
        sorted_ports = sorted(ports)
        if sorted_ports[-1] - sorted_ports[0] + 1 == len(sorted_ports):
            ports_str = f"{sorted_ports[0]}-{sorted_ports[-1]}"
        else:
            ports_str = ','.join(map(str, sorted_ports))

        # Vérifier si des catégories sont intrusives
        has_intrusive = any(
            self.NSE_CATEGORIES.get(cat, {}).get('intrusive', False)
            for cat in script_categories
        )
        if has_intrusive:
            print(f"  [⚠] Scripts NSE intrusifs activés: {scripts_arg}")

        print(f"  [*] Lancement des scripts NSE: {scripts_arg}...")

        nse_arguments = f'-sC -sV --script {scripts_arg}'
        nse_results_by_port = {}

        try:
            nm.scan(hosts=target, ports=ports_str, arguments=nse_arguments)

            if target not in nm.all_hosts():
                print(f"  [!] Aucun résultat NSE pour {target}")
                return nse_results_by_port

            for proto in nm[target].all_protocols():
                for port in sorted(nm[target][proto].keys()):
                    port_data = nm[target][proto][port]
                    script_output = port_data.get('script', {})

                    if script_output:
                        parsed = self.parse_nse_results(script_output)
                        parsed = self.enrich_nse_cves(parsed)

                        # Filtrer pour garder les résultats intéressants
                        interesting = [r for r in parsed
                                       if r['is_vulnerable'] or r['cve_ids']]

                        if interesting:
                            nse_results_by_port[port] = interesting
                            for r in interesting:
                                vuln_tag = '🔴 VULN' if r['is_vulnerable'] else '🔵 INFO'
                                cve_str = f" | CVE: {', '.join(r['cve_ids'][:3])}" if r['cve_ids'] else ""
                                print(f"    [{vuln_tag}] Port {port} - "
                                      f"{r['script_name']}{cve_str}")

        except Exception as e:
            print(f"  [!] Erreur scan NSE: {e}")

        total_vulns = sum(
            1 for results in nse_results_by_port.values()
            for r in results if r['is_vulnerable']
        )
        total_cves = sum(
            len(r['cve_ids']) for results in nse_results_by_port.values()
            for r in results
        )
        print(f"  [+] NSE terminé: {total_vulns} vulnérabilité(s), "
              f"{total_cves} CVE-ID trouvé(s) sur {len(nse_results_by_port)} port(s)")

        return nse_results_by_port


# ============================================================================
# BASE CPE ENRICHIE — Corrélation port/bannière → produit → CVE
# ============================================================================

CPE_DATABASE = {
    'openssh': {
        'cpe_prefix': 'cpe:2.3:a:openbsd:openssh',
        'default_ports': [22],
        'banner_regex': r'OpenSSH[_]([\d.p]+)',
        'known_vulns': {
            '7.4':  ['CVE-2017-15906', 'CVE-2018-15473'],
            '7.6':  ['CVE-2018-15473', 'CVE-2018-20685'],
            '7.9':  ['CVE-2019-6111', 'CVE-2019-6110'],
            '8.0':  ['CVE-2019-6111'],
            '8.1':  ['CVE-2019-16905'],
            '8.2':  ['CVE-2020-14145', 'CVE-2020-15778'],
            '8.3':  ['CVE-2020-14145'],
            '8.4':  ['CVE-2021-28041', 'CVE-2021-41617'],
            '8.5':  ['CVE-2021-41617'],
            '8.6':  ['CVE-2021-41617'],
            '8.8':  ['CVE-2023-38408'],
            '8.9':  ['CVE-2023-38408', 'CVE-2023-48795'],
            '9.0':  ['CVE-2023-48795'],
            '9.1':  ['CVE-2023-48795', 'CVE-2023-51385'],
            '9.3':  ['CVE-2024-6387'],
            '9.6':  ['CVE-2024-6387'],
            '9.7':  ['CVE-2024-6387'],
        },
    },
    'vsftpd': {
        'cpe_prefix': 'cpe:2.3:a:vsftpd_project:vsftpd',
        'default_ports': [21],
        'banner_regex': r'vsftpd\s+([\d.]+)',
        'known_vulns': {
            '2.3.4': ['CVE-2011-2523'],
        },
    },
    'proftpd': {
        'cpe_prefix': 'cpe:2.3:a:proftpd:proftpd',
        'default_ports': [21],
        'banner_regex': r'ProFTPD\s+([\d.]+)',
        'known_vulns': {
            '1.3.5': ['CVE-2015-3306'],
            '1.3.6': ['CVE-2019-12815'],
        },
    },
    'apache': {
        'cpe_prefix': 'cpe:2.3:a:apache:http_server',
        'default_ports': [80, 443, 8080, 8443],
        'banner_regex': r'Apache/([\d.]+)',
        'known_vulns': {
            '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
            '2.4.50': ['CVE-2021-42013'],
            '2.4.51': ['CVE-2022-22720'],
            '2.4.53': ['CVE-2022-26377', 'CVE-2022-31813'],
            '2.4.54': ['CVE-2022-37436'],
            '2.4.55': ['CVE-2023-25690'],
            '2.4.57': ['CVE-2023-43622', 'CVE-2023-45802'],
        },
    },
    'nginx': {
        'cpe_prefix': 'cpe:2.3:a:f5:nginx',
        'default_ports': [80, 443, 8080],
        'banner_regex': r'nginx/([\d.]+)',
        'known_vulns': {
            '1.17': ['CVE-2019-20372'],
            '1.18': ['CVE-2021-23017'],
            '1.20': ['CVE-2021-23017'],
        },
    },
    'samba': {
        'cpe_prefix': 'cpe:2.3:a:samba:samba',
        'default_ports': [139, 445],
        'banner_regex': r'Samba\s+([\d.]+)',
        'known_vulns': {
            '3.5':  ['CVE-2017-7494'],
            '4.6':  ['CVE-2017-7494'],
            '4.7':  ['CVE-2017-7494', 'CVE-2017-12150'],
            '4.10': ['CVE-2020-1472'],
            '4.13': ['CVE-2021-44142'],
        },
    },
    'mysql': {
        'cpe_prefix': 'cpe:2.3:a:oracle:mysql',
        'default_ports': [3306],
        'banner_regex': r'([\d.]+)-MariaDB|mysql[_-]native',
        'known_vulns': {
            '5.5': ['CVE-2012-2122', 'CVE-2016-6662'],
            '5.6': ['CVE-2016-6662'],
            '5.7': ['CVE-2016-6662', 'CVE-2018-2562'],
            '8.0': ['CVE-2021-2307', 'CVE-2022-21270'],
        },
    },
    'postgresql': {
        'cpe_prefix': 'cpe:2.3:a:postgresql:postgresql',
        'default_ports': [5432],
        'banner_regex': r'PostgreSQL\s+([\d.]+)',
        'known_vulns': {
            '9.6':  ['CVE-2019-10164'],
            '11':   ['CVE-2019-10164'],
            '12':   ['CVE-2020-25695'],
            '13':   ['CVE-2021-23214'],
            '14':   ['CVE-2022-2625'],
            '15':   ['CVE-2023-5868'],
        },
    },
    'redis': {
        'cpe_prefix': 'cpe:2.3:a:redis:redis',
        'default_ports': [6379],
        'banner_regex': r'redis_version:([\d.]+)',
        'known_vulns': {
            '5.0': ['CVE-2021-32761', 'CVE-2022-0543'],
            '6.0': ['CVE-2021-32761', 'CVE-2022-0543'],
            '6.2': ['CVE-2022-0543'],
            '7.0': ['CVE-2023-28856'],
        },
    },
    'bind': {
        'cpe_prefix': 'cpe:2.3:a:isc:bind',
        'default_ports': [53],
        'banner_regex': r'BIND\s+([\d.]+)',
        'known_vulns': {
            '9.11': ['CVE-2020-8617', 'CVE-2021-25216'],
            '9.16': ['CVE-2021-25216', 'CVE-2022-2795'],
            '9.18': ['CVE-2022-2795', 'CVE-2023-2828'],
        },
    },
    'openssl': {
        'cpe_prefix': 'cpe:2.3:a:openssl:openssl',
        'default_ports': [443],
        'banner_regex': r'OpenSSL/([\d.]+\w*)',
        'known_vulns': {
            '1.0.1': ['CVE-2014-0160'],  # Heartbleed
            '1.0.2': ['CVE-2016-2107'],
            '1.1.0': ['CVE-2017-3737'],
            '1.1.1': ['CVE-2021-3449', 'CVE-2022-0778'],
            '3.0.0': ['CVE-2022-3602', 'CVE-2022-3786'],
        },
    },
    'iis': {
        'cpe_prefix': 'cpe:2.3:a:microsoft:internet_information_services',
        'default_ports': [80, 443],
        'banner_regex': r'Microsoft-IIS/([\d.]+)',
        'known_vulns': {
            '7.5': ['CVE-2015-1635'],
            '8.0': ['CVE-2015-1635'],
            '10.0': ['CVE-2021-31166'],
        },
    },
    'tomcat': {
        'cpe_prefix': 'cpe:2.3:a:apache:tomcat',
        'default_ports': [8080, 8443],
        'banner_regex': r'Apache[- ]Tomcat/([\d.]+)',
        'known_vulns': {
            '8.5':  ['CVE-2020-1938'],  # GhostCat
            '9.0':  ['CVE-2020-1938', 'CVE-2021-25329'],
            '10.0': ['CVE-2021-25329'],
        },
    },
}


def lookup_cpe_database(product: str, version: str = '') -> List[str]:
    """
    Cherche les CVE connus dans la base CPE locale pour un produit/version.
    Retourne une liste de CVE-ID.
    """
    product_lower = product.lower().strip()
    for key, entry in CPE_DATABASE.items():
        if key in product_lower or product_lower in key:
            if version:
                # Chercher la version exacte ou le préfixe
                for known_ver, cve_list in entry.get('known_vulns', {}).items():
                    if version.startswith(known_ver) or known_ver.startswith(version):
                        return cve_list
                # Pas de version exacte → retourner la dernière version connue
                all_cves = []
                for cve_list in entry.get('known_vulns', {}).values():
                    all_cves.extend(cve_list)
                return list(set(all_cves))[:5]
            else:
                # Sans version, retourner les 5 CVE les plus récents
                all_cves = []
                for cve_list in entry.get('known_vulns', {}).values():
                    all_cves.extend(cve_list)
                return list(set(all_cves))[:5]
    return []


# ============================================================================
# SERVICE TESTER (avec corrélation CVE)
# ============================================================================

class ServiceTester:
    def __init__(self, timeout: int = 3, cve_db: CVEDatabase = None):
        self.timeout = timeout
        self.cve_db = cve_db
    
    def _enrich_with_cves(self, result: Dict, vuln_type: str, service: str = "",
                           product: str = "", version: str = "",
                           ip: str = "") -> Dict:
        """Enrichit un résultat avec les CVE, le finding_type, le risk_score et le contexte IP."""
        # ── Contexte réseau (approche 4) ────────────────────────
        try:
            is_private = ipaddress.ip_address(ip).is_private if ip else True
        except ValueError:
            is_private = True
        result['ip_context'] = 'private' if is_private else 'public'

        # ── Finding type (approche 1) ─────────────────────────────
        CONFIRMED_TYPES = {
            'ftp_anonymous', 'ssh_default_creds', 'telnet_default_creds',
            'smb_null_session', 'smb_guest_access', 'smb_default_creds',
            'ldap_anonymous', 'mysql_no_password', 'mysql_default_creds',
            'redis_no_auth', 'mongodb_no_auth', 'postgresql_no_password',
            'postgresql_default_creds', 'mssql_default_creds',
            'smtp_open_relay', 'vnc_no_auth', 'http_default_creds',
            'snmp_write_community', 'snmp_default_community',
        }
        EXPOSED_TYPES = {
            'ftp_exposed', 'telnet_exposed', 'rdp_exposed', 'vnc_exposed',
            'smb_v1', 'dns_zone_transfer',
        }
        if vuln_type in CONFIRMED_TYPES:
            result['finding_type'] = 'CONFIRMED'
        elif vuln_type in EXPOSED_TYPES:
            result['finding_type'] = 'EXPOSED'
        else:
            result['finding_type'] = 'INFORMATIONAL'

        # ── Risk score local (approche 3) ─────────────────────────
        BASE_RISK = {
            # CONFIRMED
            'redis_no_auth': 10.0, 'mongodb_no_auth': 9.5,
            'smb_null_session': 9.5, 'ldap_anonymous': 9.0,
            'mysql_no_password': 9.5, 'postgresql_no_password': 9.5,
            'mssql_default_creds': 9.0, 'ftp_anonymous': 7.5,
            'ssh_default_creds': 8.8, 'telnet_default_creds': 9.8,
            'smb_guest_access': 8.5, 'smb_default_creds': 9.0,
            'mysql_default_creds': 8.5, 'postgresql_default_creds': 8.5,
            'smtp_open_relay': 7.5, 'vnc_no_auth': 9.8,
            'http_default_creds': 9.1, 'snmp_write_community': 9.8,
            'snmp_default_community': 7.5,
            # EXPOSED
            'ftp_exposed': 3.0, 'telnet_exposed': 7.0,
            'rdp_exposed': 4.0, 'vnc_exposed': 4.0,
            'smb_v1': 8.8, 'dns_zone_transfer': 5.3,
            # INFORMATIONAL
            'http_sensitive_paths': 4.0, 'http_info_disclosure': 2.0,
            'service_detected': 1.0,
        }
        base = BASE_RISK.get(vuln_type, 2.0)
        # Majoration +1.5 si IP publique sur service critique
        if not is_private and result['finding_type'] in ('CONFIRMED', 'EXPOSED'):
            base = min(10.0, base + 1.5)
        # Minoration si RDP avec NLA activé
        if vuln_type == 'rdp_exposed' and result.get('nla_enabled'):
            base = max(0.0, base - 2.0)
        result['risk_score'] = round(base, 1)

        if not self.cve_db:
            return result
        # Chercher les CVE dès qu'on a un produit/version, même sans vuln de creds
        if not result.get('vulnerable') and not product and not version:
            return result
        
        cves = self.cve_db.get_cves_for_vulnerability(
            vuln_type=vuln_type,
            service=service,
            product=product,
            version=version
        )
        
        if cves:
            result['cves'] = [self.cve_db._cve_to_dict(cve) for cve in cves]
            result['cve_count'] = len(cves)
            result['max_cvss'] = self.cve_db.get_max_cvss_score(cves)
            result['top_cve_id'] = cves[0].cve_id if cves else None
            
            # Mettre à jour les détails avec le CVE le plus sévère
            if cves:
                top_cve = cves[0]
                severity_emoji = {
                    'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 
                    'LOW': '🟢', 'UNKNOWN': '⚪'
                }.get(top_cve.severity, '⚪')
                
                result['details'] += (
                    f" | {severity_emoji} CVE: {top_cve.cve_id} "
                    f"(CVSS: {top_cve.cvss_v3_score or top_cve.cvss_v2_score:.1f})"
                )
        else:
            result['cves'] = []
            result['cve_count'] = 0

        return result
    
    def test_ftp(self, ip: str, port: int) -> Dict:
        result = {'service': 'FTP', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'credentials': None, 'cves': []}
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=self.timeout)
            # FTP ouvert = vulnérabilité (transmission en clair)
            result['vulnerable'] = True
            result['vulnerability_type'] = 'ftp_exposed'
            result['details'] = '🟠 MAUVAIS: Service FTP exposé (transmission en clair)'
            # Tester en plus l'accès anonymous
            try:
                response = ftp.login('anonymous', 'anonymous@example.com')
                if '230' in response:
                    result['vulnerability_type'] = 'ftp_anonymous'
                    result['credentials'] = 'anonymous:anonymous@example.com'
                    result['details'] = '🔴 CRITIQUE: Connexion anonyme FTP réussie (transmission en clair)'
                    try:
                        files = ftp.nlst()
                        result['details'] += f' - {len(files)} fichiers/dossiers accessibles'
                        result['file_list'] = files[:10]
                    except Exception: pass
            except Exception: pass
            ftp.quit()
        except Exception as e:
            result['details'] = f'Connexion échouée: {str(e)}'
        return result
    
    def test_ssh(self, ip: str, port: int) -> Dict:
        result = {'service': 'SSH', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'credentials': None, 'cves': []}
        default_creds = [
            ('root', 'root'), ('root', 'toor'), ('root', 'password'),
            ('admin', 'admin'), ('admin', 'password'), ('user', 'user'),
            ('test', 'test'), ('ubuntu', 'ubuntu'),
        ]
        for username, password in default_creds:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port=port, username=username, password=password,
                            timeout=self.timeout, allow_agent=False, look_for_keys=False,
                            banner_timeout=self.timeout)
                result['vulnerable'] = True
                result['vulnerability_type'] = 'ssh_default_creds'
                result['credentials'] = f'{username}:{password}'
                result['details'] = f'🟠 MAUVAIS: Identifiants par défaut SSH: {username}/{password}'
                ssh.close()
                break
            except paramiko.AuthenticationException:
                continue
            except (paramiko.SSHException, Exception):
                break
        if not result['vulnerable']:
            result['details'] = 'Aucun identifiant par défaut trouvé'
        return result
    
    def test_telnet(self, ip: str, port: int) -> Dict:
        result = {'service': 'Telnet', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'banner': None, 'credentials': None, 'cves': []}
        default_creds = [
            ('root', 'root'), ('root', 'toor'), ('root', 'password'), ('root', ''),
            ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
            ('user', 'user'), ('test', 'test'),
        ]
        if not HAS_TELNETLIB:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                result['vulnerable'] = True
                result['vulnerability_type'] = 'telnet_exposed'
                result['details'] = '🔴 CRITIQUE: Service Telnet exposé (non chiffré)'
                try:
                    sock.sendall(b'\r\n')
                    banner = sock.recv(1024).decode('ascii', errors='ignore')
                    if banner.strip():
                        result['banner'] = banner[:200]
                except Exception: pass
                sock.close()
            except Exception:

                result['details'] = 'Service inaccessible'
            return result
        
        try:
            tn = telnetlib.Telnet(ip, port, timeout=self.timeout)
            banner = tn.read_until(b"login:", timeout=3).decode('ascii', errors='ignore')
            result['vulnerable'] = True
            result['vulnerability_type'] = 'telnet_exposed'
            result['details'] = '🔴 CRITIQUE: Service Telnet exposé (non chiffré)'
            if banner.strip():
                result['banner'] = banner[:200]
            # Tester les credentials par défaut
            login_found = False
            if 'login' in banner.lower():
                for username, password in default_creds:
                    try:
                        tn2 = telnetlib.Telnet(ip, port, timeout=self.timeout)
                        tn2.read_until(b"login:", timeout=3)
                        tn2.write(username.encode('ascii') + b'\n')
                        resp = tn2.read_until(b"assword:", timeout=3).decode('ascii', errors='ignore')
                        if 'assword' in resp:
                            tn2.write(password.encode('ascii') + b'\n')
                            login_resp = tn2.read_some().decode('ascii', errors='ignore')
                            # Échec si on revoit "login:" ou "incorrect" ou "denied"
                            if not any(w in login_resp.lower() for w in ['login:', 'incorrect', 'denied', 'failed', 'invalid']):
                                login_found = True
                                result['credentials'] = f'{username}:{password}'
                                result['vulnerability_type'] = 'telnet_default_creds'
                                result['details'] = (f'🔴 CRITIQUE: Telnet identifiants par défaut '
                                                     f'{username}/{password}')
                        tn2.close()
                        if login_found:
                            break
                    except Exception:
                        continue
            tn.close()
        except Exception:

            result['details'] = 'Service inaccessible'
        return result
    
    def test_http(self, ip: str, port: int, use_https: bool = False) -> Dict:
        protocol = 'https' if use_https else 'http'
        result = {'service': f'{protocol.upper()}', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'headers': {}, 'sensitive_paths': [], 'cves': [],
                  'product': '', 'version': '', 'credentials': None}
        # Credentials par défaut à tester sur les pages de login HTTP
        http_default_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
            ('root', 'root'), ('root', 'toor'), ('administrator', 'admin'),
            ('user', 'user'), ('test', 'test'),
        ]
        try:
            url = f'{protocol}://{ip}:{port}'
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            result['details'] = f'Status: {response.status_code}'
            
            sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']
            for header in sensitive_headers:
                if header in response.headers:
                    result['headers'][header] = response.headers[header]
                    result['vulnerability_type'] = 'http_info_disclosure'
                    result['details'] += f' | {header}: {response.headers[header]}'
                    # Extraire produit/version du header Server
                    if header == 'Server':
                        server_val = response.headers[header]
                        parts = server_val.split('/')
                        if len(parts) >= 2:
                            result['product'] = parts[0].strip()
                            result['version'] = parts[1].split(' ')[0].strip()
            
            sensitive_paths = ['/admin', '/administrator', '/login', '/wp-admin',
                               '/phpmyadmin', '/phpinfo.php', '/.git/config', 
                               '/backup', '/config.php', '/.env']
            for path in sensitive_paths:
                try:
                    test_url = f'{protocol}://{ip}:{port}{path}'
                    test_resp = requests.get(test_url, timeout=self.timeout, verify=False)
                    if test_resp.status_code in [200, 301, 302]:
                        result['vulnerable'] = True
                        result['vulnerability_type'] = 'http_sensitive_paths'
                        result['sensitive_paths'].append(path)
                except Exception:

                    continue
            
            if result['sensitive_paths']:
                result['details'] += f' | 🟡 Pages sensibles: {", ".join(result["sensitive_paths"][:3])}'
            
            # Test HTTP Basic Auth sur les endpoints sensibles qui renvoient 401
            auth_paths = ['/admin', '/administrator', '/manager', '/manager/html']
            for path in auth_paths:
                try:
                    test_url = f'{protocol}://{ip}:{port}{path}'
                    test_resp = requests.get(test_url, timeout=self.timeout, verify=False)
                    if test_resp.status_code == 401:
                        # Page protégée par Basic Auth → tester les credentials
                        for username, password in http_default_creds:
                            try:
                                auth_resp = requests.get(
                                    test_url, timeout=self.timeout, verify=False,
                                    auth=(username, password)
                                )
                                if auth_resp.status_code in [200, 301, 302]:
                                    result['vulnerable'] = True
                                    result['vulnerability_type'] = 'http_default_creds'
                                    result['credentials'] = f'{username}:{password}'
                                    result['details'] += (f' | 🔴 HTTP Basic Auth: '
                                                          f'{username}/{password} sur {path}')
                                    break
                            except Exception:

                                continue
                        if result.get('credentials'):
                            break
                except Exception:

                    continue
            
        except Exception as e:
            result['details'] = f'Erreur: {str(e)}'
        
        return result
    
    def test_smb(self, ip: str, port: int = 445) -> Dict:
        result = {'service': 'SMB', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'shares': [], 'credentials': None, 'cves': []}
        try:
            from smb.SMBConnection import SMBConnection

            # Liste de credentials à tester (ordre : null session → guest → défauts courants)
            smb_creds = [
                ('', '',             'smb_null_session',   '🔴 CRITIQUE: SMB Null Session autorisée'),
                ('guest', '',        'smb_guest_access',   '🟠 MAUVAIS: SMB Guest access autorisé (guest:vide)'),
                ('guest', 'guest',   'smb_default_creds',  '🟠 MAUVAIS: SMB credentials par défaut (guest:guest)'),
                ('smbguest', 'smbguest', 'smb_default_creds', '🟠 MAUVAIS: SMB credentials par défaut (smbguest:smbguest)'),
                ('admin', 'admin',   'smb_default_creds',  '🔴 CRITIQUE: SMB credentials par défaut (admin:admin)'),
                ('administrator', 'password', 'smb_default_creds', '🔴 CRITIQUE: SMB credentials par défaut (administrator:password)'),
            ]

            for username, password, vuln_type, detail_msg in smb_creds:
                try:
                    conn = SMBConnection(username, password, 'client', ip,
                                         use_ntlm_v2=True, is_direct_tcp=True)
                    if conn.connect(ip, port, timeout=self.timeout):
                        result['vulnerable'] = True
                        result['vulnerability_type'] = vuln_type
                        result['details'] = detail_msg
                        result['credentials'] = f'{username}:{password}' if username else 'null session'
                        try:
                            shares = conn.listShares(timeout=self.timeout)
                            result['shares'] = [s.name for s in shares if not s.isSpecial]
                            result['details'] += f' | {len(result["shares"])} partages accessibles'
                        except Exception:
                            pass
                        conn.close()
                        break
                except Exception:
                    continue

            if not result['vulnerable']:
                result['details'] = 'Authentification requise'
        except ImportError:
            result['details'] = 'Module pysmb non installé (pip install pysmb)'
        except Exception as e:
            result['details'] = f'Erreur: {str(e)}'
        return result
    
    def test_dns(self, ip: str, port: int = 53, domain: str = None) -> Dict:
        result = {'service': 'DNS', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'records': [], 'cves': []}
        try:
            import dns.resolver, dns.zone, dns.query
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]
            resolver.timeout = self.timeout
            result['details'] = 'Serveur DNS actif'
            if domain:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ip, domain, timeout=self.timeout))
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'dns_zone_transfer'
                    result['details'] = f'🟡 MOYEN: Zone transfer autorisé pour {domain}'
                    records = [str(name) for name, _ in list(zone.items())[:10]]
                    result['records'] = records
                    result['details'] += f' | {len(list(zone.items()))} enregistrements exposés'
                except Exception:

                    result['details'] += ' | Zone transfer non autorisé'
            else:
                result['details'] += ' | Pas de domaine spécifié'
        except ImportError:
            result['details'] = 'Module dnspython non installé'
        except Exception as e:
            result['details'] = f'Erreur: {str(e)}'
        return result
    
    def test_ldap(self, ip: str, port: int = 389) -> Dict:
        result = {'service': 'LDAP', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'base_dn': None, 'cves': []}
        try:
            from ldap3 import Server, Connection, ALL, ANONYMOUS
            server = Server(ip, port=port, get_info=ALL, connect_timeout=self.timeout)
            conn = Connection(server, authentication=ANONYMOUS)
            if conn.bind():
                result['vulnerable'] = True
                result['vulnerability_type'] = 'ldap_anonymous'
                result['details'] = '🔴 CRITIQUE: LDAP Anonymous Bind autorisé'
                if server.info.naming_contexts:
                    result['base_dn'] = str(server.info.naming_contexts[0])
                    result['details'] += f' | Base DN: {result["base_dn"]}'
                conn.unbind()
            else:
                result['details'] = 'Authentification requise'
        except ImportError:
            result['details'] = 'Module ldap3 non installé'
        except Exception as e:
            result['details'] = f'Erreur: {str(e)}'
        return result
    
    def test_rdp(self, ip: str, port: int = 3389) -> Dict:
        result = {'service': 'RDP', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'credentials': None, 'nla_enabled': None, 'cves': []}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            result['vulnerable'] = True
            result['vulnerability_type'] = 'rdp_exposed'
            result['details'] = '🟠 MAUVAIS: RDP exposé (risque BlueKeep/brute force)'
            # Vérifier NLA (Network Level Authentication) via le handshake RDP
            try:
                # Envoyer une requête de négociation RDP (X.224 Connection Request)
                # tpktHeader(4) + x224Crq(7) + RDP Nego Request
                nego_req = (
                    b'\x03\x00'          # TPKT version + reserved
                    b'\x00\x13'          # TPKT length = 19
                    b'\x0e'              # X.224 length
                    b'\xe0'              # X.224 CR (Connection Request)
                    b'\x00\x00'          # DST-REF
                    b'\x00\x00'          # SRC-REF
                    b'\x00'              # Class
                    b'\x01'              # RDP Negotiation Request
                    b'\x00'              # flags
                    b'\x08\x00'          # length of nego request = 8
                    b'\x03\x00\x00\x00'  # requestedProtocols: TLS + CredSSP (NLA)
                )
                sock.sendall(nego_req)
                resp = sock.recv(1024)
                if len(resp) >= 19:
                    nego_type = resp[11] if len(resp) > 11 else 0
                    if nego_type == 0x02:  # Negotiation Response
                        selected_proto = resp[15] if len(resp) > 15 else 0
                        if selected_proto == 0:
                            result['nla_enabled'] = False
                            result['details'] += ' | ⚠️ NLA désactivé (accès sans pré-authentification)'
                        else:
                            result['nla_enabled'] = True
                            result['details'] += ' | NLA activé'
                    elif nego_type == 0x03:  # Negotiation Failure
                        result['nla_enabled'] = False
                        result['details'] += ' | ⚠️ NLA non supporté'
            except Exception:
                pass
            sock.close()
        except Exception:

            result['details'] = 'Service inaccessible'
        return result
    
    def test_mysql(self, ip: str, port: int) -> Dict:
        result = {'service': 'MySQL', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'credentials': None, 'cves': []}
        mysql_creds = [
            ('root', ''),
            ('root', 'root'), ('root', 'toor'), ('root', 'password'), ('root', 'mysql'),
            ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
            ('mysql', 'mysql'), ('test', 'test'), ('user', 'user'),
            ('dbadmin', 'dbadmin'), ('db', 'db'),
        ]
        try:
            import pymysql
            for username, password in mysql_creds:
                try:
                    conn = pymysql.connect(host=ip, port=port, user=username,
                                           password=password,
                                           connect_timeout=self.timeout)
                    result['vulnerable'] = True
                    result['credentials'] = f'{username}:{password}'
                    if password == '':
                        result['vulnerability_type'] = 'mysql_no_password'
                        result['details'] = f'🔴 CRITIQUE: MySQL {username} sans mot de passe'
                    else:
                        result['vulnerability_type'] = 'mysql_default_creds'
                        result['details'] = f'🟠 MAUVAIS: MySQL identifiants par défaut {username}/{password}'
                    conn.close()
                    break
                except pymysql.err.OperationalError:
                    continue
                except Exception:
                    break
            if not result['vulnerable']:
                result['details'] = 'Authentification requise'
        except ImportError:
            result['details'] = 'Module pymysql non installé'
        except Exception:
            result['details'] = 'Authentification requise'
        return result
    
    def test_redis(self, ip: str, port: int) -> Dict:
        result = {'service': 'Redis', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'cves': []}
        try:
            import redis
            r = redis.Redis(host=ip, port=port, socket_timeout=self.timeout,
                           socket_connect_timeout=self.timeout)
            r.ping()
            result['vulnerable'] = True
            result['vulnerability_type'] = 'redis_no_auth'
            result['details'] = '🟠 MAUVAIS: Redis accessible sans authentification'
            try:
                info = r.info()
                result['details'] += f' | Version: {info.get("redis_version", "unknown")}'
                result['product'] = 'Redis'
                result['version'] = info.get("redis_version", "")
            except Exception: pass
        except ImportError:
            result['details'] = 'Module redis non installé'
            return result
        except Exception:

            result['details'] = 'Authentification requise'
        return result
    
    def test_mongodb(self, ip: str, port: int) -> Dict:
        result = {'service': 'MongoDB', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'cves': []}
        try:
            from pymongo import MongoClient
            client = MongoClient(ip, port, serverSelectionTimeoutMS=self.timeout*1000)
            client.server_info()
            result['vulnerable'] = True
            result['vulnerability_type'] = 'mongodb_no_auth'
            result['details'] = '🟠 MAUVAIS: MongoDB accessible sans authentification'
            try:
                server_info = client.server_info()
                mongo_ver = server_info.get('version', '')
                result['product'] = 'MongoDB'
                result['version'] = mongo_ver
                result['details'] += f' | Version: {mongo_ver}'
            except Exception: pass
            try:
                dbs = client.list_database_names()
                result['details'] += f' | {len(dbs)} bases trouvées'
            except Exception: pass
        except ImportError:
            result['details'] = 'Module pymongo non installé'
        except Exception:

            result['details'] = 'Authentification requise'
        return result
    
    def test_postgresql(self, ip: str, port: int) -> Dict:
        result = {'service': 'PostgreSQL', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'credentials': None, 'cves': []}
        pg_creds = [
            ('postgres', 'postgres'), ('postgres', ''), ('postgres', 'password'),
            ('admin', 'admin'), ('root', 'root'),
        ]
        try:
            import psycopg2
            for username, password in pg_creds:
                try:
                    conn = psycopg2.connect(host=ip, port=port, user=username,
                                            password=password, connect_timeout=self.timeout,
                                            dbname='postgres')
                    result['vulnerable'] = True
                    result['credentials'] = f'{username}:{password}'
                    if password == '':
                        result['vulnerability_type'] = 'postgresql_no_password'
                        result['details'] = f'🔴 CRITIQUE: PostgreSQL {username} sans mot de passe'
                    else:
                        result['vulnerability_type'] = 'postgresql_default_creds'
                        result['details'] = f'🟠 MAUVAIS: PostgreSQL identifiants par défaut {username}/{password}'
                    try:
                        cur = conn.cursor()
                        cur.execute("SELECT version()")
                        ver = cur.fetchone()[0]
                        result['product'] = 'PostgreSQL'
                        m = re.search(r'PostgreSQL\s+([\d.]+)', ver)
                        if m:
                            result['version'] = m.group(1)
                        result['details'] += f' | Version: {ver[:60]}'
                        cur.close()
                    except Exception:
                        pass
                    conn.close()
                    break
                except Exception:
                    continue
            if not result['vulnerable']:
                result['details'] = 'Authentification requise'
        except ImportError:
            result['details'] = 'Module psycopg2 non installé (pip install psycopg2-binary)'
        return result
    
    def test_mssql(self, ip: str, port: int) -> Dict:
        result = {'service': 'MSSQL', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'credentials': None, 'cves': []}
        mssql_creds = [
            ('sa', ''), ('sa', 'sa'), ('sa', 'password'), ('sa', 'Password1'),
            ('admin', 'admin'),
        ]
        try:
            import pymssql
            for username, password in mssql_creds:
                try:
                    conn = pymssql.connect(server=ip, port=port, user=username,
                                           password=password, login_timeout=self.timeout)
                    result['vulnerable'] = True
                    result['credentials'] = f'{username}:{password}'
                    result['vulnerability_type'] = 'mssql_default_creds'
                    result['details'] = f'🔴 CRITIQUE: MSSQL identifiants par défaut {username}/{password}'
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT @@VERSION")
                        ver = cursor.fetchone()[0]
                        result['product'] = 'SQL Server'
                        result['details'] += f' | {ver[:60]}'
                    except Exception:
                        pass
                    conn.close()
                    break
                except Exception:
                    continue
            if not result['vulnerable']:
                result['details'] = 'Authentification requise'
        except ImportError:
            result['details'] = 'Module pymssql non installé (pip install pymssql)'
        return result
    
    def test_smtp(self, ip: str, port: int) -> Dict:
        result = {'service': 'SMTP', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'cves': []}
        try:
            import smtplib
            smtp = smtplib.SMTP(timeout=self.timeout)
            smtp.connect(ip, port)
            banner = smtp.docmd('EHLO', 'audit.local')[1].decode('ascii', errors='ignore')
            result['details'] = f'SMTP actif | Banner: {banner[:80]}'
            # Test open relay
            code, _ = smtp.docmd('MAIL FROM:', '<test@audit.local>')
            if code == 250:
                code2, _ = smtp.docmd('RCPT TO:', '<test@example.com>')
                if code2 == 250:
                    result['vulnerable'] = True
                    result['vulnerability_type'] = 'smtp_open_relay'
                    result['details'] = '🔴 CRITIQUE: SMTP Open Relay détecté'
            # Reset la transaction sans envoyer
            smtp.docmd('RSET')
            smtp.quit()
        except Exception as e:
            result['details'] = f'SMTP: {str(e)[:60]}'
        return result
    
    def test_vnc(self, ip: str, port: int) -> Dict:
        result = {'service': 'VNC', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'cves': []}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode('ascii', errors='ignore')
            if 'RFB' in banner:
                result['vulnerable'] = True
                result['vulnerability_type'] = 'vnc_exposed'
                result['details'] = f'🟠 MAUVAIS: VNC exposé ({banner.strip()[:30]})'
                # Vérifier si auth None (type 1) est proposé
                sock.sendall(banner[:12].encode('ascii', errors='ignore'))
                auth_data = sock.recv(1024)
                if auth_data and len(auth_data) > 1:
                    num_types = auth_data[0]
                    auth_types = list(auth_data[1:1+num_types])
                    if 1 in auth_types:  # Type 1 = None (no auth)
                        result['details'] = '🔴 CRITIQUE: VNC sans authentification'
                        result['vulnerability_type'] = 'vnc_no_auth'
            sock.close()
        except Exception:
            result['details'] = 'Service inaccessible'
        return result
    
    def test_snmp(self, ip: str, port: int = 161) -> Dict:
        """Test SNMP avec community strings par défaut (public, private, etc.)"""
        result = {'service': 'SNMP', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'cves': [], 'community_strings': []}
        community_strings = [
            ('public', 'ro'), ('private', 'rw'), ('community', 'ro'),
            ('manager', 'rw'), ('admin', 'rw'), ('snmp', 'ro'),
            ('default', 'ro'), ('monitor', 'ro'), ('cisco', 'rw'),
            ('secret', 'rw'),
        ]
        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )
            engine = SnmpEngine()
            found_communities = []
            for community, access_type in community_strings:
                try:
                    iterator = getCmd(
                        engine,
                        CommunityData(community, mpModel=1),  # SNMPv2c
                        UdpTransportTarget((ip, port), timeout=self.timeout, retries=0),
                        ContextData(),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
                    )
                    error_indication, error_status, error_index, var_binds = next(iterator)
                    if not error_indication and not error_status:
                        sys_descr = ''
                        for var_bind in var_binds:
                            sys_descr = str(var_bind[1])[:120]
                        found_communities.append({
                            'community': community,
                            'access': access_type,
                            'sys_descr': sys_descr
                        })
                except Exception:
                    continue
            if found_communities:
                result['vulnerable'] = True
                result['community_strings'] = [c['community'] for c in found_communities]
                # Vérifier si une community a un accès en écriture
                has_write = any(c['access'] == 'rw' for c in found_communities)
                if has_write:
                    rw_names = [c['community'] for c in found_communities if c['access'] == 'rw']
                    result['vulnerability_type'] = 'snmp_write_community'
                    result['details'] = (f'🔴 CRITIQUE: SNMP community RW par défaut: '
                                         f'{", ".join(rw_names)}')
                else:
                    result['vulnerability_type'] = 'snmp_default_community'
                    result['details'] = (f'🟠 MAUVAIS: SNMP community par défaut: '
                                         f'{", ".join(c["community"] for c in found_communities)}')
                # Ajouter sysDescr de la première community trouvée
                if found_communities[0]['sys_descr']:
                    result['details'] += f' | {found_communities[0]["sys_descr"][:80]}'
            else:
                result['details'] = 'Aucune community string par défaut acceptée'
        except ImportError:
            # Fallback sans pysnmp : test UDP brut SNMPv2c GET sysDescr
            result = self._test_snmp_raw(ip, port, community_strings)
        return result
    
    def _test_snmp_raw(self, ip: str, port: int, community_strings: list) -> Dict:
        """Test SNMP brut via socket UDP (fallback sans pysnmp)"""
        result = {'service': 'SNMP', 'vulnerable': False, 'vulnerability_type': None,
                  'details': '', 'cves': [], 'community_strings': []}
        found_communities = []
        for community, access_type in community_strings:
            try:
                # Construction manuelle d'un paquet SNMPv2c GET pour sysDescr (1.3.6.1.2.1.1.1.0)
                community_bytes = community.encode('ascii')
                # OID sysDescr encodé en BER
                oid_bytes = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
                # Varbind: SEQUENCE { OID, NULL }
                varbind = bytes([0x30, len(oid_bytes) + 2]) + oid_bytes + bytes([0x05, 0x00])
                # VarbindList: SEQUENCE { varbind }
                varbind_list = bytes([0x30, len(varbind)]) + varbind
                # PDU GetRequest: [0] request-id=1, error-status=0, error-index=0
                request_id = bytes([0x02, 0x01, 0x01])  # INTEGER 1
                error_status = bytes([0x02, 0x01, 0x00])  # INTEGER 0
                error_index = bytes([0x02, 0x01, 0x00])   # INTEGER 0
                pdu_content = request_id + error_status + error_index + varbind_list
                pdu = bytes([0xa0, len(pdu_content)]) + pdu_content
                # Message SNMPv2c: SEQUENCE { version=1, community, pdu }
                version = bytes([0x02, 0x01, 0x01])  # INTEGER 1 (SNMPv2c)
                comm = bytes([0x04, len(community_bytes)]) + community_bytes
                message_content = version + comm + pdu
                packet = bytes([0x30, len(message_content)]) + message_content
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(packet, (ip, port))
                response, _ = sock.recvfrom(4096)
                sock.close()
                # Si on reçoit une réponse valide (commence par 0x30), la community est acceptée
                if response and response[0] == 0x30:
                    found_communities.append({
                        'community': community,
                        'access': access_type
                    })
            except (socket.timeout, OSError):
                continue
        if found_communities:
            result['vulnerable'] = True
            result['community_strings'] = [c['community'] for c in found_communities]
            has_write = any(c['access'] == 'rw' for c in found_communities)
            if has_write:
                rw_names = [c['community'] for c in found_communities if c['access'] == 'rw']
                result['vulnerability_type'] = 'snmp_write_community'
                result['details'] = (f'🔴 CRITIQUE: SNMP community RW par défaut: '
                                     f'{", ".join(rw_names)}')
            else:
                result['vulnerability_type'] = 'snmp_default_community'
                result['details'] = (f'🟠 MAUVAIS: SNMP community par défaut: '
                                     f'{", ".join(c["community"] for c in found_communities)}')
        else:
            result['details'] = 'Aucune community string par défaut acceptée'
        return result


# ============================================================================
# CLASSE PRINCIPALE
# ============================================================================

class AuditFlashWindows:
    def __init__(self, targets: List[str], ports: List[int] = None,
                 timeout: int = 3, use_nmap: bool = True, domain: str = None,
                 discover_vlans: bool = False, vlan_interface: str = None,
                 vlan_timeout: int = 30, threads: int = 50,
                 cve_db: CVEDatabase = None,
                 nse_scripts: List[str] = None,
                 banner_grab: bool = True):
        self.targets = self._parse_targets(targets)
        self.timeout = timeout
        self.use_nmap = use_nmap and HAS_NMAP
        self.domain = domain
        self.cve_db = cve_db
        self.tester = ServiceTester(timeout, cve_db)
        self.results = []
        self.discover_vlans = discover_vlans
        self.vlan_interface = vlan_interface
        self.vlan_timeout = vlan_timeout
        self.vlan_results = []
        self.threads = threads
        self.nse_scripts = nse_scripts or []
        self.banner_grab = banner_grab
        self.nse_results = {}        # {ip: {port: [nse_results]}}
        self.banner_results = {}     # {ip: {port: {banner, product, version}}}
        
        # BannerGrabber uniquement utile en mode scan basique (socket)
        self.banner_grabber = BannerGrabber(timeout=timeout) if not (use_nmap and HAS_NMAP) else None
        
        # Initialiser le scanner NSE
        self.nse_scanner = NmapNSEScanner(cve_db=cve_db) if self.nse_scripts else None
        
        self.ports = ports or [
            21, 22, 23, 53, 80, 135, 139, 389, 443, 445,
            3306, 3389, 5432, 5900, 6379, 8080, 27017,
        ]
        
        if self.use_nmap:
            self.nm = nmap.PortScanner()
            print("[+] Mode Nmap activé")
            if self.nse_scripts:
                print(f"[+] Scripts NSE activés: {', '.join(self.nse_scripts)}")
        else:
            print("[+] Mode scan basique (socket)")
            if self.banner_grab:
                print("[+] Banner grabbing activé")
        
        self.service_testers = {
            'ftp': self.tester.test_ftp,
            'ssh': self.tester.test_ssh,
            'telnet': self.tester.test_telnet,
            'http': lambda ip, port: self.tester.test_http(ip, port, False),
            'https': lambda ip, port: self.tester.test_http(ip, port, True),
            'smb': self.tester.test_smb,
            'microsoft-ds': self.tester.test_smb,
            'netbios-ssn': self.tester.test_smb,
            'domain': lambda ip, port: self.tester.test_dns(ip, port, self.domain),
            'ldap': self.tester.test_ldap,
            'rdp': self.tester.test_rdp,
            'ms-wbt-server': self.tester.test_rdp,
            'mysql': self.tester.test_mysql,
            'redis': self.tester.test_redis,
            'mongodb': self.tester.test_mongodb,
            'postgresql': self.tester.test_postgresql,
            'mssql': self.tester.test_mssql,
            'ms-sql-s': self.tester.test_mssql,
            'smtp': self.tester.test_smtp,
            'vnc': self.tester.test_vnc,
            'snmp': self.tester.test_snmp,
        }
    
    def _parse_targets(self, targets: List[str]) -> List[str]:
        parsed = []
        for target in targets:
            try:
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    num_hosts = network.num_addresses
                    if num_hosts > 256:
                        print(f"[⚠️] Plage {target} contient {num_hosts} hôtes")
                        confirm = input(f"    Continuer ? (o/N) : ").strip().lower()
                        if confirm != 'o':
                            print(f"    Plage {target} ignorée")
                            continue
                    parsed.extend([str(ip) for ip in network.hosts()])
                else:
                    parsed.append(target)
            except ValueError:
                print(f"[!] Cible invalide: {target}")
        return parsed
    
    def scan_port_basic(self, ip: str, port: int) -> Tuple[str, int, bool, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except Exception:
                    service = 'unknown'
                return (ip, port, True, service)
        except Exception:
            pass
        return (ip, port, False, '')
    
    def scan_host_basic(self, ip: str) -> List[Dict]:
        print(f"\n[*] Scan basique de {ip}...")
        host_results = []
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port_basic, ip, port): port for port in self.ports}
            iterator = tqdm(as_completed(futures), total=len(self.ports), 
                           desc="  Scan ports", unit="port", leave=False) if HAS_TQDM else as_completed(futures)
            for future in iterator:
                ip_addr, port, is_open, service = future.result()
                if is_open:
                    open_ports.append((port, service))
                    print(f"  [+] Port {port} ouvert ({service})")
        
        # Banner grabbing sur les ports ouverts
        banner_data = {}
        # cpe_cache : évite de recalculer lookup_cpe_database deux fois par port
        cpe_cache: Dict[int, list] = {}
        if open_ports and self.banner_grab:
            print(f"  [*] Banner grabbing sur {len(open_ports)} port(s)...")
            banner_data = self.banner_grabber.grab_banners_for_ports(ip, open_ports)
            self.banner_results[ip] = banner_data
            for port, info in banner_data.items():
                if info.get('product'):
                    print(f"    [i] Port {port}: {info['product']} {info.get('version', '')}")
                    cpe_cves = lookup_cpe_database(info['product'], info.get('version', ''))
                    cpe_cache[port] = cpe_cves
                    if cpe_cves:
                        print(f"    [!] CVE connus (base CPE): {', '.join(cpe_cves[:3])}")
        
        if open_ports:
            print(f"  [*] Test de {len(open_ports)} service(s) + corrélation CVE...")
            port_iterator = (tqdm(open_ports, desc="  Tests services", unit="service", leave=False) 
                           if HAS_TQDM else open_ports)
            for port, service in port_iterator:
                # Enrichir avec les infos de bannière
                b_info = banner_data.get(port, {})
                product = b_info.get('product', '')
                version = b_info.get('version', '')
                test_result = self.test_discovered_service(ip, port, service, product, version)
                if test_result:
                    # Ajouter les infos de bannière au résultat
                    if b_info.get('banner'):
                        test_result['banner'] = b_info['banner']
                    if product and not test_result.get('product'):
                        test_result['product'] = product
                    if version and not test_result.get('version'):
                        test_result['version'] = version
                    # Réutiliser le lookup CPE déjà calculé lors du banner grabbing
                    cpe_cves = cpe_cache.get(port) or (lookup_cpe_database(product, version) if product else [])
                    if cpe_cves:
                        test_result.setdefault('cpe_cves', cpe_cves)
                    host_results.append({'ip': ip, 'hostname': '', 'port': port,
                                        'service': service, 'product': product,
                                        'version': version, 'test_result': test_result})
        return host_results
    
    def scan_with_nmap(self, target: str) -> Dict:
        print(f"\n[*] Scan Nmap de {target}...")
        try:
            # Optimiser la chaîne de ports pour éviter WinError 206
            # Si plage contiguë 1-N, utiliser la notation nmap "1-N"
            sorted_ports = sorted(self.ports)
            if sorted_ports[-1] - sorted_ports[0] + 1 == len(sorted_ports):
                ports_str = f"{sorted_ports[0]}-{sorted_ports[-1]}"
            else:
                ports_str = ','.join(map(str, sorted_ports))
            # Si --script-scan, fusionner la détection de version + scripts NSE en un seul scan
            if self.nse_scripts and self.nse_scanner:
                scripts_arg = self.nse_scanner.build_scripts_arg(self.nse_scripts)
                nmap_args = f'-sC -sV --script {scripts_arg}'
                print(f"  [i] Scan combiné: -sC -sV + scripts NSE ({scripts_arg})")
            else:
                nmap_args = '-sC -sV'
            self.nm.scan(hosts=target, ports=ports_str, arguments=nmap_args)
            if target not in self.nm.all_hosts():
                print(f"[!] Hôte {target} non accessible")
                return {}
            host_info = {'ip': target, 'hostname': self.nm[target].hostname(),
                        'state': self.nm[target].state(), 'ports': []}
            nse_port_results = {}
            for proto in self.nm[target].all_protocols():
                for port in sorted(self.nm[target][proto].keys()):
                    port_info = self.nm[target][proto][port]
                    if port_info['state'] == 'open':
                        product = port_info.get('product', '')
                        version = port_info.get('version', '')
                        service_info = {
                            'port': port,
                            'service': port_info.get('name', 'unknown'),
                            'product': product,
                            'version': version
                        }
                        # Recherche CVE via la base CPE locale
                        if product:
                            cpe_cves = lookup_cpe_database(product, version)
                            if cpe_cves:
                                service_info['cpe_cves'] = cpe_cves
                                print(f"  [+] Port {port} - {service_info['service']} "
                                      f"{product} {version} "
                                      f"[CPE: {', '.join(cpe_cves[:2])}]")
                            else:
                                print(f"  [+] Port {port} - {service_info['service']} "
                                      f"{product} {version}")
                        else:
                            print(f"  [+] Port {port} - {service_info['service']}")
                        
                        # Parser les résultats NSE si scan combiné
                        if self.nse_scripts and self.nse_scanner:
                            script_output = port_info.get('script', {})
                            if script_output:
                                parsed = self.nse_scanner.parse_nse_results(script_output)
                                parsed = self.nse_scanner.enrich_nse_cves(parsed)
                                interesting = [r for r in parsed
                                               if r['is_vulnerable'] or r['cve_ids']]
                                if interesting:
                                    nse_port_results[port] = interesting
                                    for r in interesting:
                                        vuln_tag = '🔴 VULN' if r['is_vulnerable'] else '🔵 INFO'
                                        cve_str = f" | CVE: {', '.join(r['cve_ids'][:3])}" if r['cve_ids'] else ""
                                        print(f"    [{vuln_tag}] Port {port} - "
                                              f"{r['script_name']}{cve_str}")
                        
                        host_info['ports'].append(service_info)
            
            # Stocker les résultats NSE du scan combiné
            if nse_port_results:
                self.nse_results[target] = nse_port_results
                total_vulns = sum(1 for results in nse_port_results.values()
                                  for r in results if r['is_vulnerable'])
                total_cves = sum(len(r['cve_ids']) for results in nse_port_results.values()
                                 for r in results)
                print(f"  [+] NSE combiné: {total_vulns} vulnérabilité(s), "
                      f"{total_cves} CVE-ID sur {len(nse_port_results)} port(s)")
            
            return host_info
        except Exception as e:
            print(f"[!] Erreur Nmap: {str(e)}")
            return {}
    
    def test_discovered_service(self, ip: str, port: int, service_name: str,
                                 product: str = "", version: str = "") -> Optional[Dict]:
        service_lower = service_name.lower()
        for pattern, tester in self.service_testers.items():
            if pattern in service_lower:
                try:
                    result = tester(ip, port)
                    # Enrichir avec les infos produit/version (bannière ou nmap)
                    if product and not result.get('product'):
                        result['product'] = product
                    if version and not result.get('version'):
                        result['version'] = version
                    # Utiliser le produit/version le plus spécifique disponible
                    final_product = result.get('product', '') or product
                    final_version = result.get('version', '') or version
                    # Enrichissement CVE centralisé avec le vrai produit/version
                    vuln_type = result.get('vulnerability_type', 'service_detected')
                    result = self.tester._enrich_with_cves(
                        result, vuln_type, service_name,
                        final_product, final_version, ip
                    )
                    if result.get('vulnerable'):
                        cve_info = ""
                        if result.get('cves'):
                            cve_info = f" [{result['cve_count']} CVE, max CVSS: {result.get('max_cvss', 0):.1f}]"
                        ft = result.get('finding_type', '')
                        rs = result.get('risk_score', 0)
                        ctx = '🌐' if result.get('ip_context') == 'public' else '🏠'
                        print(f"  [!] {result['details']}{cve_info} [{ft} risk:{rs} {ctx}]")
                    return result
                except Exception as e:
                    return None
        result = {'service': service_name, 'vulnerable': False,
                'vulnerability_type': 'service_detected',
                'finding_type': 'INFORMATIONAL', 'risk_score': 1.0,
                'details': f'Service {service_name} détecté', 'cves': []}
        if product:
            result['product'] = product
            result['details'] += f' ({product} {version})'.rstrip()
        if version:
            result['version'] = version
        return result
    
    def run_audit(self) -> List[Dict]:
        print(f"\n{'='*70}")
        print(f"AUDIT FLASH v5.0")
        print(f"{'='*70}")
        print(f"OS: {platform.system()} {platform.release()}")
        print(f"Cibles: {len(self.targets)} hôtes | Ports: {len(self.ports)} | Threads: {self.threads}")
        print(f"Mode scan: {'Nmap' if self.use_nmap else 'Basique'}")
        if self.nse_scripts:
            print(f"Scripts NSE: {', '.join(self.nse_scripts)}")
        if self.banner_grab and not self.use_nmap:
            print(f"Banner grabbing: activé")
        if self.cve_db:
            print(f"Base CVE: NVD/NIST {'(online)' if self.cve_db.use_api else '(offline)'}")
        print(f"Base CPE locale: {len(CPE_DATABASE)} produits référencés")
        print(f"{'='*70}")
        
        start_time = datetime.now()
        target_iterator = (tqdm(self.targets, desc="Scan cibles", unit="hôte") 
                          if HAS_TQDM and len(self.targets) > 1 else self.targets)
        
        for target in target_iterator:
            if self.use_nmap:
                host_info = self.scan_with_nmap(target)
                if host_info and host_info.get('ports'):
                    print(f"\n[*] Tests sécurité + CVE sur {target}...")
                    port_iterator = (tqdm(host_info['ports'], desc="  Tests+CVE", 
                                         unit="service", leave=False) 
                                   if HAS_TQDM else host_info['ports'])
                    for port_info in port_iterator:
                        test_result = self.test_discovered_service(
                            target, port_info['port'], port_info['service'],
                            port_info.get('product', ''), port_info.get('version', '')
                        )
                        if test_result:
                            # Ajouter les CVE CPE du scan Nmap
                            if port_info.get('cpe_cves'):
                                test_result.setdefault('cpe_cves', port_info['cpe_cves'])
                            self.results.append({
                                'ip': target,
                                'hostname': host_info['hostname'],
                                'port': port_info['port'],
                                'service': port_info['service'],
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'test_result': test_result
                            })
                    
                    # Intégrer les résultats NSE (déjà collectés par le scan combiné)
                    nse_results = self.nse_results.get(target, {})
                    if nse_results:
                            for result in self.results:
                                if result['ip'] == target and result['port'] in nse_results:
                                    port_nse = nse_results[result['port']]
                                    result['test_result']['nse_results'] = port_nse
                                    # Ajouter les CVE NSE au résultat
                                    for nse_r in port_nse:
                                        if nse_r.get('is_vulnerable'):
                                            result['test_result']['vulnerable'] = True
                                            if not result['test_result'].get('vulnerability_type'):
                                                result['test_result']['vulnerability_type'] = 'nse_vuln_detected'
                                        for cve_detail in nse_r.get('cve_details', []):
                                            existing_ids = {c.get('cve_id') for c in result['test_result'].get('cves', [])}
                                            if cve_detail.get('cve_id') not in existing_ids:
                                                result['test_result'].setdefault('cves', []).append(cve_detail)
            else:
                host_results = self.scan_host_basic(target)
                self.results.extend(host_results)
        
        duration = (datetime.now() - start_time).total_seconds()
        
        if self.cve_db:
            stats = self.cve_db.get_stats()
            print(f"\n[i] CVE: {stats['api_calls']} requêtes API, {stats['cache_entries']} en cache")
        
        # Résumé NSE
        if self.nse_results:
            total_nse_vulns = sum(
                1 for ip_results in self.nse_results.values()
                for port_results in ip_results.values()
                for r in port_results if r.get('is_vulnerable')
            )
            total_nse_cves = sum(
                len(r.get('cve_ids', [])) for ip_results in self.nse_results.values()
                for port_results in ip_results.values()
                for r in port_results
            )
            print(f"[i] NSE: {total_nse_vulns} vulnérabilité(s) confirmée(s), "
                  f"{total_nse_cves} CVE-ID détectés")
        
        if self.discover_vlans:
            vlan_discovery = VLANDiscovery(interface=self.vlan_interface, timeout=self.vlan_timeout)
            self.vlan_results = vlan_discovery.discover_vlans()
            if self.vlan_results:
                self._display_vlan_summary()

        print(f"\n{'='*70}")
        print(f"AUDIT TERMINÉ en {duration:.2f}s")
        print(f"{'='*70}\n")
        
        return self.results
    
    def _display_vlan_summary(self):
        print(f"\n{'='*70}\nRÉSUMÉ VLAN\n{'='*70}\n")
        for vlan in self.vlan_results:
            print(f"  VLAN {vlan.vlan_id} - {vlan.vlan_name or 'Sans nom'} | "
                  f"Switch: {vlan.switch_name} ({vlan.switch_ip}) | Port: {vlan.switch_port}")
    

    def generate_report(self, output_file: str = 'audit_report_cve.json'):
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # --- Déduplication vulnérabilités ---
        seen_vulns: set = set()
        deduplicated: list = []
        for r in self.results:
            t = r.get('test_result', {})
            if t.get('vulnerable'):
                key = (r.get('ip', ''), t.get('vulnerability_type', ''))
                if key in seen_vulns:
                    continue
                seen_vulns.add(key)
            deduplicated.append(r)
        self.results = deduplicated

        vulnerabilities = [r for r in self.results if r.get('test_result', {}).get('vulnerable')]

        # --- Centralized CVE filtering function ---
        # IMPORTANT: appelé uniquement APRÈS l'enrichissement NVD
        # Ne filtre que les entrées sans CVE-ID valide, pas celles avec score 0.0
        # (un CVE récent peut avoir score 0.0 côté NVD mais rester informatif)
        def _filter_cves(cves):
            filtered = []
            for cve in cves:
                if not isinstance(cve, dict):
                    continue
                cve_id = cve.get('cve_id', '')
                if not cve_id:
                    continue
                # Garder tous les CVE avec un ID valide — même score 0.0
                # (CVE récent, réservé, ou réseau indisponible pendant le scan)
                filtered.append(cve)
            return filtered

        # --- Collect and enrich CVEs (limit 5 per service, parallelize enrichment) ---
        all_cves_map = {}
        cve_ids_to_enrich = set()
        service_cve_map = {}
        for vuln in vulnerabilities:
            cves = vuln['test_result'].get('cves', [])
            # Filter and sort by severity/score
            filtered = _filter_cves(cves)
            sorted_cves = sorted(filtered, key=lambda c: c.get('cvss_v3_score', 0) or c.get('cvss_v2_score', 0), reverse=True)
            top_cves = sorted_cves[:5]
            service_cve_map[vuln.get('test_result', {}).get('service', f"{vuln.get('ip','')}:{vuln.get('port','')}")] = [c.get('cve_id','') for c in top_cves]
            for cve in top_cves:
                cve_id = cve.get('cve_id', '')
                if cve_id and cve_id not in all_cves_map:
                    all_cves_map[cve_id] = cve
                    cve_ids_to_enrich.add(cve_id)
            # Update vuln's cves to only top 5 filtered
            vuln['test_result']['cves'] = top_cves

        # --- Collect CPE CVEs ---
        all_cpe_cves = set()
        for result in self.results:
            for cve_id in result.get('test_result', {}).get('cpe_cves', []):
                all_cpe_cves.add(cve_id)
                # Toujours ajouter à la liste d'enrichissement NVD, même si déjà dans all_cves_map
                cve_ids_to_enrich.add(cve_id)
                # Si pas dans le mapping, ajouter un placeholder minimal (sera enrichi juste après)
                if cve_id not in all_cves_map:
                    all_cves_map[cve_id] = {
                        'cve_id': cve_id,
                        'description': f"CVE issu de la base CPE locale pour {result.get('product', result.get('service', 'service détecté'))}",
                        'cvss_v3_score': 0.0,
                        'cvss_v3_vector': "",
                        'cvss_v2_score': 0.0,
                        'severity': "UNKNOWN",
                        'published': "",
                        'modified': "",
                        'references': [],
                        'affected_products': [],
                        'cwe_ids': [],
                        'nvd_url': CVEDatabase._build_nvd_url(cve_id),
                        'confidence': "CONFIRMED"
                    }

        # --- Parallel enrichment for missing CVEs ---
        if self.cve_db and self.cve_db.use_api:
            def enrich_cve(cve_id):
                detail = self.cve_db._fetch_cve_detail(cve_id)
                if detail:
                    return cve_id, self.cve_db._cve_to_dict(detail, confidence='CONFIRMED')
                return cve_id, all_cves_map[cve_id]

            # Forcer enrichissement pour toutes les CVE collectées, même sans mapping CPE
            all_cve_ids = set(all_cves_map.keys()) | set(cve_ids_to_enrich)
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = {executor.submit(enrich_cve, cve_id): cve_id for cve_id in all_cve_ids}
                for future in as_completed(futures):
                    cve_id, cve_dict = future.result()
                    all_cves_map[cve_id] = cve_dict

        # --- Synchronize enriched CVEs back into vulnerabilities ---
        for vuln in vulnerabilities:
            cves = vuln['test_result'].get('cves', [])
            enriched = []
            for cve in cves:
                cve_id = cve.get('cve_id', '')
                if cve_id and cve_id in all_cves_map:
                    enriched.append(all_cves_map[cve_id])
                else:
                    enriched.append(cve)
            vuln['test_result']['cves'] = enriched

        # --- NSE results (unchanged, but filter CVEs) ---
        nse_summary = {}
        nse_cve_ids = set()
        nse_cve_list = []
        nse_vulnerable_ports = set()
        if self.nse_results:
            for ip, ports_data in self.nse_results.items():
                for port, nse_list in ports_data.items():
                    for nse_r in nse_list:
                        script_name = nse_r.get('script_name', '')
                        if script_name not in nse_summary:
                            nse_summary[script_name] = {
                                'total_runs': 0,
                                'vulnerable': 0,
                                'cve_ids': [],
                            }
                        nse_summary[script_name]['total_runs'] += 1
                        if nse_r.get('is_vulnerable'):
                            nse_summary[script_name]['vulnerable'] += 1
                            nse_vulnerable_ports.add(f"{ip}:{port}")
                        for cve_id in nse_r.get('cve_ids', []):
                            nse_cve_ids.add(cve_id)
                            if cve_id not in nse_summary[script_name]['cve_ids']:
                                nse_summary[script_name]['cve_ids'].append(cve_id)
                            if cve_id not in all_cves_map:
                                all_cves_map[cve_id] = {
                                    'cve_id': cve_id,
                                    'description': f'Détecté par script NSE: {script_name}',
                                    'cvss_v3_score': 0.0,
                                    'cvss_v3_vector': "",
                                    'cvss_v2_score': 0.0,
                                    'severity': nse_r.get('severity', 'UNKNOWN'),
                                    'published': "",
                                    'modified': "",
                                    'references': [],
                                    'affected_products': [],
                                    'cwe_ids': [],
                                    'nvd_url': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                                    'confidence': "CONFIRMED"
                                }
                            nse_cve_list.append(all_cves_map[cve_id])

        # --- Cyberscore calculation ---
        cyberscore = CyberScore.calculate_score(
            vulnerabilities,
            extra_cves=nse_cve_list,
            extra_ports=len(nse_vulnerable_ports)
        )

        # --- Banner summary (unchanged) ---
        banner_summary = {}
        for ip, ports_data in self.banner_results.items():
            for port, b_info in ports_data.items():
                if b_info.get('product'):
                    banner_summary[f"{ip}:{port}"] = {
                        'product': b_info['product'],
                        'version': b_info.get('version', ''),
                        'banner': b_info.get('banner', '')[:200],
                    }

        # --- Build report ---
        report = {
            'timestamp': datetime.now().isoformat(),
            'version': '5.0',
            'system_info': {
                'os': platform.system(),
                'os_version': platform.release(),
                'python_version': sys.version.split()[0]
            },
            'scan_config': {
                'nse_scripts': self.nse_scripts,
                'banner_grab': self.banner_grab,
                'nmap_mode': self.use_nmap,
                'cpe_database_size': len(CPE_DATABASE),
            },
            'cyberscore': {
                'grade':                 cyberscore['grade'],
                'label':                 cyberscore['label'],
                'final_score':           cyberscore['final_score'],
                'score_breakdown': {
                    'base_score_gravity':    cyberscore['base_score'],
                    'volume_score_cve_count':cyberscore['volume_score'],
                    'exposure_score_services':cyberscore['exposure_score'],
                    'cvss_max_bonus':        cyberscore.get('cvss_max_score', 0),
                    'max_possible':          100,
                    'note': (
                        'gravité_pondérée(0-50) + volume_CVE(0-25) + '
                        'nb_services(0-15) + cvss_max(0-10)'
                    )
                },
                'worst_cvss':            cyberscore['worst_cvss'],
                'worst_severity':        cyberscore['worst_severity'],
                'total_cves':            cyberscore['total_cves'],
                'cve_by_severity':       cyberscore['cve_by_severity'],
                'total_vulnerabilities': cyberscore['total_vulnerabilities'],
                'top_cves':              cyberscore['top_cves'],
            },
            'cve_summary': {
                'total_unique_cves': len(all_cves_map),
                'critical_cves': cyberscore['cve_by_severity']['CRITICAL'],
                'high_cves':     cyberscore['cve_by_severity']['HIGH'],
                'medium_cves':   cyberscore['cve_by_severity']['MEDIUM'],
                'low_cves':      cyberscore['cve_by_severity']['LOW'],
                'all_cves':      sorted(
                    all_cves_map.values(),
                    key=lambda c: c.get('cvss_v3_score', 0) or c.get('cvss_v2_score', 0),
                    reverse=True
                ),
                'top_cves':      sorted(
                    all_cves_map.values(),
                    key=lambda c: c.get('cvss_v3_score', 0) or c.get('cvss_v2_score', 0),
                    reverse=True
                )[:10],
                'cpe_local_cves': list(all_cpe_cves),
                # Correction ici : injecter les CVE enrichis pour NSE, pas juste les IDs
                'nse_cves':      nse_cve_list,
            },
            'cve_to_hosts': self._build_cve_to_hosts(),
            'nse_scan': {
                'enabled': bool(self.nse_scripts),
                'scripts_used': self.nse_scripts,
                'results_by_script': nse_summary,
                'total_cves_found': len(nse_cve_ids),
                'raw_results': {
                    ip: {
                        str(port): results
                        for port, results in ports_data.items()
                    }
                    for ip, ports_data in self.nse_results.items()
                },
            },
            'banner_grabbing': {
                'enabled': self.banner_grab,
                'products_detected': banner_summary,
                'total_products': len(banner_summary),
            },
            'summary': {
                'total_hosts': len(set(r['ip'] for r in self.results)),
                'total_services': len(self.results),
                'vulnerabilities_found': len(vulnerabilities),
                'vulnerabilities_by_type': cyberscore['vulnerability_counts']
            },
            'vulnerabilities': vulnerabilities,
            'all_results': self.results,
            'vlan_discovery': {
                'enabled': self.discover_vlans,
                'vlans_found': len(self.vlan_results),
                'vlans': [{
                    'vlan_id': v.vlan_id, 'vlan_name': v.vlan_name,
                    'protocol': v.protocol, 'native_vlan': v.native_vlan,
                    'switch': {'name': v.switch_name, 'ip': v.switch_ip,
                               'port': v.switch_port, 'model': v.switch_model},
                    'discovered_at': v.discovered_at
                } for v in self.vlan_results]
            }
        }

        # --- Apply filtering everywhere ---
        if 'all_cves' in report['cve_summary']:
            report['cve_summary']['all_cves'] = _filter_cves(report['cve_summary']['all_cves'])
        if 'top_cves' in report['cve_summary']:
            report['cve_summary']['top_cves'] = _filter_cves(report['cve_summary']['top_cves'])
        if 'nse_cves' in report['cve_summary']:
            report['cve_summary']['nse_cves'] = _filter_cves(report['cve_summary']['nse_cves'])
        if 'vulnerabilities' in report:
            for v in report['vulnerabilities']:
                if 'cves' in v.get('test_result', {}):
                    v['test_result']['cves'] = _filter_cves(v['test_result']['cves'])

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        self._display_cyberscore(cyberscore, vulnerabilities)
        self._display_cve_summary(all_cves_map, self._build_cve_to_hosts())
        self._display_nse_summary(nse_summary, nse_cve_ids)
        self._display_banner_summary(banner_summary)
        print(f"\n[+] Rapport généré: {output_file}")
        return report

    def _build_cve_to_hosts(self) -> Dict:
        """
        Construit un dict { cve_id: [{ip, port, product, version}] }
        permettant de savoir quels hôtes sont affectés par chaque CVE.
        """
        mapping: Dict[str, list] = {}
        for result in self.results:
            ip      = result.get('ip', '')
            port    = result.get('port', '')
            product = result.get('product', '')
            version = result.get('version', '')
            for cve in result.get('test_result', {}).get('cves', []):
                cve_id = cve.get('cve_id', '')
                if not cve_id:
                    continue
                if cve_id not in mapping:
                    mapping[cve_id] = []
                entry = {'ip': ip, 'port': port, 'product': product, 'version': version}
                if entry not in mapping[cve_id]:
                    mapping[cve_id].append(entry)
        return mapping

    def _display_cyberscore(self, score: Dict, vulnerabilities: List):
        print(f"\n{'='*70}")
        print(f"{'★  CYBERSCORE  ★':^70}")
        print(f"{'Notation 100% basée sur les CVE/CVSS réels (NVD/NIST)':^70}")
        print(f"{'='*70}\n")

        grade   = score['grade']
        emoji   = score['emoji']
        label   = score['label']
        final   = score['final_score']

        # Affichage de la note
        bar_filled = int(final / 5)           # 20 blocs pour 100 pts
        bar = '█' * bar_filled + '░' * (20 - bar_filled)
        print(f"  {emoji}  NOTE : {grade}  —  {label}  {emoji}")
        print(f"  Score : [{bar}] {final}/100")
        print()

        # Décomposition des 4 composantes
        print(f"  {'DÉCOMPOSITION DU SCORE':^64}")
        print(f"  {'─'*64}")
        g = score['base_score']
        v = score['volume_score']
        e = score['exposure_score']
        m = score.get('cvss_max_score', 0)
        print(f"  Gravité pondérée (somme CVSS décroissante)           : {g:>3}/50 pts")
        print(f"  Volume   ({score['total_cves']} CVE distincts détectés)              : {v:>3}/25 pts")
        print(f"  Exposition ({score['total_vulnerabilities']} service(s) vulnérable(s))             : {e:>3}/15 pts")
        print(f"  CVSS max  (pire CVE = CVSS {score['worst_cvss']:.1f} {score['worst_severity']:8})  : {m:>3}/10 pts")
        print(f"  {'─'*64}")
        print(f"  {'TOTAL':>55} : {final:>3}/100")
        print()

        # Répartition par sévérité
        sev_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        print(f"  Répartition des CVE par sévérité :")
        for sev, count in score['cve_by_severity'].items():
            bar_s = '■' * count + '□' * max(0, 10 - count)
            status = f" {sev_emoji[sev]} {count:>3} CVE  [{bar_s}]  {sev}"
            print(f"  {status}")
        print()

        # Grille de notation
        print(f"  {'GRILLE DE NOTATION':^64}")
        print(f"  {'─'*64}")
        grille = [
            ('A', '0-19',  '🟢', 'Aucun CVE critique, risque minimal'),
            ('B', '20-39', '🔵', 'CVE de faible/moyenne gravité'),
            ('C', '40-59', '🟡', 'CVE modérés ou accumulation'),
            ('D', '60-79', '🟠', 'CVE élevés ou multiples CVE modérés'),
            ('E', '80-100','🔴', 'CVE critiques ou accumulation sévère'),
        ]
        for g_note, g_range, g_emoji, g_desc in grille:
            marker = ' ◄ VOUS ÊTES ICI' if g_note == grade else ''
            print(f"  {g_emoji} {g_note} ({g_range:>6}) : {g_desc}{marker}")
        print()

        # Top vulnérabilités avec CVE (triées par criticité)
        if vulnerabilities:
            print(f"  TOP VULNÉRABILITÉS DÉTECTÉES (par criticité) :")
            print(f"  {'─'*64}")
            def get_cve_score(c):
                v3 = c.get('cvss_v3_score', 0)
                v2 = c.get('cvss_v2_score', 0)
                return v3 if v3 and v3 > 0 else v2
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda v: max(
                    (get_cve_score(c)
                     for c in v.get('test_result', {}).get('cves', [])),
                    default=0
                ),
                reverse=True
            )
            for vuln in sorted_vulns[:10]:
                t = vuln['test_result']
                cve_str = ""
                if t.get('cves'):
                    top = t['cves'][0]
                    v3 = top.get('cvss_v3_score', 0)
                    v2 = top.get('cvss_v2_score', 0)
                    cscore = v3 if v3 and v3 > 0 else v2
                    sev = (top.get('severity') or '').upper()
                    se = sev_emoji.get(sev, '⚪')
                    cve_str = f"  {se} {top['cve_id']} (CVSS {cscore:.1f})"
                print(f"  • [{t['service']:12}] {t['details'][:45]}")
                if cve_str:
                    print(f"    └─{cve_str}")

        print(f"\n{'='*70}\n")
    
    def _display_cve_summary(self, all_cves_map: Dict, cve_to_hosts: Dict = None):
        if not all_cves_map:
            return
        
        print(f"{'='*70}")
        print(f"TOP CVE DÉTECTÉS ({len(all_cves_map)} uniques) — triés par criticité")
        print(f"{'='*70}\n")
        
        # Trier par score CVSS décroissant
        def get_cve_score(c):
            v3 = c.get('cvss_v3_score', 0)
            v2 = c.get('cvss_v2_score', 0)
            return v3 if v3 and v3 > 0 else v2
        sorted_cves = sorted(all_cves_map.values(), 
                            key=lambda x: get_cve_score(x),
                            reverse=True)
        
        severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 
                         'LOW': '🟢', 'UNKNOWN': '⚪'}
        confidence_label = {'CONFIRMED': '✅ CONFIRMÉ', 'PROBABLE': '🟡 PROBABLE', 'GENERIC': '⚪ GÉNÉRIQUE'}
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        
        # Regrouper par sévérité
        by_severity = {}
        for cve in sorted_cves:
            sev = (cve.get('severity', 'UNKNOWN') or 'UNKNOWN').upper()
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(cve)
        
        # Afficher par groupe de sévérité (CRITICAL d'abord)
        displayed = 0
        for sev in severity_order:
            if sev not in by_severity:
                continue
            emoji = severity_emoji.get(sev, '⚪')
            group = by_severity[sev]
            print(f"  {emoji} ── {sev} ({len(group)} CVE) ──")
            for cve in group:
                if displayed >= 20:
                    break
                score      = cve.get('cvss_v3_score', 0) or cve.get('cvss_v2_score', 0)
                desc       = cve.get('description', '')[:75]
                cwe        = ', '.join(cve.get('cwe_ids', [])[:2])
                conf       = cve.get('confidence', 'GENERIC')
                remote     = cve.get('remotely_exploitable')
                no_auth    = cve.get('no_auth_required')
                cve_id     = cve['cve_id']

                # Tags exploitabilité
                tags = []
                if remote is True:  tags.append('🌐 Exploitable à distance')
                if no_auth is True: tags.append('🔓 Sans auth')
                tags_str = '  |  '.join(tags)

                # Hôtes affectés
                hosts = (cve_to_hosts or {}).get(cve_id, [])
                hosts_str = ''
                if hosts:
                    host_parts = [f"{h['ip']}:{h['port']}" for h in hosts[:5]]
                    hosts_str = ', '.join(host_parts)
                    if len(hosts) > 5:
                        hosts_str += f' (+{len(hosts)-5})'

                print(f"     {cve_id:20} CVSS: {score:.1f}  {confidence_label.get(conf, conf)}")
                if tags_str:
                    print(f"     {tags_str}")
                print(f"     {desc}...")
                if cwe:
                    print(f"     CWE: {cwe}")
                if hosts_str:
                    print(f"     📍 Hôtes: {hosts_str}")
                url = cve.get('nvd_url', '')
                if url:
                    print(f"     🔗 {url}")
                print()
                displayed += 1
            if displayed >= 20:
                remaining = len(sorted_cves) - displayed
                if remaining > 0:
                    print(f"  ... et {remaining} autre(s) CVE")
                break
        
        print(f"{'='*70}\n")

    def _display_nse_summary(self, nse_summary: Dict, nse_cve_ids: set):
        """Affiche un résumé des résultats NSE"""
        if not nse_summary:
            return
        
        print(f"{'='*70}")
        print(f"RÉSUMÉ SCAN NSE (Scripts Nmap)")
        print(f"{'='*70}\n")
        
        for script_name, data in sorted(nse_summary.items()):
            vuln_count = data['vulnerable']
            total = data['total_runs']
            cve_list = data['cve_ids']
            
            if vuln_count > 0:
                status = f"🔴 {vuln_count}/{total} VULNÉRABLE(S)"
            else:
                status = f"✅ {total} test(s) - OK"
            
            print(f"  📋 {script_name}")
            print(f"     {status}")
            if cve_list:
                print(f"     CVE: {', '.join(cve_list[:5])}")
            print()
        
        if nse_cve_ids:
            print(f"  Total CVE détectés par NSE: {len(nse_cve_ids)}")
            print(f"  CVE-IDs: {', '.join(sorted(nse_cve_ids)[:10])}")
            if len(nse_cve_ids) > 10:
                print(f"  ... et {len(nse_cve_ids) - 10} autre(s)")
        
        print(f"\n{'='*70}\n")

    def _display_banner_summary(self, banner_summary: Dict):
        """Affiche un résumé du banner grabbing"""
        if not banner_summary:
            return
        
        print(f"{'='*70}")
        print(f"PRODUITS DÉTECTÉS (Banner Grabbing + CPE)")
        print(f"{'='*70}\n")
        
        for endpoint, info in sorted(banner_summary.items()):
            product = info.get('product', 'Inconnu')
            version = info.get('version', '')
            
            # Recherche CVE CPE locale
            cpe_cves = lookup_cpe_database(product, version) if product else []
            
            cve_str = ""
            if cpe_cves:
                cve_str = f" | ⚠️  CVE connus: {', '.join(cpe_cves[:3])}"
            
            print(f"  🔍 {endpoint:25} {product} {version}{cve_str}")
        
        print(f"\n  Total: {len(banner_summary)} produit(s) identifié(s)")
        print(f"{'='*70}\n")


# ============================================================================
# EXPORT PDF DU RAPPORT
# ============================================================================

class PDFReportGenerator:
    """
    Génère un rapport PDF professionnel à partir des données d'audit.
    Requiert reportlab (pip install reportlab).
    """

    GRADE_COLORS = {
        'A': '#00e5a0', 'B': '#38bdf8', 'C': '#facc15',
        'D': '#fb923c', 'E': '#f43f5e',
    }
    SEV_COLORS = {
        'CRITICAL': '#f43f5e', 'HIGH': '#fb923c', 'MEDIUM': '#facc15',
        'LOW': '#34d399', 'UNKNOWN': '#94a3b8', 'NONE': '#94a3b8',
    }
    GRADE_LABELS = {
        'A': 'EXCELLENT', 'B': 'BON', 'C': 'MOYEN',
        'D': 'MAUVAIS', 'E': 'CRITIQUE',
    }

    def __init__(self, report_data: Dict, output_path: str):
        self.data = report_data
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        self.styles.add(ParagraphStyle(
            'AFTitle', parent=self.styles['Title'],
            fontSize=24, textColor=HexColor('#1e293b'),
            spaceAfter=6, fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            'AFHeading', parent=self.styles['Heading2'],
            fontSize=14, textColor=HexColor('#1e293b'),
            spaceBefore=18, spaceAfter=8, fontName='Helvetica-Bold',
            borderWidth=0, borderPadding=0,
        ))
        self.styles.add(ParagraphStyle(
            'AFBody', parent=self.styles['Normal'],
            fontSize=9, textColor=HexColor('#334155'),
            fontName='Helvetica', leading=13,
        ))
        self.styles.add(ParagraphStyle(
            'AFSmall', parent=self.styles['Normal'],
            fontSize=7.5, textColor=HexColor('#64748b'),
            fontName='Helvetica', leading=10,
        ))
        self.styles.add(ParagraphStyle(
            'AFCenter', parent=self.styles['Normal'],
            fontSize=9, textColor=HexColor('#334155'),
            fontName='Helvetica', alignment=TA_CENTER,
        ))

    def _hex(self, color_str):
        return HexColor(color_str)

    # ── Header / Footer ───────────────────────────────────────────────────
    def _header_footer(self, canvas, doc):
        canvas.saveState()
        w, h = A4
        # Header bar
        canvas.setFillColor(HexColor('#0f172a'))
        canvas.rect(0, h - 28*mm, w, 28*mm, fill=True, stroke=False)
        canvas.setFillColor(white)
        canvas.setFont('Helvetica-Bold', 14)
        canvas.drawString(20*mm, h - 18*mm, 'AUDIT FLASH 5.0')
        canvas.setFont('Helvetica', 8)
        canvas.drawRightString(w - 20*mm, h - 14*mm, 'Rapport Cyberscore')
        ts = self.data.get('timestamp', '')
        if ts:
            try:
                dt = datetime.fromisoformat(ts)
                canvas.drawRightString(w - 20*mm, h - 20*mm,
                                       dt.strftime('%d/%m/%Y %H:%M'))
            except Exception:
                pass
        # Footer
        canvas.setFillColor(HexColor('#94a3b8'))
        canvas.setFont('Helvetica', 7)
        canvas.drawString(20*mm, 10*mm,
                          'Audit Flash 5.0 — CVE/CVSS NVD/NIST — Confidentiel')
        canvas.drawRightString(w - 20*mm, 10*mm, f'Page {doc.page}')
        canvas.restoreState()

    # ── Score gauge drawing ────────────────────────────────────────────────
    def _make_grade_drawing(self, grade, score):
        col = self.GRADE_COLORS.get(grade, '#f43f5e')
        d = Drawing(160, 160)
        # Background circle
        d.add(Circle(80, 80, 70, fillColor=HexColor('#f1f5f9'),
                     strokeColor=HexColor('#e2e8f0'), strokeWidth=2))
        # Inner circle with grade color
        d.add(Circle(80, 80, 58, fillColor=HexColor(col),
                     strokeColor=None, strokeWidth=0))
        # Grade letter
        d.add(String(80, 62, grade, fontSize=48,
                     fillColor=white, textAnchor='middle',
                     fontName='Helvetica-Bold'))
        # Score below
        d.add(String(80, 18, f'{score}/100', fontSize=11,
                     fillColor=HexColor('#334155'), textAnchor='middle',
                     fontName='Helvetica-Bold'))
        return d

    # ── Build ──────────────────────────────────────────────────────────────
    def generate(self):
        doc = SimpleDocTemplate(
            self.output_path, pagesize=A4,
            topMargin=35*mm, bottomMargin=20*mm,
            leftMargin=20*mm, rightMargin=20*mm,
        )
        elements = []
        cs = self.data.get('cyberscore', {})
        summary = self.data.get('summary', {})
        cve_summary = self.data.get('cve_summary', {})
        grade = cs.get('grade', 'E')
        score = cs.get('final_score', 0)
        label = cs.get('label', self.GRADE_LABELS.get(grade, ''))
        grade_col = self.GRADE_COLORS.get(grade, '#f43f5e')

        # ── TITRE ──────────────────────────────────────────────────────
        elements.append(Paragraph('Rapport Cyberscore', self.styles['AFTitle']))
        sysinfo = self.data.get('system_info', {})
        elements.append(Paragraph(
            f"OS : {sysinfo.get('os', '?')} {sysinfo.get('os_version', '')} "
            f"| Python {sysinfo.get('python_version', '?')} | v{self.data.get('version', '4.0')}",
            self.styles['AFSmall']
        ))
        elements.append(Spacer(1, 6*mm))

        # ── NOTE GLOBALE ───────────────────────────────────────────────
        gauge = self._make_grade_drawing(grade, score)
        note_table = Table(
            [[gauge, [
                Paragraph(f'<font color="{grade_col}" size="20"><b>{grade} — {label}</b></font>',
                          self.styles['AFBody']),
                Spacer(1, 3*mm),
                Paragraph(f'Score final : <b>{score}/100</b>', self.styles['AFBody']),
                Paragraph(f'CVSS max : <b>{cs.get("worst_cvss", 0):.1f}</b> ({cs.get("worst_severity", "?")})',
                          self.styles['AFBody']),
            ]]],
            colWidths=[170, 340],
        )
        note_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (1, 0), (1, 0), 20),
        ]))
        elements.append(note_table)
        elements.append(Spacer(1, 4*mm))

        # ── DÉCOMPOSITION DU SCORE ─────────────────────────────────────
        elements.append(Paragraph('Décomposition du score', self.styles['AFHeading']))
        bk = cs.get('score_breakdown', {})
        bk_data = [
            ['Composante', 'Détail', 'Points'],
            ['Gravité (pire CVE)',
             f'CVSS {cs.get("worst_cvss", 0):.1f} ({cs.get("worst_severity", "?")})',
             f'{bk.get("base_score_gravity", "?")}/60'],
            ['Volume CVE',
             f'{cs.get("total_cves", 0)} CVE uniques détectés',
             f'{bk.get("volume_score_cve_count", "?")}/25'],
            ['Exposition',
             f'{cs.get("total_vulnerabilities", 0)} services vulnérables',
             f'{bk.get("exposure_score_services", "?")}/15'],
            ['', '', f'TOTAL : {score}/100'],
        ]
        bk_table = Table(bk_data, colWidths=[140, 250, 100])
        bk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -2), [HexColor('#f8fafc'), white]),
            ('FONTNAME', (-1, -1), (-1, -1), 'Helvetica-Bold'),
            ('ALIGN', (-1, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(bk_table)
        elements.append(Spacer(1, 4*mm))

        # ── STATISTIQUES ───────────────────────────────────────────────
        elements.append(Paragraph('Statistiques du scan', self.styles['AFHeading']))
        stats_data = [
            ['Hôtes scannés', 'Services testés', 'Vulnérabilités', 'CVE uniques'],
            [str(summary.get('total_hosts', '?')),
             str(summary.get('total_services', '?')),
             str(summary.get('vulnerabilities_found', '?')),
             str(cs.get('total_cves', '?'))],
        ]
        stats_table = Table(stats_data, colWidths=[122.5]*4)
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('FONTSIZE', (0, 1), (-1, 1), 16),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 4*mm))

        # ── RÉPARTITION CVE PAR SÉVÉRITÉ ───────────────────────────────
        elements.append(Paragraph('Répartition des CVE par sévérité', self.styles['AFHeading']))
        cve_by_sev = cs.get('cve_by_severity', {})
        sev_data = [['Sévérité', 'Nombre']]
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = cve_by_sev.get(sev, 0)
            sev_data.append([sev, str(count)])

        sev_table = Table(sev_data, colWidths=[245, 245])
        sev_styles = [
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]
        for i, sev in enumerate(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], start=1):
            col = self.SEV_COLORS.get(sev, '#94a3b8')
            sev_styles.append(('TEXTCOLOR', (0, i), (0, i), HexColor(col)))
            sev_styles.append(('FONTNAME', (0, i), (0, i), 'Helvetica-Bold'))
        sev_table.setStyle(TableStyle(sev_styles))
        elements.append(sev_table)
        elements.append(Spacer(1, 4*mm))

        # ── VULNÉRABILITÉS DÉTECTÉES ───────────────────────────────────
        vulns = [v for v in self.data.get('vulnerabilities', [])
                 if v.get('test_result', {}).get('vulnerable')]
        if vulns:
            elements.append(Paragraph('Vulnérabilités détectées', self.styles['AFHeading']))
            vuln_header = ['IP:Port', 'Service', 'Sévérité', 'Détails', 'CVE principal']
            vuln_rows = [vuln_header]
            for vuln in vulns:
                t = vuln.get('test_result', {})
                cves = t.get('cves', [])
                top_cve = cves[0] if cves else None
                top_score = 0
                top_sev = 'UNKNOWN'
                cve_text = '—'
                if top_cve:
                    top_score = top_cve.get('cvss_v3_score') or top_cve.get('cvss_v2_score') or 0
                    top_sev = (top_cve.get('severity') or '').upper() or 'UNKNOWN'
                    nvd_url = top_cve.get('nvd_url', '')
                    cve_id = top_cve.get('cve_id', '')
                    if nvd_url:
                        cve_text = f'<a href="{nvd_url}" color="#3b82f6">{cve_id}</a><br/><font size="7">CVSS {top_score:.1f}</font>'
                    else:
                        cve_text = f'{cve_id}<br/><font size="7">CVSS {top_score:.1f}</font>'
                else:
                    top_sev = self._sev_from_type(t.get('vulnerability_type', ''))

                details = (t.get('details', '') or '')[:60]
                # Nettoyage des emojis pour le PDF
                details = re.sub(r'[^\x00-\x7F]+', '', details).strip()

                vuln_rows.append([
                    f"{vuln.get('ip', '?')}:{vuln.get('port', '?')}",
                    t.get('service', '?'),
                    top_sev,
                    Paragraph(details, self.styles['AFSmall']),
                    Paragraph(cve_text, self.styles['AFSmall']),
                ])

            vuln_table = Table(vuln_rows, colWidths=[80, 65, 65, 170, 110])
            vuln_styles = [
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0f172a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#f8fafc'), white]),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
            ]
            # Color code severity column
            for i in range(1, len(vuln_rows)):
                sev_val = vuln_rows[i][2]
                col = self.SEV_COLORS.get(sev_val, '#94a3b8')
                vuln_styles.append(('TEXTCOLOR', (2, i), (2, i), HexColor(col)))
                vuln_styles.append(('FONTNAME', (2, i), (2, i), 'Helvetica-Bold'))
            vuln_table.setStyle(TableStyle(vuln_styles))
            elements.append(vuln_table)
            elements.append(Spacer(1, 4*mm))

        # ── TABLE DES CVE ──────────────────────────────────────────────
        def _filter_cves(cves):
            return [cve for cve in cves if not (cve.get('cvss_v3_score', 0.0) == 0.0 and (cve.get('severity', '') or '').upper() == 'UNKNOWN')]

        all_cves = _filter_cves(cve_summary.get('all_cves', []))
        if all_cves:
            elements.append(PageBreak())
            elements.append(Paragraph(
                f'Détail des CVE détectés ({len(all_cves)})', self.styles['AFHeading']))

            sorted_cves = sorted(all_cves,
                key=lambda x: x.get('cvss_v3_score', 0) or x.get('cvss_v2_score', 0),
                reverse=True)

            cve_header = ['CVE ID', 'CVSS', 'Sévérité', 'Description', 'CWE']
            cve_rows = [cve_header]
            for cve in sorted_cves[:30]:
                cve_id = cve.get('cve_id', '?')
                cvss = cve.get('cvss_v3_score', 0) or cve.get('cvss_v2_score', 0)
                sev = (cve.get('severity', '') or '').upper() or 'UNKNOWN'
                desc = (cve.get('description', '') or '')[:120]
                cwe_str = ', '.join((cve.get('cwe_ids', []) or [])[:2]) or '—'
                nvd_url = cve.get('nvd_url', '')

                if nvd_url:
                    id_cell = Paragraph(
                        f'<a href="{nvd_url}" color="#3b82f6"><b>{cve_id}</b></a>',
                        self.styles['AFSmall'])
                else:
                    id_cell = Paragraph(f'<b>{cve_id}</b>', self.styles['AFSmall'])

                cve_rows.append([
                    id_cell,
                    f'{cvss:.1f}',
                    sev,
                    Paragraph(desc, self.styles['AFSmall']),
                    Paragraph(cwe_str, self.styles['AFSmall']),
                ])

            cve_table = Table(cve_rows, colWidths=[85, 40, 60, 230, 75])
            cve_styles = [
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0f172a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#f8fafc'), white]),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('ALIGN', (1, 0), (2, -1), 'CENTER'),
            ]
            for i in range(1, len(cve_rows)):
                sev_val = cve_rows[i][2]
                col = self.SEV_COLORS.get(sev_val, '#94a3b8')
                cve_styles.append(('TEXTCOLOR', (2, i), (2, i), HexColor(col)))
                cve_styles.append(('FONTNAME', (2, i), (2, i), 'Helvetica-Bold'))
            cve_table.setStyle(TableStyle(cve_styles))
            elements.append(cve_table)

        # ── GRILLE DE NOTATION ─────────────────────────────────────────
        elements.append(Spacer(1, 6*mm))
        elements.append(Paragraph('Grille de notation Cyberscore', self.styles['AFHeading']))
        grille_data = [
            ['Note', 'Plage', 'Description'],
            ['A', '0 – 19', 'Aucun CVE critique, risque minimal'],
            ['B', '20 – 39', 'CVE de faible/moyenne gravité'],
            ['C', '40 – 59', 'CVE modérés ou accumulation'],
            ['D', '60 – 79', 'CVE élevés ou multiples CVE modérés'],
            ['E', '80 – 100', 'CVE critiques ou accumulation sévère'],
        ]
        grille_table = Table(grille_data, colWidths=[60, 80, 350])
        grille_styles = [
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ('ALIGN', (0, 0), (1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]
        grade_labels = ['A', 'B', 'C', 'D', 'E']
        for i, g in enumerate(grade_labels, start=1):
            col = self.GRADE_COLORS[g]
            grille_styles.append(('TEXTCOLOR', (0, i), (0, i), HexColor(col)))
            grille_styles.append(('FONTNAME', (0, i), (0, i), 'Helvetica-Bold'))
            grille_styles.append(('FONTSIZE', (0, i), (0, i), 14))
            if g == grade:
                grille_styles.append(('BACKGROUND', (0, i), (-1, i), HexColor('#f0f9ff')))
        grille_table.setStyle(TableStyle(grille_styles))
        elements.append(grille_table)

        # ── BUILD PDF ──────────────────────────────────────────────────
        doc.build(elements, onFirstPage=self._header_footer,
                  onLaterPages=self._header_footer)

    @staticmethod
    def _sev_from_type(vtype):
        CRITICAL = ['ftp_anonymous', 'telnet_exposed', 'smb_null_session',
                    'ldap_anonymous', 'smb_v1', 'redis_no_auth']
        HIGH_SEV = ['ftp_exposed', 'ssh_default_creds', 'rdp_exposed', 'mysql_no_password',
                'mongodb_no_auth', 'smb_guest_access']
        HIGH = HIGH_SEV
        MEDIUM = ['http_sensitive_paths', 'dns_zone_transfer',
                  'smtp_open_relay', 'vnc_exposed']
        if vtype in CRITICAL: return 'CRITICAL'
        if vtype in HIGH:     return 'HIGH'
        if vtype in MEDIUM:   return 'MEDIUM'
        return 'LOW'


# ============================================================================
# EXPORT HTML AUTONOME
# ============================================================================

class HTMLReportGenerator:
    """
    Génère un rapport HTML autonome (single-file) à partir du template
    cyberscore_viewer.html en injectant les données JSON directement.
    Le fichier produit s'ouvre dans n'importe quel navigateur sans dépendance.
    """

    def __init__(self, report_data: Dict, output_path: str, template_path: str = None):
        self.data = report_data
        self.output_path = output_path
        # Chercher le template : même dossier que le script, ou racine du projet
        if template_path and os.path.isfile(template_path):
            self.template_path = template_path
        else:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            candidates = [
                os.path.join(script_dir, '..', 'cyberscore_viewer.html'),
                os.path.join(script_dir, 'cyberscore_viewer.html'),
                os.path.join(os.getcwd(), 'cyberscore_viewer.html'),
                os.path.join(os.getcwd(), '..', 'cyberscore_viewer.html'),
            ]
            self.template_path = None
            for c in candidates:
                if os.path.isfile(c):
                    self.template_path = os.path.abspath(c)
                    break

    def generate(self):
        if not self.template_path:
            raise FileNotFoundError(
                "Template cyberscore_viewer.html introuvable. "
                "Vérifiez qu'il est à la racine du projet."
            )

        with open(self.template_path, 'r', encoding='utf-8') as f:
            html = f.read()

        # --- Filtrage des CVE à masquer (score 0.0 et sévérité UNKNOWN) ---
        def _filter_cves(cves):
            return [cve for cve in cves if not (cve.get('cvss_v3_score', 0.0) == 0.0 and cve.get('severity', '').upper() == 'UNKNOWN')]

        filtered_data = json.loads(json.dumps(self.data))  # deep copy
        # Filtrer dans les sections principales si elles existent
        if 'all_cves' in filtered_data:
            filtered_data['all_cves'] = _filter_cves(filtered_data['all_cves'])
        if 'nse_cves' in filtered_data:
            filtered_data['nse_cves'] = _filter_cves(filtered_data['nse_cves'])
        if 'cpe_cves' in filtered_data:
            filtered_data['cpe_cves'] = _filter_cves(filtered_data['cpe_cves'])
        # Filtrer dans chaque vulnérabilité/service
        if 'vulnerabilities' in filtered_data:
            for v in filtered_data['vulnerabilities']:
                if 'cves' in v:
                    v['cves'] = _filter_cves(v['cves'])

        # Sérialiser les données JSON (en échappant </script> pour éviter une fermeture prématurée du bloc script)
        json_str = json.dumps(filtered_data, ensure_ascii=False, default=str)
        json_str = json_str.replace('</script>', r'<\/script>')

        # Injection : ajouter un script d'auto-rendu juste avant </body>
        auto_render_script = (
            '\n<script>\n'
            '// ── Auto-render : données injectées par Audit Flash \n'
            '(function() {\n'
            f'    const _AF_DATA = {json_str};\n'
            '    // Masquer la drop zone et afficher le rapport directement\n'
            '    document.addEventListener("DOMContentLoaded", function() {\n'
            '        renderReport(_AF_DATA);\n'
            '        // Masquer le bouton "Nouveau rapport" (inutile en mode autonome)\n'
            '        var btn = document.querySelector(".btn-reload");\n'
            '        if (btn) btn.style.display = "none";\n'
            '    });\n'
            '})();\n'
            '</script>\n'
        )

        # Insérer avant </body>
        html = html.replace('</body>', auto_render_script + '</body>')

        # Rendre les Google Fonts optionnelles (fallback système)
        html = html.replace(
            '<link rel="preconnect" href="https://fonts.googleapis.com">',
            '<!-- Fonts : chargées si connecté, fallback système sinon -->\n'
            '    <link rel="preconnect" href="https://fonts.googleapis.com">'
        )

        # Mettre à jour le titre de la page
        grade = filtered_data.get('cyberscore', {}).get('grade', '?')
        score = filtered_data.get('cyberscore', {}).get('final_score', '?')
        ts = filtered_data.get('timestamp', '')
        date_str = ''
        if ts:
            try:
                date_str = f" — {datetime.fromisoformat(ts).strftime('%d/%m/%Y %H:%M')}"
            except Exception:
                pass
        html = html.replace(
            '<title>Audit Flash 4.0 — Rapport Cyberscore</title>',
            f'<title>Audit Flash 4.0 — Note {grade} ({score}/100){date_str}</title>'
        )

        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(html)


# ============================================================================
# RÉSOLUTION AUTOMATIQUE CLÉ API NVD
# ============================================================================

def _resolve_nvd_api_key() -> str:
    """
    Résout la clé API NVD par ordre de priorité :
      1. Variable d'environnement NVD_API_KEY
      2. Fichier .nvd-api-key (dossier du script, puis dossier courant)
    """
    # 1. Variable d'environnement
    env_key = os.environ.get('NVD_API_KEY', '').strip()
    if env_key:
        print("[+] Clé API NVD chargée depuis la variable d'environnement NVD_API_KEY")
        return env_key

    # 3. Fichier .nvd-api-key
    search_dirs = [
        os.path.dirname(os.path.abspath(__file__)),  # dossier du script
        os.getcwd(),                                  # dossier courant
    ]
    for directory in search_dirs:
        key_file = os.path.join(directory, '.nvd-api-key')
        if os.path.isfile(key_file):
            try:
                with open(key_file, 'r', encoding='utf-8') as f:
                    file_key = f.read().strip()
                if file_key:
                    print(f"[+] Clé API NVD chargée depuis {key_file}")
                    return file_key
            except Exception as e:
                print(f"[!] Erreur lecture {key_file}: {e}")

    return None


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Audit Flash v5.0 - NSE Scripts + CVE Database + Banner Grabbing + VLAN',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Scan basique avec corrélation CVE
  python audit_flash.py -t 192.168.1.100 --profile top-100

  # Scan complet avec scripts NSE vuln sur tous les ports découverts
  python audit_flash.py -t 192.168.1.100 --profile top-100 --script-scan

  # Scripts NSE spécifiques (ex: audit SSL + vuln SMB)
  python audit_flash.py -t 192.168.1.100 --nse smb-vuln ssl

  # Script-scan + catégories NSE additionnelles
  python audit_flash.py -t 192.168.1.100 --script-scan --nse ssl auth

  # Mode offline avec base CPE locale uniquement
  python audit_flash.py -t 192.168.1.100 --no-cve-api --no-nmap

  # Lister les catégories de scripts NSE disponibles
  python audit_flash.py -t 127.0.0.1 --list-nse

  # Configurer la clé API NVD (pour accélérer les requêtes CVE):
  #   Variable d'environnement : set NVD_API_KEY=VOTRE_CLE
  #   Ou fichier .nvd-api-key dans le dossier du script
  #   Obtenir une clé gratuite : https://nvd.nist.gov/developers/request-an-api-key

  # Avec découverte VLAN
  sudo python3 audit_flash.py -t 192.168.1.100 --profile windows --discover-vlans
        """
    )
    
    parser.add_argument('-t', '--targets', nargs='+', required=True,
                       help='Adresses IP ou plages CIDR')
    parser.add_argument('--profile', choices=SCAN_PROFILES.keys(),
                       help='Profil de scan prédéfini')
    parser.add_argument('--list-profiles', action='store_true',
                       help='Lister les profils disponibles')
    parser.add_argument('-p', '--ports', nargs='+', type=int,
                       help='Ports à scanner (ignoré si --profile)')
    parser.add_argument('-o', '--output', default='audit_report_cve.json',
                       help='Fichier de sortie JSON')
    parser.add_argument('--output-dir', type=str, default='reports',
                       help='Dossier de destination des rapports (défaut: reports/)')
    parser.add_argument('--timeout', type=int, help='Timeout en secondes')
    parser.add_argument('--threads', type=int, help='Nombre de threads')
    parser.add_argument('--no-nmap', action='store_true', help='Désactiver Nmap')
    parser.add_argument('--domain', type=str, help='Domaine pour test DNS')
    
    # Arguments NSE (Scripts Nmap)
    nse_group = parser.add_argument_group('Scripts NSE (Nmap Scripting Engine)')
    nse_group.add_argument('--script-scan', action='store_true',
                          help='Scan global: lance --script vuln sur tous les ports/protocoles '
                               'découverts (équivalent nmap -sV --script vuln)')
    nse_group.add_argument('--nse', nargs='+', type=str, default=None,
                          metavar='CATEGORIE',
                          help='Catégories de scripts NSE additionnelles '
                               '(vuln, safe, default, smb-vuln, ssl, http-vuln, auth, discovery, '
                               'ou nom de script personnalisé)')
    nse_group.add_argument('--list-nse', action='store_true',
                          help='Lister les catégories de scripts NSE disponibles')
    nse_group.add_argument('--no-banner', action='store_true',
                          help='Désactiver le banner grabbing (activé par défaut)')
    
    # Arguments CVE
    cve_group = parser.add_argument_group('Base de données CVE (NVD/NIST)')
    cve_group.add_argument('--no-cve-api', action='store_true',
                          help='Désactiver l\'API NVD (utiliser base locale uniquement)')
    cve_group.add_argument('--cve-cache', type=str, default='cve_cache.json',
                          help='Fichier de cache CVE local (TTL 24h, défaut: cve_cache.json). '
                               'Permet de relancer un audit sans re-fetcher tous les CVEs depuis NVD.')
    
    # Export
    parser.add_argument('--pdf', type=str, default=None, metavar='FICHIER.pdf',
                       help='Générer un rapport PDF (requiert reportlab)')
    parser.add_argument('--html', type=str, default=None, metavar='FICHIER.html',
                       help='Générer un rapport HTML autonome (single-file)')

    # Arguments VLAN
    parser.add_argument('--discover-vlans', action='store_true',
                       help='Découverte VLAN via CDP/LLDP (root requis)')
    parser.add_argument('-i', '--interface', type=str,
                       help='Interface réseau pour VLAN')
    parser.add_argument('--vlan-timeout', type=int, default=65,
                       help='Timeout découverte VLAN (défaut: 65s, couvre au moins 1 cycle CDP de 60s)')
    
    args = parser.parse_args()
    
    # Lister les catégories NSE
    if args.list_nse:
        print(NmapNSEScanner.list_categories())
        sys.exit(0)
    
    if args.list_profiles:
        print("\n" + "="*70 + "\nPROFILS DE SCAN\n" + "="*70)
        for key, profile in SCAN_PROFILES.items():
            print(f"\n{profile['color']} {key.upper()} - {profile['name']}")
            print(f"   {profile['description']} | {len(profile['ports'])} ports | "
                  f"timeout: {profile['timeout']}s")
        sys.exit(0)
    
    # Construire la liste finale de scripts NSE
    nse_final = []
    if args.script_scan:
        nse_final.append('vuln')
    if args.nse:
        for cat in args.nse:
            if cat not in nse_final:
                nse_final.append(cat)
    
    # Vérifier que NSE requiert Nmap
    if nse_final and args.no_nmap:
        print("[!] ERREUR: --script-scan/--nse nécessite Nmap (incompatible avec --no-nmap)")
        sys.exit(1)
    
    if nse_final and not HAS_NMAP:
        print("[!] ERREUR: --script-scan/--nse nécessite python-nmap (pip install python-nmap)")
        print("[!] Et Nmap installé sur le système: https://nmap.org/download.html")
        sys.exit(1)
    
    # Le cache CVE est chargé à l'initialisation de CVEDatabase si le fichier existe
    
    # Appliquer le profil
    if args.profile:
        profile = SCAN_PROFILES[args.profile]
        print(f"\n{profile['color']} Profil: {profile['name']} - {profile['description']}")
        if not args.ports: args.ports = profile['ports']
        if not args.timeout: args.timeout = profile['timeout']
        if not args.threads: args.threads = profile['threads']
    else:
        if not args.timeout: args.timeout = 3
        if not args.threads: args.threads = 50
    
    # Résoudre la clé API NVD (env > fichier)
    resolved_api_key = _resolve_nvd_api_key()

    cve_db = CVEDatabase(
        api_key=resolved_api_key,
        cache_file=args.cve_cache,
        use_api=not args.no_cve_api
    )
    
    if not args.no_cve_api and not resolved_api_key:
        print("[i] Conseil: Obtenez une clé API NVD gratuite pour 10x plus de rapidité")
        print("    https://nvd.nist.gov/developers/request-an-api-key")
        print("    Configurer via :")
        print("      • Variable d'environnement NVD_API_KEY")
        print("      • Fichier .nvd-api-key dans le dossier du script")
    
    # Avertissement scripts intrusifs
    if nse_final:
        intrusive_cats = [
            cat for cat in nse_final 
            if NmapNSEScanner.NSE_CATEGORIES.get(cat, {}).get('intrusive', False)
        ]
        if intrusive_cats:
            print(f"\n[⚠️] ATTENTION: Les catégories NSE suivantes sont INTRUSIVES:")
            for cat in intrusive_cats:
                info = NmapNSEScanner.NSE_CATEGORIES[cat]
                print(f"    • {cat}: {info['description']}")
            print("[⚠️] Ces scripts peuvent déclencher des alertes IDS/IPS.")
            print("[⚠️] Assurez-vous d'avoir l'autorisation de scanner ces cibles.\n")
    
    # Créer le dossier de sortie des rapports
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)
    args.output = os.path.join(output_dir, os.path.basename(args.output))
    if args.pdf:
        args.pdf = os.path.join(output_dir, os.path.basename(args.pdf))
    if args.html:
        args.html = os.path.join(output_dir, os.path.basename(args.html))
    print(f"[+] Rapports enregistrés dans : {output_dir}")

    # Lancer l'audit
    auditor = AuditFlashWindows(
        targets=args.targets,
        ports=args.ports,
        timeout=args.timeout,
        use_nmap=not args.no_nmap,
        domain=args.domain,
        discover_vlans=args.discover_vlans,
        vlan_interface=args.interface,
        vlan_timeout=args.vlan_timeout,
        threads=args.threads,
        cve_db=cve_db,
        nse_scripts=nse_final if nse_final else None,
        banner_grab=not args.no_banner,
    )
    
    auditor.run_audit()
    report = auditor.generate_report(args.output)

    # Export PDF si demandé
    if args.pdf:
        if not HAS_REPORTLAB:
            print("[!] reportlab non installé - impossible de générer le PDF")
            print("    pip install reportlab")
        else:
            try:
                pdf_gen = PDFReportGenerator(report, args.pdf)
                pdf_gen.generate()
                print(f"[+] Rapport PDF généré : {args.pdf}")
            except Exception as e:
                print(f"[!] Erreur génération PDF : {e}")

    # Export HTML autonome si demandé
    if args.html:
        try:
            html_gen = HTMLReportGenerator(report, args.html)
            html_gen.generate()
            print(f"[+] Rapport HTML autonome généré : {args.html}")
        except Exception as e:
            print(f"[!] Erreur génération HTML : {e}")


if __name__ == '__main__':
    main()
