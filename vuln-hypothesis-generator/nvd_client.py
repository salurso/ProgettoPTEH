"""
nvd_client.py — Client per le API NVD (National Vulnerability Database)

Implementa:
- Query CVE per servizio/versione (punto 2)
- Cache SQLite locale con TTL (punto 3)
- Fallback su dataset exploit-db offline VERIFICATO PER VERSIONE (punto 4)
- Metodo curated_cves(): CVE note e applicabili per versione, SENZA keyword-flood

NOTA (fix precision): la vecchia validazione aggiungeva alla lista TUTTE le ~20 CVE
restituite dalla keyword-search NVD per ogni servizio, ignorando la versione. Questo
produceva ~126 "vulnerabilità" quasi tutte irrilevanti (CVE Precision ~0.8%).
Ora la keyword-search NVD serve solo a CONFERMARE una CVE suggerita dall'LLM, mentre
le CVE note vengono aggiunte solo se APPLICABILI alla versione rilevata (curated_cves).
"""

import os
import json
import sqlite3
import time
import requests
from datetime import datetime, timedelta
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


# ─────────────────────────────────────────────
# PUNTO 3 — Cache SQLite
# ─────────────────────────────────────────────

class NVDCache:
    """
    Cache SQLite per evitare query ripetute alle API NVD.
    Ogni risultato scade dopo NVD_CACHE_TTL_HOURS ore.
    """

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_table()

    def _create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS nvd_cache (
                query_key   TEXT PRIMARY KEY,
                response    TEXT NOT NULL,
                cached_at   REAL NOT NULL
            )
        """)
        self.conn.commit()

    def get(self, key: str, ttl_hours: int) -> Optional[list]:
        """Restituisce il dato se presente e non scaduto, altrimenti None."""
        row = self.conn.execute(
            "SELECT response, cached_at FROM nvd_cache WHERE query_key = ?", (key,)
        ).fetchone()

        if not row:
            return None

        cached_at = row[1]
        age_hours = (time.time() - cached_at) / 3600

        if age_hours > ttl_hours:
            # Cache scaduta: elimina e considera miss
            self.conn.execute("DELETE FROM nvd_cache WHERE query_key = ?", (key,))
            self.conn.commit()
            return None

        return json.loads(row[0])

    def set(self, key: str, data: list):
        """Salva un risultato in cache."""
        self.conn.execute(
            "INSERT OR REPLACE INTO nvd_cache (query_key, response, cached_at) VALUES (?, ?, ?)",
            (key, json.dumps(data), time.time())
        )
        self.conn.commit()

    def stats(self) -> dict:
        count = self.conn.execute("SELECT COUNT(*) FROM nvd_cache").fetchone()[0]
        return {"cached_entries": count}


# ─────────────────────────────────────────────
# PUNTO 4 — Dataset curato exploit-db (verificato per versione)
# ─────────────────────────────────────────────

# Dataset minimale hardcoded con CVE reali, note e sfruttabili.
# Le chiavi sono il NOME PRODOTTO (così da fare match sia sul nome servizio Nmap,
# es. "ftp"/"netbios-ssn", sia sulla stringa di versione, es. "vsftpd 2.3.4").
# affected_versions: se valorizzato, la CVE è aggiunta SOLO se la versione combacia.
#                    se vuoto [], la CVE si applica a tutte le versioni del prodotto.
EXPLOITDB_FALLBACK = {
    "vsftpd": [
        {
            "cve_id": "CVE-2011-2523",
            "description": "Backdoor in vsftpd 2.3.4 — apre una shell non autenticata sulla porta 6200/tcp",
            "severity": "CRITICAL", "cvss_score": 9.8, "attack_vector": "NETWORK",
            "affected_versions": ["2.3.4"]
        },
    ],
    "proftpd": [
        {
            "cve_id": "CVE-2015-3306",
            "description": "RCE tramite modulo mod_copy in ProFTPD 1.3.5 (comandi SITE CPFR/CPTO)",
            "severity": "CRITICAL", "cvss_score": 9.8, "attack_vector": "NETWORK",
            "affected_versions": ["1.3.5"]
        },
        {
            "cve_id": "CVE-2010-4221",
            "description": "Stack overflow nel comando TELNET IAC in ProFTPD 1.3.2/1.3.3",
            "severity": "CRITICAL", "cvss_score": 9.8, "attack_vector": "NETWORK",
            "affected_versions": ["1.3.2", "1.3.3"]
        },
    ],
    "samba": [
        {
            "cve_id": "CVE-2007-2447",
            "description": "RCE 'username map script' in Samba 3.0.20-3.0.25rc3 — command injection remota non autenticata",
            "severity": "CRITICAL", "cvss_score": 9.8, "attack_vector": "NETWORK",
            "affected_versions": ["3.0.20", "3.0.21", "3.0.22", "3.0.23", "3.0.24", "3.0.25"]
        },
    ],
    "unreal": [  # UnrealIRCd
        {
            "cve_id": "CVE-2010-2075",
            "description": "Backdoor in UnrealIRCd 3.2.8.1 — esecuzione di comandi arbitrari da remoto",
            "severity": "CRITICAL", "cvss_score": 9.8, "attack_vector": "NETWORK",
            "affected_versions": []
        },
    ],
    "distcc": [
        {
            "cve_id": "CVE-2004-2687",
            "description": "distccd consente l'esecuzione di comandi arbitrari con la configurazione di default",
            "severity": "CRITICAL", "cvss_score": 9.3, "attack_vector": "NETWORK",
            "affected_versions": []
        },
    ],
    "mysql": [
        {
            "cve_id": "CVE-2012-2122",
            "description": "Authentication bypass in MySQL/MariaDB 5.1.x e 5.5.x (confronto memcmp errato)",
            "severity": "HIGH", "cvss_score": 8.1, "attack_vector": "NETWORK",
            "affected_versions": ["5.1", "5.5"]
        },
    ],
    "apache": [
        {
            "cve_id": "CVE-2021-41773",
            "description": "Path traversal e RCE in Apache HTTP Server 2.4.49",
            "severity": "CRITICAL", "cvss_score": 9.8, "attack_vector": "NETWORK",
            "affected_versions": ["2.4.49"]
        },
        {
            "cve_id": "CVE-2021-42013",
            "description": "Path traversal bypass in Apache HTTP Server 2.4.49 e 2.4.50",
            "severity": "CRITICAL", "cvss_score": 9.8, "attack_vector": "NETWORK",
            "affected_versions": ["2.4.49", "2.4.50"]
        },
    ],
    "openssh": [
        {
            "cve_id": "CVE-2023-38408",
            "description": "RCE tramite ssh-agent forwarding in OpenSSH < 9.3p2 (PKCS#11)",
            "severity": "CRITICAL", "cvss_score": 9.8, "attack_vector": "NETWORK",
            "affected_versions": ["9.0", "9.1", "9.2", "9.3"]
        },
    ],
}


def _version_applies(affected_versions: list, haystack: str) -> bool:
    """True se una delle versioni affette compare nella stringa (nome+versione)."""
    if not affected_versions:
        return True  # si applica a tutte le versioni del prodotto
    return any(v.lower() in haystack for v in affected_versions)


def _search_exploitdb_fallback(service_name: str, version: str) -> list:
    """Cerca nel dataset curato per nome prodotto, verificando la versione."""
    haystack = f"{service_name} {version}".lower()
    results = []
    for keyword, cves in EXPLOITDB_FALLBACK.items():
        if keyword in haystack:
            for cve in cves:
                if _version_applies(cve.get("affected_versions") or [], haystack):
                    results.append(dict(cve))
    return results


def _cpe22_to_23(cpe: str) -> str:
    """
    Converte il CPE prodotto da nmap (formato 2.2 URI, es. 'cpe:/a:openbsd:openssh:4.7p1')
    nel formato CPE 2.3 formatted-string richiesto da NVD
    ('cpe:2.3:a:openbsd:openssh:4.7p1:*:*:*:*:*:*:*'). I campi mancanti diventano '*'.
    Ritorna "" se il CPE non è riconoscibile.
    """
    cpe = (cpe or "").strip()
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
    elif cpe.startswith("cpe:/"):
        parts = ["cpe", "2.3"] + cpe[len("cpe:/"):].split(":")
    else:
        return ""
    # cpe:2.3 + 11 componenti = 13 token totali; i mancanti → '*'
    while len(parts) < 13:
        parts.append("*")
    return ":".join(parts[:13])


# ─────────────────────────────────────────────
# PUNTI 1 e 2 — NVD Client principale
# ─────────────────────────────────────────────

class NVDClient:
    """
    Client completo per NVD API v2.

    Flusso di query:
      1. Controlla la cache SQLite
      2. Se cache miss → chiama l'API NVD
      3. Se NVD è down / chiave assente → fallback exploit-db curato
    """

    def __init__(self):
        self.api_key   = os.getenv("NVD_API_KEY", "")
        self.base_url  = os.getenv("NVD_API_BASE_URL",
                                   "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.ttl_hours = int(os.getenv("NVD_CACHE_TTL_HOURS", 24))
        db_path        = os.getenv("NVD_CACHE_DB", "output/nvd_cache.db")
        self.cache     = NVDCache(db_path)

    # ── PUNTO 2 ───────────────────────────────
    def search_cves(self, service_name: str, version: str = "") -> list:
        """
        Cerca CVE per nome servizio e versione (keyword-search NVD).
        Usata per CONFERMARE una CVE suggerita dall'LLM, NON per riversare
        tutte le CVE del servizio nel report.

        Restituisce lista di dict normalizzati:
        [{cve_id, description, severity, cvss_score, attack_vector}]
        """
        query_key = f"{service_name.lower()}::{version.lower()}"
        print(f"  [NVD] Query: '{service_name} {version}'".rstrip())

        # 1. Controlla cache
        cached = self.cache.get(query_key, self.ttl_hours)
        if cached is not None:
            print(f"  [NVD] Cache HIT ({len(cached)} CVE trovate)")
            return cached

        # 2. Prova API NVD
        if self.api_key:
            results = self._query_nvd_api(service_name, version)
            if results is not None:
                self.cache.set(query_key, results)
                print(f"  [NVD] API OK — {len(results)} CVE trovate, salvate in cache")
                return results
        else:
            print("  [NVD] API key assente — skip API, uso dataset curato")

        # 3. Fallback dataset curato (verificato per versione)
        results = _search_exploitdb_fallback(service_name, version)
        print(f"  [NVD] Dataset curato — {len(results)} CVE applicabili")
        self.cache.set(query_key, results)
        return results

    def curated_cves(self, service_name: str, version: str = "") -> list:
        """
        CVE note e VERIFICATE PER VERSIONE dal dataset curato (nessun keyword-flood).
        Cerca il prodotto sia nel nome servizio sia nella stringa di versione.
        È la fonte autorevole per aggiungere al report CVE applicabili ai servizi
        realmente rilevati, con alta precisione.
        """
        return _search_exploitdb_fallback(service_name, version)

    # ── Scoperta GENERALE per CPE (non statica, riproducibile su qualsiasi target) ──
    def cves_by_cpe(self, cpe: str) -> list:
        """
        Interroga NVD col CPE rilevato da nmap (parametro virtualMatchString) e
        restituisce TUTTE le CVE il cui range di versioni include quella del servizio.
        È NVD stessa a fare il match sulla versione: niente tabella statica, niente
        keyword-flood. Funziona su qualsiasi sistema purché nmap fornisca un CPE.
        Cache per CPE. Se la chiave API manca o NVD è irraggiungibile, ritorna [].
        """
        cpe23 = _cpe22_to_23(cpe)
        if not cpe23:
            return []
        # GUARDIA VERSIONE: senza una versione concreta nel CPE, virtualMatchString
        # restituirebbe TUTTE le CVE del prodotto (di ogni versione) → non applicabili
        # alla versione realmente rilevata. In quel caso NON interroghiamo: il servizio
        # resta coperto da LLM+NVD e dal DB curato.
        _tok = cpe23.split(":")
        ver_field = _tok[5] if len(_tok) > 5 else "*"
        if ver_field in ("", "*", "-"):
            print(f"  [NVD/CPE] CPE senza versione precisa ({cpe}) — skip (eviterebbe match su tutte le versioni)")
            return []
        query_key = f"cpe::{cpe23.lower()}"
        cached = self.cache.get(query_key, self.ttl_hours)
        if cached is not None:
            print(f"  [NVD/CPE] Cache HIT {cpe23} ({len(cached)} CVE)")
            return cached
        if not self.api_key:
            print("  [NVD/CPE] API key assente — skip scoperta per CPE")
            return []
        results = self._query_nvd_cpe(cpe23)
        if results is None:
            return []
        self.cache.set(query_key, results)
        print(f"  [NVD/CPE] {cpe23} → {len(results)} CVE applicabili alla versione")
        return results

    def _query_nvd_cpe(self, cpe23: str) -> Optional[list]:
        """Chiama NVD con virtualMatchString=<cpe2.3> e normalizza il risultato."""
        headers = {"apiKey": self.api_key}
        params  = {"virtualMatchString": cpe23, "resultsPerPage": 200}
        try:
            resp = requests.get(self.base_url, headers=headers, params=params, timeout=15)
            resp.raise_for_status()
            return self._normalize_nvd_response(resp.json())
        except requests.exceptions.ConnectionError:
            print("  [NVD/CPE] Server NVD non raggiungibile")
            return None
        except requests.exceptions.Timeout:
            print("  [NVD/CPE] Timeout connessione a NVD")
            return None
        except requests.exceptions.HTTPError as e:
            print(f"  [NVD/CPE] Errore HTTP: {e}")
            return None
        except Exception as e:
            print(f"  [NVD/CPE] Errore imprevisto: {e}")
            return None

    def _query_nvd_api(self, service_name: str, version: str) -> Optional[list]:
        """Chiama l'API NVD e normalizza il risultato."""
        keyword = f"{service_name} {version}".strip()
        headers = {"apiKey": self.api_key}
        params  = {
            "keywordSearch": keyword,
            "resultsPerPage": 20,
        }

        try:
            resp = requests.get(
                self.base_url,
                headers=headers,
                params=params,
                timeout=10
            )
            resp.raise_for_status()
            data = resp.json()
            return self._normalize_nvd_response(data)

        except requests.exceptions.ConnectionError:
            print("  [NVD] Server NVD non raggiungibile (down o no internet)")
            return None
        except requests.exceptions.Timeout:
            print("  [NVD] Timeout connessione a NVD")
            return None
        except requests.exceptions.HTTPError as e:
            print(f"  [NVD] Errore HTTP: {e}")
            return None
        except Exception as e:
            print(f"  [NVD] Errore imprevisto: {e}")
            return None

    def _normalize_nvd_response(self, data: dict) -> list:
        """
        Trasforma la risposta raw dell'API NVD nel formato interno.
        Formato NVD → formato interno normalizzato.
        """
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            # Estrai descrizione in inglese
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available"
            )

            # Estrai CVSS score (preferisci v3.1, poi v3.0, poi v2)
            metrics = cve.get("metrics", {})
            severity    = "UNKNOWN"
            cvss_score  = 0.0
            attack_vector = "UNKNOWN"

            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    severity      = cvss_data.get("baseSeverity", "UNKNOWN")
                    cvss_score    = cvss_data.get("baseScore", 0.0)
                    attack_vector = cvss_data.get("attackVector", "UNKNOWN")
                    break

            results.append({
                "cve_id":        cve_id,
                "description":   description,
                "severity":      severity,
                "cvss_score":    cvss_score,
                "attack_vector": attack_vector,
                "affected_versions": []
            })

        return results
