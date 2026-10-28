"""
exposure_detector.py — Osservazioni dagli script NSE di nmap.

Principio di onestà: NON siamo noi a dichiarare quali misconfigurazioni esistono.
Le rileva uno strumento (nmap) tramite i suoi script NSE; qui ci limitiamo a
LEGGERE (parsare) ciò che nmap ha realmente prodotto in nmap_scan.xml e a
trasformarlo in finding. L'esistenza dell'osservazione viene dal tool, non da
una nostra regola scritta a mano.

Natura dei finding: sono OSSERVAZIONI, con severity=INFO e SENZA CVSS calcolato.
Non vengono "giudicate" da noi: riportiamo l'evidenza grezza dello strumento.
Le vere vulnerabilità con CVE e severità restano compito del Vulnerability
Generator (CVE + NVD/DB curato); qui aumentiamo solo la copertura sfruttando al
massimo i dati che nmap già raccoglie, senza scanner esterni.

Per rendere la rilevazione davvero tool-driven e completa, lo scan va lanciato
con più categorie di script NSE, es.:
    nmap -sV -A --script "default,safe,vuln" -Pn <target> -oX nmap_scan.xml
- default : set curato eseguito da -sC (ftp-anon, ssl-cert, ssh-hostkey, ...)
- safe    : raccolta informazioni non invasiva, più ampia del default
- vuln    : verifica attiva di vulnerabilità note (ftp-vsftpd-backdoor, smb-vuln-*, ...)

L'arricchimento descrittivo delle osservazioni resta compito dell'LLM nel
Reporting Engine.
"""

import xml.etree.ElementTree as ET
from typing import List


# Script NSE informativi noti → (titolo leggibile, remediation di base).
# Per questi diamo un testo curato; estendibile.
_NSE_RELEVANT = {
    "ftp-anon":           ("FTP: accesso anonimo consentito",
                           "Disabilitare l'accesso anonimo (anonymous_enable=NO) o usare SFTP/FTPS."),
    "smb-security-mode":  ("SMB: firma dei messaggi non applicata",
                           "Rendere obbligatorio l'SMB signing per prevenire relay/MITM."),
    "smb2-security-mode": ("SMB2: firma dei messaggi non applicata",
                           "Rendere obbligatorio l'SMB signing."),
    "nfs-showmount":      ("NFS: condivisioni esportate visibili",
                           "Restringere gli export NFS ai soli host autorizzati (evitare 'everyone')."),
    "nfs-ls":             ("NFS: contenuto delle condivisioni accessibile",
                           "Limitare permessi ed export NFS; applicare root_squash."),
    "ssl-cert":           ("TLS: certificato da verificare",
                           "Verificare validità, scadenza e robustezza del certificato."),
    "ssl-dh-params":      ("TLS: parametri Diffie-Hellman deboli",
                           "Usare gruppi DH >= 2048 bit o scambio su curve ellittiche."),
    "sslv2":              ("TLS: SSLv2 supportato (obsoleto)",
                           "Disabilitare SSLv2/SSLv3; abilitare solo TLS 1.2+."),
    "ssh2-enum-algos":    ("SSH: algoritmi deboli supportati",
                           "Disabilitare cifrari/MAC deboli (es. CBC, arcfour, MD5)."),
    "ssh-hostkey":        ("SSH: chiavi host esposte",
                           "Verificare la robustezza delle chiavi host e ruotarle se deboli."),
    "http-methods":       ("HTTP: metodi potenzialmente pericolosi",
                           "Disabilitare i metodi non necessari (PUT, DELETE, TRACE)."),
    "telnet-encryption":  ("Telnet: nessuna cifratura disponibile",
                           "Sostituire Telnet con SSH."),
    "vnc-info":           ("VNC: informazioni/sicurezza del servizio esposte",
                           "Proteggere VNC con autenticazione forte e canale cifrato."),
    "rpcinfo":            ("RPC: servizi registrati enumerabili",
                           "Limitare l'accesso ai servizi RPC via firewall."),
    "mysql-info":         ("MySQL: servizio e versione esposti",
                           "Limitare l'accesso al database e aggiornare il server."),
}


def _humanize(sid: str) -> str:
    """Titolo leggibile per uno script non in whitelist (es. ftp-vsftpd-backdoor)."""
    return "NSE: " + sid.replace("-", " ").replace("_", " ").strip()


def detect_nse_observations(nmap_xml_path: str) -> List[dict]:
    """
    Legge gli output degli script NSE da nmap_scan.xml e li trasforma in finding
    informativi (severity=INFO, SENZA CVSS). Deterministico e corroborato: emette
    solo ciò che nmap ha realmente prodotto.

    Due vie, entrambe tool-driven:
      1) script informativi noti (whitelist) → titolo/remediation curati;
      2) qualsiasi script che riporti uno stato 'VULNERABLE' (tipico della libreria
         'vuln' di NSE, es. ftp-vsftpd-backdoor, smb-vuln-*) → osservazione generica.
    Risultati 'NOT VULNERABLE' o vuoti vengono ignorati (niente rumore).
    Se l'XML non c'è/è illeggibile, ritorna [].
    """
    out: List[dict] = []
    seen = set()
    try:
        root = ET.parse(nmap_xml_path).getroot()
    except Exception:
        return out

    def _emit(scr, svc, port):
        sid = (scr.get("id") or "").lower()
        output = (scr.get("output") or "").strip()
        up = output.upper()

        if sid in _NSE_RELEVANT:
            title, rem = _NSE_RELEVANT[sid]
        elif "VULNERABLE" in up and "NOT VULNERABLE" not in up and "COULDN'T" not in up:
            # Script di vulnerabilità (categoria 'vuln') con esito positivo.
            title = _humanize(sid)
            rem = "Rimediare la vulnerabilità segnalata da nmap (aggiornamento/patch del servizio)."
        else:
            return  # script non rilevante o esito negativo/vuoto → ignorato

        key = f"{sid}:{port}"
        if key in seen:
            return
        seen.add(key)

        out.append({
            "id":                 f"NSE-{sid.upper()}" + (f"-{port}" if port else ""),
            "cve_id":             "N/A",
            "title":              title,
            "severity":           "INFO",      # osservazione non "rated"
            "cvss_score":         None,         # SENZA CVSS calcolato (per scelta)
            "cvss_vector":        None,
            "severity_source":    "nse-observation",
            "affected_service":   f"{svc}" + (f" porta {port}" if port else ""),
            "service_name":       svc,
            "service_port":       int(port) if str(port).isdigit() else 0,
            "description":        f"Osservazione dallo script NSE '{sid}' di nmap sul servizio {svc or 'host'}.",
            "exploitation_path":  "Osservazione rilevata attivamente da uno script NSE di nmap",
            "evidence":           output[:400],
            "remediation":        rem,
            "remediation_source": "scan",       # l'LLM la arricchirà nel Reporting Engine
            "category":           "nse-observation",
            "source":             "nse",
            "references":         [],
        })

    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            portid = port.get("portid", "")
            svc_el = port.find("service")
            svc = svc_el.get("name", "") if svc_el is not None else ""
            for scr in port.findall("script"):
                _emit(scr, svc, portid)
        for scr in host.findall("./hostscript/script"):
            _emit(scr, "host", "")
    return out
