import sys
import os
import json
from datetime import datetime
from typing import Optional
from jinja2 import Environment, FileSystemLoader
from dotenv import load_dotenv

load_dotenv()

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core_shared.llm_client import LLMClient


class ReportCollector:
    """
    Aggrega l'output di tutti i moduli della pipeline in un unico dict.
    Legge i file JSON prodotti da ogni modulo nella cartella output/.
    """

    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def _load(self, filename: str) -> Optional[dict]:
        path = os.path.join(self.output_dir, filename)
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return None

    def collect(self) -> dict:
        """
        Carica tutti gli output della pipeline.
        Se un file non esiste usa dati di fallback per demo.
        """
        print("[INFO] Raccolta dati da tutti i moduli...")

        # Recon Agent
        recon = self._load("recon_results.json")
        if recon:
            target_ip           = recon.get("target_info", {}).get("resolved", "N/A")
            discovered_services = recon.get("results", [])
            print(f"  [OK] recon_results.json — target: {target_ip}")
        else:
            target_ip           = "192.168.1.50"
            discovered_services = [
                {"tool": "nmap", "success": True,
                 "output": "22/tcp open ssh OpenSSH 8.2p1\n80/tcp open http Apache/2.4.29\n21/tcp open ftp vsftpd 2.3.4"}
            ]
            print("  [DEMO] recon_results.json non trovato — uso dati demo")

        #vulnerability Generator
        vulns = self._load("vulnerabilities.json")
        exposures      = (vulns or {}).get("exposures", [])
        llm_weaknesses = (vulns or {}).get("llm_weaknesses", [])
        if vulns:
            vulnerabilities = vulns.get("vulnerabilities", [])
            print(f"  [OK] vulnerabilities.json — {len(vulnerabilities)} vulnerabilità, "
                  f"{len(exposures)} esposizioni, {len(llm_weaknesses)} debolezze LLM")
        else:
            vulnerabilities = [
                {"cve_id": "CVE-2011-2523", "severity": "CRITICAL", "cvss_score": 10.0,
                 "service_name": "vsftpd", "service_port": 21,
                 "description": "Backdoor in vsftpd 2.3.4 — shell su porta 6200",
                 "attack_vector": "NETWORK", "risk_score": 9.8, "rank": 1},
                {"cve_id": "CVE-2021-41773", "severity": "CRITICAL", "cvss_score": 9.8,
                 "service_name": "apache", "service_port": 80,
                 "description": "Path traversal in Apache 2.4.49",
                 "attack_vector": "NETWORK", "risk_score": 9.2, "rank": 2},
                {"cve_id": "CVE-2019-0211", "severity": "HIGH", "cvss_score": 7.8,
                 "service_name": "apache", "service_port": 80,
                 "description": "Local privilege escalation in Apache < 2.4.39",
                 "attack_vector": "LOCAL", "risk_score": 6.5, "rank": 3},
            ]
            print("  [DEMO] vulnerabilities.json non trovato — uso dati demo")

        #execution Results
        exec_data = self._load("execution_results.json")
        if exec_data:
            execution_results = exec_data.get("results", [])
            print(f"  [OK] execution_results.json — {len(execution_results)} step")
        else:
            execution_results = [
                {"step_number": 1, "step_name": "port_scan", "tool": "nmap",
                 "status": "SUCCESS", "exit_code": 0, "duration_s": 12,
                 "output": "21/tcp open ftp\n22/tcp open ssh\n80/tcp open http"},
                {"step_number": 2, "step_name": "ftp_backdoor_check", "tool": "netcat",
                 "status": "SUCCESS", "exit_code": 0, "duration_s": 3,
                 "output": "Connessione su porta 6200 riuscita — shell attiva"},
                {"step_number": 3, "step_name": "http_traversal", "tool": "curl",
                 "status": "FAILED", "exit_code": 1, "duration_s": 5,
                 "output": ""},
            ]
            print("  [DEMO] execution_results.json non trovato — uso dati demo")

        return {
            "target_ip":           target_ip,
            "discovered_services": discovered_services,
            "vulnerabilities":     vulnerabilities,
            "exposures":           exposures,
            "llm_weaknesses":      llm_weaknesses,
            "execution_results":   execution_results,
            "collected_at":        datetime.now().isoformat()
        }




def extract_evidence(execution_results: list) -> dict:
    """
    Estrae le evidenze (prove di compromissione) dai log di esecuzione.
    Mappa ogni step al suo output rilevante.
    """
    evidence = {}
    for r in execution_results:
        if r.get("status") == "SUCCESS" and r.get("output"):
            step_key = f"step_{r['step_number']}_{r.get('step_name', 'unknown')}"
            evidence[step_key] = {
                "tool":     r.get("tool", ""),
                "output":   r.get("output", "")[:500],
                "duration": r.get("duration_s", 0)
            }
    return evidence




SEVERITY_COLORS = {
    "CRITICAL": "#e53e3e",
    "HIGH":     "#dd6b20",
    "MEDIUM":   "#d69e2e",
    "LOW":      "#38a169",
    "INFO":     "#718096"
}

def compute_findings_stats(findings: list) -> dict:
    """Conta i finding per severity per le statistiche nel report."""
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in stats:
            stats[sev] += 1
    return stats


#report LLM

def generate_report_with_llm(llm: LLMClient, data: dict) -> Optional[dict]:
    """
    Chiede al LLM di generare executive summary, findings dettagliati e remediation.
    """
    print("\n[INFO] Generazione report con LLM...")

    top_vulns = data["vulnerabilities"][:10]

    prompt = llm.render_prompt("report_prompt.j2", {
        "target_ip":          data["target_ip"],
        "date":               datetime.now().strftime("%d/%m/%Y %H:%M"),
        "discovered_services":data["discovered_services"][:10],
        "vulnerabilities":    top_vulns,
        "execution_results":  data["execution_results"]
    })

  
  #utilizziamo il fallback se viene raggiunto il limite deei token
    report_max = int(os.getenv("REPORT_MAX_TOKENS", "900"))
    try:
        raw = llm.generate(prompt, json_mode=True, max_tokens=report_max)
    except Exception as e:
        print(f"  [WARN] Chiamata LLM fallita ({e}) — uso report di fallback")
        return None

    # Parsing robusto
    import json as _json
    for attempt in [raw, raw[raw.find("{"):raw.rfind("}")+1] if "{" in raw else ""]:
        try:
            parsed = _json.loads(attempt)
            if "executive_summary" in parsed:
                print("  [OK] Report LLM generato correttamente")
                return parsed
        except Exception:
            pass

    print("  [WARN] LLM non ha restituito JSON valido — uso report di fallback")
    return None


def build_fallback_report(data: dict) -> dict:
    """
    Report di fallback se il LLM non risponde correttamente.
    Costruito dai dati raw senza LLM.
    """
    vulns    = data["vulnerabilities"]
    critical = [v for v in vulns if v.get("severity") == "CRITICAL"]
    high     = [v for v in vulns if v.get("severity") == "HIGH"]

    findings = []
    for i, v in enumerate(vulns, 1):
        findings.append({
            "id":               f"FIND-{i:03d}",
            "cve_id":           v.get("cve_id", "N/A"),
            "title":            v.get("description", "")[:60],
            "severity":         v.get("severity", "UNKNOWN"),
            "cvss_score":       v.get("cvss_score", 0),
            "affected_service": f"{v.get('service_name','')} porta {v.get('service_port','')}",
            "description":      v.get("description", ""),
            "exploitation_path":"Identificata durante la fase di vulnerability assessment automatizzato",
            "evidence":         "",
            "remediation":      "Aggiornare il software all'ultima versione disponibile",
            "remediation_source":"code_fallback",
            "references":       [f"https://nvd.nist.gov/vuln/detail/{v.get('cve_id','')}"]
        })

    overall = "CRITICAL" if critical else "HIGH" if high else "MEDIUM"
    max_cvss = max((v.get("cvss_score", 0) for v in vulns), default=0)

    return {
        "executive_summary":  (
            f"La valutazione automatizzata del target {data['target_ip']} ha identificato "
            f"{len(vulns)} vulnerabilità, di cui {len(critical)} critiche e {len(high)} alte. "
            f"Il sistema presenta rischi significativi che richiedono intervento immediato."
        ),
        "overall_risk_level": overall,
        "risk_score":         round(max_cvss, 1),
        "findings":           findings,
        "recommendations": [
            {"priority": "IMMEDIATE",  "action": "Aggiornare tutti i pacchetti vulnerabili", "effort": "low", "source": "code_fallback"},
            {"priority": "SHORT_TERM", "action": "Implementare firewall e IDS", "effort": "medium", "source": "code_fallback"},
            {"priority": "LONG_TERM",  "action": "Eseguire pentest periodici", "effort": "high", "source": "code_fallback"}
        ],
        "methodology":  "Black-box penetration test automatizzato con LLM agent",
        "disclaimer":   "Report generato su sistema autorizzato in ambiente controllato.",
        "report_source": "code_fallback"
    }


#generazione del html con jinja

def generate_html(report: dict, data: dict, templates_dir: str, output_path: str):
    """
    Renderizza il template HTML con i dati del report.
    """
    env      = Environment(loader=FileSystemLoader(templates_dir))
    template = env.get_template("report_template.html")

    exec_results    = data["execution_results"]
    success_steps   = sum(1 for r in exec_results if r.get("status") == "SUCCESS")
    findings_stats  = compute_findings_stats(report.get("findings", []))

    html = template.render(
        target_ip          = data["target_ip"],
        date               = datetime.now().strftime("%d/%m/%Y %H:%M"),
        report             = report,
        execution_results  = exec_results,
        total_steps        = len(exec_results),
        success_steps      = success_steps,
        findings_by_severity = findings_stats
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"  [OK] Report HTML: {output_path}")
    return html


#export ddel pdf con weasyprint

def generate_pdf(html_path: str, pdf_path: str):
    """
    Converte il report HTML in PDF usando WeasyPrint.
    Se WeasyPrint non è installato lo segnala senza crashare.
    """
    try:
        from weasyprint import HTML
        HTML(filename=html_path).write_pdf(pdf_path)
        print(f"  [OK] Report PDF:  {pdf_path}")
        return True
    except ImportError:
        print("  [SKIP] WeasyPrint non installato — solo HTML generato")
        print("         Per abilitare PDF: pip install weasyprint")
        return False
    except Exception as e:
        print(f"  [WARN] Errore generazione PDF: {e}")
        return False


#supporto dell'LLM per il secondo run

_ALL_TIERS = ["IMMEDIATE", "SHORT_TERM", "LONG_TERM"]


def fill_missing_advice_with_llm(llm: LLMClient, report: dict, data: dict) -> None:
    findings_missing = [f for f in report.get("findings", []) if not f.get("remediation")]
    present_tiers    = {(r.get("priority") or "").upper() for r in report.get("recommendations", [])}
    missing_tiers    = [t for t in _ALL_TIERS if t not in present_tiers]
    if not findings_missing and not missing_tiers:
        return 

    print("[INFO] Consigli mancanti dal report — secondo giro LLM mirato...")
    try:
        prompt = llm.render_prompt("advice_fill_prompt.j2", {
            "target_ip":         data["target_ip"],
            "target_os":         data.get("target_os", "sconosciuto"),
            "findings_missing":  findings_missing,
            "missing_tiers":     missing_tiers,
            "vulnerabilities":   data.get("vulnerabilities", [])[:10],
        })
        raw = llm.generate(prompt, json_mode=True,
                           max_tokens=int(os.getenv("ADVICE_MAX_TOKENS", "600")))
        import json as _json
        parsed = None
        for attempt in [raw, raw[raw.find("{"):raw.rfind("}") + 1] if "{" in raw else ""]:
            try:
                parsed = _json.loads(attempt); break
            except Exception:
                pass
        if not parsed:
            print("  [WARN] Secondo giro LLM senza JSON valido")
            return

        #assegna le remediation per id finding
        rem_map = parsed.get("remediations", {}) or {}
        filled = 0
        for f in findings_missing:
            txt = rem_map.get(f.get("id"))
            if txt and isinstance(txt, str) and txt.strip():
                f["remediation"] = txt.strip()
                f["remediation_source"] = "llm"
                filled += 1

      
        recos = parsed.get("recommendations") or []
        added = 0
        if missing_tiers and isinstance(recos, list):
            existing = report.get("recommendations", []) or []
            have = {(r.get("priority") or "").upper() for r in existing}
            for r in recos:
                pr = (r.get("priority") or "").upper()
                if pr in missing_tiers and pr not in have and (r.get("action") or "").strip():
                    r["source"] = "llm"
                    existing.append(r)
                    have.add(pr)
                    added += 1
            report["recommendations"] = existing
        print(f"  [OK] Secondo giro LLM: {filled} remediation + {added} raccomandazioni (livelli mancanti) dall'LLM")
    except Exception as e:
        print(f"  [WARN] Secondo giro LLM fallito ({e})")



def _severity_from_cvss(score) -> str:
    """Deriva la banda di severità dal punteggio CVSS (quando NVD non la fornisce)."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s <= 0:   return "NONE"
    if s < 4.0:  return "LOW"
    if s < 7.0:  return "MEDIUM"
    if s < 9.0:  return "HIGH"
    return "CRITICAL"


def rebuild_findings_from_all_cves(report: dict, data: dict) -> None:
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return

    #Indicizza le remediation/descrizioni che l'LLM ha già prodotto, per CVE.
    llm_by_cve = {}
    for f in report.get("findings", []):
        cid = (f.get("cve_id") or "").upper()
        if cid and cid != "N/A":
            llm_by_cve[cid] = f

    full = []
    for i, v in enumerate(vulns, 1):
        cid = (v.get("cve_id") or "N/A").upper()
        sev = v.get("severity") or "UNKNOWN"
        if sev in ("UNKNOWN", "NONE", "", None):
            sev = _severity_from_cvss(v.get("cvss_score", 0))

        lf = llm_by_cve.get(cid)
        if lf and lf.get("remediation"):
            remediation = lf["remediation"]
            rem_src     = "llm"
            description = lf.get("description") or v.get("description", "")
        else:
            remediation = ("Aggiornare il componente alla versione supportata o "
                           "disabilitare/limitare il servizio se non necessario.")
            rem_src     = "code_fallback"
            description = v.get("description", "")

        cve_id = v.get("cve_id", "N/A")
        full.append({
            "id":                 f"FIND-{i:03d}",
            "cve_id":             cve_id,
            "title":              (description or cve_id)[:70],
            "severity":           sev,
            "cvss_score":         v.get("cvss_score", 0.0),
            "affected_service":   f"{v.get('service_name','')} porta {v.get('service_port','')}".strip(),
            "service_name":       v.get("service_name", ""),
            "service_port":       v.get("service_port", 0),
            "description":        description,
            "exploitation_path":  "Identificata nel vulnerability assessment (NVD per CPE / DB curato / LLM+NVD)",
            "evidence":           "",
            "remediation":        remediation,
            "remediation_source": rem_src,
            "source":             v.get("source", ""),
            "references":         ([f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id != "N/A" else []),
        })

    report["findings"] = full


def enrich_exposures_with_llm(llm: LLMClient, exposures: list) -> None:
    if not exposures:
        return
    print("[INFO] Arricchimento esposizioni con LLM (descrizione + remediation)...")
    items = [{"id": e.get("id"), "title": e.get("title"),
              "service": e.get("affected_service", ""),
              "severity": e.get("severity", "")} for e in exposures]
    prompt = (
        "Sei un penetration tester. Le seguenti esposizioni/misconfigurazioni sono "
        "GIA' state rilevate e valutate dal sistema (non modificare id, severita' o "
        "punteggio). Per ciascuna scrivi in italiano: una breve DESCRIZIONE del rischio "
        "(1-2 frasi, contestuale al servizio) e una REMEDIATION specifica e azionabile "
        "(1-2 frasi). Rispondi SOLO con JSON valido nella forma:\n"
        "{\"items\":[{\"id\":\"EXPO-...\",\"description\":\"...\",\"remediation\":\"...\"}]}\n\n"
        "Esposizioni:\n" + json.dumps(items, ensure_ascii=False)
    )
    try:
        raw = llm.generate(prompt, json_mode=True,
                           max_tokens=int(os.getenv("EXPO_MAX_TOKENS", "2500")))
        import json as _json
        parsed = None
        for attempt in [raw, raw[raw.find("{"):raw.rfind("}") + 1] if "{" in raw else ""]:
            try:
                parsed = _json.loads(attempt); break
            except Exception:
                pass
        if not parsed:
            print("  [WARN] LLM senza JSON valido — resta il testo del rilevatore (fallback)")
            return
        by_id = {it.get("id"): it for it in parsed.get("items", []) if isinstance(it, dict)}
        enriched = 0
        for e in exposures:
            it = by_id.get(e.get("id"))
            if not it:
                continue
            desc = (it.get("description") or "").strip()
            rem  = (it.get("remediation") or "").strip()
            if desc:
                e["description"] = desc
                e["description_source"] = "llm"
            if rem:
                e["remediation"] = rem
                e["remediation_source"] = "llm"   #badge per il report
            if desc or rem:
                enriched += 1
        print(f"  [OK] {enriched}/{len(exposures)} esposizioni arricchite dall'LLM "
              f"(rilevamento e CVSS restano del codice)")
    except Exception as ex:
        print(f"  [WARN] Arricchimento LLM fallito ({ex}) — resta il testo del rilevatore")




def main():
    print("=" * 55)
    print("  REPORTING ENGINE")
    print("=" * 55)

    current_dir    = os.path.dirname(os.path.abspath(__file__))
    output_dir     = os.path.abspath(os.path.join(current_dir, '..', 'output'))
    templates_dir  = os.path.abspath(os.path.join(current_dir, '..', 'core_shared', 'templates'))
    llm            = LLMClient(templates_dir=templates_dir)

    #raccolta dati da tutti i moduli
    collector = ReportCollector(output_dir)
    data      = collector.collect()

    # PUNTO 3: estrai evidenze dai log
    evidence = extract_evidence(data["execution_results"])
    print(f"\n[INFO] Evidenze estratte: {len(evidence)} step con output")

    # PUNTO 4: genera report con LLM
    report = generate_report_with_llm(llm, data)
    if not report:
        report = build_fallback_report(data)
    else:
       
        report.setdefault("report_source", "llm")

   
    rebuild_findings_from_all_cves(report, data)

 
    for rec in report.get("recommendations", []):
        rec.setdefault("source", "llm")
    for finding in report.get("findings", []):
        if finding.get("remediation"):
            finding.setdefault("remediation_source", "llm")

   
    report.setdefault("methodology", "Black-box penetration test automatizzato con LLM agent")
    report.setdefault("disclaimer", "Report generato in ambiente controllato su sistema autorizzato.")

  
    fill_missing_advice_with_llm(llm, report, data)

    
    if not report.get("recommendations"):
        report["recommendations"] = [
            {"priority": "IMMEDIATE", "action": "LLM non disponibile: analizzare i finding e definire le azioni di remediation.", "effort": "n/d", "source": "code_fallback"}
        ]

    
    for finding in report.get("findings", []):
        finding.setdefault("severity", "INFO")
        if finding.get("cvss_score") is None:
            finding["cvss_score"] = 0.0
        if not finding.get("remediation"):
            finding["remediation"] = (
                "Aggiornare il componente all'ultima versione supportata o "
                "disabilitare/limitare il servizio se non necessario."
            )
            finding["remediation_source"] = "code_fallback"

  
    for finding in report.get("findings", []):
        if finding.get("evidence"):
            continue
        cve = (finding.get("cve_id") or "").lower()
        svc = (finding.get("affected_service") or "").lower()
        for step_key, ev in evidence.items():
            out = (ev.get("output") or "")
            hay = f"{step_key} {out}".lower()
            # match se la CVE o il nome servizio compaiono nell'evidenza/nome step
            if (cve and cve in hay) or any(tok and tok in hay for tok in svc.split()[:1]):
                finding["evidence"] = out
                break

   
    report.setdefault("findings", [])
    base_findings = len(report["findings"])
    exposures = data.get("exposures", [])
   
    enrich_exposures_with_llm(llm, exposures)
    report["findings"].extend(exposures)
    weak_findings = []
    for i, w in enumerate(data.get("llm_weaknesses", []), 1):
        weak_findings.append({
            "id":                f"WEAK-{i:03d}",
            "cve_id":            "N/A",
            "title":             (w.get("description", "") or "Debolezza ipotizzata")[:70],
            "severity":          "INFO",
            "cvss_score":        0.0,
            "affected_service":  w.get("service_name", "") or "",
            "description":       w.get("description", ""),
            "exploitation_path": "Ipotesi di debolezza/misconfigurazione suggerita dall'LLM (da verificare)",
            "evidence":          "",
            "remediation":       "Verificare la configurazione del servizio e applicare l'hardening appropriato.",
            "remediation_source":"llm_hypothesis",
            "category":          "weakness",
            "references":        [],
        })
    report["findings"].extend(weak_findings)
    print(f"\n[INFO] Findings aggiuntivi: {len(exposures)} esposizioni (scan) + "
          f"{len(weak_findings)} debolezze LLM (oltre a {base_findings} findings principali)")

    
    stats = compute_findings_stats(report.get("findings", []))
    print(f"\n[INFO] Finding per severity:")
    for sev, count in stats.items():
        if count > 0:
            print(f"  {sev}: {count}")

    #riepilogo LLM vs codice )
    rem_llm  = sum(1 for f in report.get("findings", []) if f.get("remediation_source") == "llm")
    rem_code = sum(1 for f in report.get("findings", []) if f.get("remediation_source") == "code_fallback")
    rec_llm  = sum(1 for r in report.get("recommendations", []) if r.get("source") == "llm")
    rec_code = sum(1 for r in report.get("recommendations", []) if r.get("source") == "code_fallback")
    print(f"\n[INFO] Origine dei consigli (LLM vs codice):")
    print(f"  Report generato da:        {report.get('report_source', 'llm')}")
    print(f"  Remediation finding:       {rem_llm} da LLM, {rem_code} da fallback codice")
    print(f"  Raccomandazioni generali:  {rec_llm} da LLM, {rec_code} da fallback codice")

    #Salva report JSON 
    json_path = os.path.join(output_dir, "final_report.json")
    with open(json_path, "w") as f:
        json.dump({"target_ip": data["target_ip"],
                   "generated_at": datetime.now().isoformat(),
                   "report": report}, f, indent=2)
    print(f"\n[INFO] Report JSON: {json_path}")

    #html
    print("\n[INFO] Generazione output...")
    html_path = os.path.join(output_dir, "pentest_report.html")
    generate_html(report, data, templates_dir, html_path)

    #genera PDF
    pdf_path = os.path.join(output_dir, "pentest_report.pdf")
    generate_pdf(html_path, pdf_path)

    #Riepilogo finale
    print()
    print("=" * 55)
    print("  REPORT GENERATO")
    print("=" * 55)
    print(f"  Target:      {data['target_ip']}")
    print(f"  Rischio:     {report.get('overall_risk_level')} ({report.get('risk_score')}/10)")
    print(f"  Finding:     {len(report.get('findings', []))}")
    print(f"  HTML:        output/pentest_report.html")
    print(f"  PDF:         output/pentest_report.pdf")
    print(f"  JSON:        output/final_report.json")
    print()
    print("  Pipeline completata!")


if __name__ == "__main__":
    main()
