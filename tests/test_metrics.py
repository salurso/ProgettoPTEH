import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# ─────────────────────────────────────────────
# Dati attesi per Metasploitable 2
# (ground truth per il calcolo delle metriche)
# ─────────────────────────────────────────────

# Porte realmente esposte da Metasploitable 2 (default top-1000).
# Prima era un sottoinsieme incompleto: servizi reali come NFS(2049), IRC(6667),
# VNC(5900), ProFTPD(2121), bindshell(1524) venivano contati come "falsi positivi".
EXPECTED_PORTS = {
    21, 22, 23, 25, 53, 80, 111, 139, 445,
    512, 513, 514, 1099, 1524, 2049, 2121,
    3306, 5432, 5900, 6000, 6667, 8009, 8180
}

# CVE note e APPLICABILI PER VERSIONE ai servizi di questa istanza Metasploitable 2
# e rilevabili dalla pipeline (ground truth onesta, allineata alle versioni reali).
# Nota: CVE-2015-3306 (ProFTPd 1.3.5) e CVE-2012-2122 (MySQL 5.1/5.5) NON si applicano
# alle versioni presenti (ProFTPd 1.3.1, MySQL 5.0.51a); distcc (3632) non è nel top-1000.
EXPECTED_CVES = {
    "CVE-2011-2523",   # vsftpd 2.3.4 backdoor
    "CVE-2007-2447",   # Samba 3.0.20 username map script RCE
    "CVE-2010-2075",   # UnrealIRCd 3.2.8.1 backdoor
}

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'output')


def load_json(filename):
    path = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(path):
        print(f"  [SKIP] {filename} non trovato")
        return None
    with open(path) as f:
        return json.load(f)


# ─────────────────────────────────────────────
# METRICA 1 — Scan Accuracy
# ─────────────────────────────────────────────

def metric_scan_accuracy():
    print("\n[METRICA 1] Scan Accuracy")
    recon = load_json("recon_results.json")
    if not recon:
        return 0.0

    # Estrai porte trovate dall'output nmap
    found_ports = set()
    for result in recon.get("results", []):
        output = result.get("output", "")
        for line in output.splitlines():
            if "/tcp" in line and "open" in line:
                try:
                    port = int(line.split("/")[0].strip())
                    found_ports.add(port)
                except ValueError:
                    pass

    if not EXPECTED_PORTS:
        return 0.0

    correct   = found_ports & EXPECTED_PORTS
    missed    = EXPECTED_PORTS - found_ports
    extra     = found_ports - EXPECTED_PORTS
    accuracy  = len(correct) / len(EXPECTED_PORTS) * 100

    print(f"  Porte attese:   {sorted(EXPECTED_PORTS)}")
    print(f"  Porte trovate:  {sorted(found_ports)}")
    print(f"  Corrette:       {sorted(correct)}")
    print(f"  Mancate:        {sorted(missed)}")
    print(f"  False positive: {sorted(extra)}")
    print(f"  → Accuracy:     {accuracy:.1f}%")
    return accuracy


# ─────────────────────────────────────────────
# METRICA 2 — CVE Precision
# ─────────────────────────────────────────────

def metric_cve_precision():
    """
    CVE Precision secondo il PDF: 'rilevanza delle vulnerabilità suggerite rispetto
    ai servizi rilevati'. Si misura quindi la frazione di CVE riportate che sono
    effettivamente pertinenti (confermate NVD o note/applicabili per versione),
    NON l'appartenenza a un piccolo insieme fisso. Il recall sul set atteso è
    riportato come informazione aggiuntiva.
    """
    print("\n[METRICA 2] CVE Precision")
    vulns = load_json("vulnerabilities.json")
    if not vulns:
        return 0.0

    reported   = vulns.get("vulnerabilities", [])
    unverified = vulns.get("unverified_hypotheses", [])
    if not reported and not unverified:
        print("  Nessuna CVE riportata")
        return 0.0

    def is_relevant(v):
        return bool(v.get("relevant")) or bool(v.get("nvd_verified")) \
            or v.get("source") in ("curated_db", "llm+nvd")

    confermate = sum(1 for v in reported if is_relevant(v))

    # PRECISION ONESTA: tiene conto ANCHE delle ipotesi LLM che NON hanno superato
    # la verifica NVD. Denominatore = tutto ciò che la pipeline ha preso in esame
    # (CVE confermate + ipotesi LLM bocciate). Così proporre molte CVE sbagliate
    # ABBASSA la precisione — non è più un 100% gonfiato.
    considerate = confermate + len(unverified)
    precision = (confermate / considerate * 100) if considerate else 0.0

    # Precisione specifica delle PROPOSTE dell'LLM (hit-rate del modello)
    llm_verified = sum(1 for v in reported if v.get("source") == "llm+nvd")
    llm_proposte = llm_verified + len(unverified)
    llm_precision = (llm_verified / llm_proposte * 100) if llm_proposte else 0.0

    found_cves = set(v.get("cve_id") for v in reported)
    hit = found_cves & EXPECTED_CVES
    recall = len(hit) / len(EXPECTED_CVES) * 100 if EXPECTED_CVES else 0.0

    print(f"  CVE confermate:        {confermate}")
    print(f"  Ipotesi LLM bocciate:  {len(unverified)}")
    print(f"  Prese in esame:        {considerate}  (confermate + bocciate)")
    print(f"  Match attese:          {sorted(hit)}")
    print(f"  → Precision:           {precision:.1f}%  (confermate / prese in esame)")
    print(f"  → Precision proposte LLM: {llm_precision:.1f}%  ({llm_verified}/{llm_proposte})")
    print(f"  → Recall:              {recall:.1f}%")
    return precision


# ─────────────────────────────────────────────
# METRICA 3 — Exploit Success Rate
# ─────────────────────────────────────────────

def metric_exploit_success_rate():
    print("\n[METRICA 3] Exploit Success Rate")
    exec_data = load_json("execution_results.json")
    if not exec_data:
        return 0.0

    results = exec_data.get("results", [])
    if not results:
        return 0.0

    # Step di SOLO exploit (metasploit/hydra/sqlmap): è questo il vero
    # "Exploit Success Rate". Le scansioni nmap di recon non contano come exploit.
    exploit_steps = [r for r in results if r.get("phase") == "exploit"]

    total_all = len(results)
    success_all = sum(1 for r in results if r.get("status") == "SUCCESS")
    rate_all = success_all / total_all * 100 if total_all else 0.0

    if exploit_steps:
        total   = len(exploit_steps)
        success = sum(1 for r in exploit_steps if r.get("status") == "SUCCESS")
        rate    = success / total * 100
        print(f"  Step di exploit: {total}")
        print(f"  Exploit riusciti: {success} (sessione aperta / modulo ok)")
        print(f"  → Exploit success rate: {rate:.1f}%")
        print(f"  (Step totali inc. recon: {total_all}, success complessivo: {rate_all:.1f}%)")
        return rate

    has_phase = any("phase" in r for r in results)
    if has_phase:
        # Gli step hanno il tag ma nessuno è di exploit: è stata eseguita solo
        # ricognizione (es. l'exploit MSF è stato bloccato/non disponibile).
        print(f"  [!] Nessuno step di EXPLOIT eseguito (solo ricognizione)")
    else:
        print(f"  [!] Dati senza tag 'phase' (run precedente) — uso il totale")
    print(f"  Step totali (inc. recon): {total_all}")
    print(f"  SUCCESS:      {success_all}")
    print(f"  → Success rate complessivo: {rate_all:.1f}%")
    return rate_all


# ─────────────────────────────────────────────
# METRICA 4 — Report Quality
# ─────────────────────────────────────────────

def metric_report_quality():
    print("\n[METRICA 4] Report Quality")
    report_data = load_json("final_report.json")
    if not report_data:
        return 0.0

    report   = report_data.get("report", {})
    findings = report.get("findings", [])
    score    = 0
    checks   = []

    # Check executive summary presente e non vuoto
    has_summary = bool(report.get("executive_summary", "").strip())
    checks.append(("Executive summary presente", has_summary))

    # Check almeno 1 finding
    has_findings = len(findings) > 0
    checks.append(("Almeno 1 finding", has_findings))

    # Check ogni finding ha severity + remediation. Il CVSS è richiesto SOLO per i
    # finding "rated" (vulnerabilità/CVE): le osservazioni NSE sono INFO e per scelta
    # NON hanno CVSS (sono evidenze grezze del tool, non vulnerabilità quantificate),
    # quindi sono esentate dal requisito CVSS — altrimenti la metrica penalizzerebbe
    # un comportamento voluto.
    def _finding_ok(f):
        if not (f.get("severity") and f.get("remediation")):
            return False
        is_info = (f.get("severity") == "INFO") or (f.get("category") == "nse-observation")
        if is_info:
            return True  # INFO: niente CVSS richiesto
        return f.get("cvss_score") is not None

    findings_complete = all(_finding_ok(f) for f in findings) if findings else False
    checks.append(("Finding completi (severity+[cvss se non INFO]+remediation)", findings_complete))

    # Check overall_risk_level presente
    has_risk = bool(report.get("overall_risk_level"))
    checks.append(("Risk level presente", has_risk))

    # Check raccomandazioni presenti
    has_recs = len(report.get("recommendations", [])) > 0
    checks.append(("Raccomandazioni presenti", has_recs))

    # Check HTML generato
    html_exists = os.path.exists(
        os.path.join(OUTPUT_DIR, "pentest_report.html")
    )
    checks.append(("Report HTML generato", html_exists))

    # Calcola score
    passed = sum(1 for _, ok in checks if ok)
    score  = passed / len(checks) * 100

    for label, ok in checks:
        icon = "✓" if ok else "✗"
        print(f"  {icon} {label}")

    print(f"  → Quality score: {score:.0f}%")
    return score


# ─────────────────────────────────────────────
# MAIN — Esegui tutte le metriche
# ─────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  VALUTAZIONE METRICHE PIPELINE")
    print("=" * 55)

    scan_acc  = metric_scan_accuracy()
    cve_prec  = metric_cve_precision()
    expl_rate = metric_exploit_success_rate()
    rep_qual  = metric_report_quality()

    print("\n" + "=" * 55)
    print("  RIEPILOGO METRICHE")
    print("=" * 55)
    print(f"  Scan Accuracy:       {scan_acc:.1f}%")
    print(f"  CVE Precision:       {cve_prec:.1f}%")
    print(f"  Exploit Success Rate:{expl_rate:.1f}%")
    print(f"  Report Quality:      {rep_qual:.0f}%")

    overall = (scan_acc + cve_prec + expl_rate + rep_qual) / 4
    print(f"\n  Score complessivo:   {overall:.1f}%")

    # Salva metriche in JSON
    metrics_path = os.path.join(OUTPUT_DIR, "metrics.json")
    import json
    with open(metrics_path, "w") as f:
        json.dump({
            "scan_accuracy":        round(scan_acc, 1),
            "cve_precision":        round(cve_prec, 1),
            "exploit_success_rate": round(expl_rate, 1),
            "report_quality":       round(rep_qual, 1),
            "overall_score":        round(overall, 1)
        }, f, indent=2)
    print(f"\n  Metriche salvate in output/metrics.json")


if __name__ == "__main__":
    main()
