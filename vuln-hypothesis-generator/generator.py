import sys
import os
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core_shared.llm_client import LLMClient
from nvd_client import NVDClient


#parsing risposta LLM 

def parse_llm_hypotheses(raw: str) -> list:
  
    #Restituisce la lista di ipotesi o lista vuota se fallisce.
    
    def try_parse(text):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

   
    parsed = try_parse(raw)
    if parsed:
        return parsed.get("hypotheses", [])

   
    try:
        start = raw.index("{")
        end = raw.rindex("}") + 1
        parsed = try_parse(raw[start:end])
        if parsed:
            return parsed.get("hypotheses", [])
    except ValueError:
        pass

   
    if "```json" in raw:
        try:
            start = raw.index("```json") + 7
            end = raw.index("```", start)
            parsed = try_parse(raw[start:end].strip())
            if parsed:
                return parsed.get("hypotheses", [])
        except ValueError:
            pass

    print("[ERROR] Impossibile estrarre JSON dalla risposta LLM")
    return []


#Validazione CVE contro NVD
import re

def _extract_version(text: str) -> str:
    """Estrae un token di versione (es. '2.3.4') da una stringa, se presente."""
    m = re.search(r'\b\d+(?:\.\d+){1,3}[a-z]?\d*\b', text or "")
    return m.group(0) if m else ""


def validate_hypotheses(hypotheses: list, nvd: NVDClient, discovered_services: list = None):
    
    print("\n[INFO] Validazione CVE in corso...")
    validated = []     
    unverified = []   
    weaknesses = []    
    seen_cves = set()      
    validated_ids = set()  

    #Verifica ogni ipotesi LLM per NOME + VERSIONE
    for h in hypotheses:
        cve_id  = h.get("cve_id", "UNKNOWN")
        service = h.get("service_name", "")
        version = h.get("product_version", "") or _extract_version(h.get("description", ""))

        # Ipotesi SENZA una CVE valida
        if not cve_id or not str(cve_id).upper().startswith("CVE-"):
            h["source"] = "llm_hypothesis"
            h["relevant"] = False
            h["category"] = "weakness"
            weaknesses.append(h)
            continue
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        nvd_results = nvd.search_cves(service, version)
        nvd_match   = next((r for r in nvd_results if r["cve_id"] == cve_id), None)

        if nvd_match:
            h["severity"]      = nvd_match.get("severity", h.get("severity", "UNKNOWN"))
            h["cvss_score"]    = nvd_match.get("cvss_score", h.get("cvss_score", 0.0))
            h["attack_vector"] = nvd_match.get("attack_vector", h.get("attack_vector", "UNKNOWN"))
            h["nvd_verified"]  = True
            h["source"]        = "llm+nvd"
            h["relevant"]      = True
            validated.append(h)
            validated_ids.add(cve_id)
            print(f"  [✓] {cve_id} verificata in NVD — severity: {h['severity']}")
        else:
            h["confidence_score"] = round(h.get("confidence_score", 0.5) * 0.6, 2)
            h["nvd_verified"]     = False
            h["source"]           = "llm_unverified"
            h["relevant"]         = False
            unverified.append(h)
            print(f"  [?] {cve_id} non confermata — ipotesi non verificata (confidence {h['confidence_score']})")

    #CVE note e APPLICABILI PER VERSIONE dal dataset curato.
    if discovered_services and hasattr(nvd, "curated_cves"):
        for svc in discovered_services:
            sname = svc.get("service_name", "")
            sver  = svc.get("product_version", "")
            for cve in nvd.curated_cves(sname, sver):
                cid = cve["cve_id"]
                if cid in validated_ids:
                    continue  
                unverified[:] = [u for u in unverified if u.get("cve_id") != cid]
                validated_ids.add(cid)
                entry = dict(cve)
                entry["service_name"]     = sname
                entry["product_version"]  = sver
                entry["service_port"]     = svc.get("port", 0)
                entry["confidence_score"] = 0.9
                entry["nvd_verified"]     = True
                entry["source"]           = "curated_db"
                entry["relevant"]         = True
                entry["attack_type"]      = "known_exploit"
                validated.append(entry)
                print(f"  [+] {cid} ({sname}) dal DB curato — applicabile a '{sver}'")

 

    print(f"  [=] {len(validated)} CVE confermate/applicabili, {len(unverified)} ipotesi CVE non verificate, "
          f"{len(weaknesses)} debolezze/misconfig ipotizzate dall'LLM")
    return validated, unverified, weaknesses




SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "INFO":     1,
    "UNKNOWN":  0
}

ATTACK_VECTOR_SCORE = {
    "NETWORK":  1.0,   
    "ADJACENT": 0.7,
    "LOCAL":    0.4,
    "PHYSICAL": 0.1,
    "UNKNOWN":  0.3
}

def rank_vulnerabilities(vulnerabilities: list) -> list:
    """
    Ranking multi-criterio:
    - 50% CVSS score (0-10)
    - 30% severity categorica
    - 20% attack_vector (network > local)
    + bonus se nvd_verified e confidence_score alto

    Restituisce la lista ordinata dal più critico al meno critico.
    """
    def compute_score(v: dict) -> float:
        #Pesi normalizzati: lo score massimo possibile è esattamente 10.0
        cvss          = float(v.get("cvss_score", 0.0))
        severity_pts  = SEVERITY_ORDER.get(v.get("severity", "UNKNOWN"), 0)
        vector_mult   = ATTACK_VECTOR_SCORE.get(v.get("attack_vector", "UNKNOWN"), 0.3)
        confidence    = float(v.get("confidence_score", 0.5))
        nvd_bonus     = 0.5 if v.get("nvd_verified", False) else 0.0

        score = (
            (cvss / 10.0) * 5.0          +   
            (severity_pts / 5.0) * 2.0   +   
            vector_mult * 1.5            +  
            confidence * 1.0             +  
            nvd_bonus                        
        )
        return round(min(score, 10.0), 3) 

    for v in vulnerabilities:
        v["risk_score"] = compute_score(v)

    ranked = sorted(vulnerabilities, key=lambda x: x["risk_score"], reverse=True)

   
    for i, v in enumerate(ranked, 1):
        v["rank"] = i

    return ranked


#main 

def main():
    print("=" * 55)
    print("  VULNERABILITY HYPOTHESIS GENERATOR")
    print("=" * 55)

    #Setup client
    current_dir    = os.path.dirname(os.path.abspath(__file__))
    templates_path = os.path.abspath(os.path.join(current_dir, '..', 'core_shared', 'templates'))
    llm = LLMClient(templates_dir=templates_path)
    nvd = NVDClient()

    #dati di input dal grafo di attacco (output del SurfaceMapper) 
    mapper_path = os.path.join(current_dir, '..', 'output', 'attack_graph.json')
    recon_path  = os.path.join(current_dir, '..', 'output', 'recon_results.json')

    target_os = "unknown"   

    if os.path.exists(mapper_path):
        #Carica dal grafo NetworkX prodotto dal Attack Surface Mapper
        import networkx as nx
        from networkx.readwrite import json_graph
        with open(mapper_path) as f:
            graph_data = json.load(f)
        G = json_graph.node_link_graph(graph_data)
        discovered_services = [
            {
                "port":            int(G.nodes[n].get("port", 0)),
                "protocol":        "tcp",
                "service_name":    G.nodes[n].get("service", "unknown"),
                "product_version": G.nodes[n].get("version", "unknown"),
                "cpe":             G.nodes[n].get("cpe", "")
            }
            for n, attr in G.nodes(data=True)
            if attr.get("type") == "service"
        ]
        #OS fingerprinting: recupera il nodo OS dal grafo
        for n, attr in G.nodes(data=True):
            if attr.get("type") == "os":
                target_os = attr.get("os", "unknown")
                break
        target_ip = "192.168.56.4"
        print(f"[INFO] Caricato attack_graph.json dal Surface Mapper — {len(discovered_services)} servizi")

    elif os.path.exists(recon_path):
        #Fallback: legge direttamente da recon_results.json
        with open(recon_path) as f:
            recon_data = json.load(f)
        target_ip = recon_data.get("target_info", {}).get("resolved", "192.168.56.4")
        discovered_services = []
        for r in recon_data.get("results", []):
            output = r.get("output", "")
            for line in output.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    try:
                        port     = int(parts[0].split("/")[0])
                        svc_name = parts[2] if len(parts) > 2 else "unknown"
                        version  = " ".join(parts[3:]) if len(parts) > 3 else "unknown"
                        discovered_services.append({
                            "port": port, "protocol": "tcp",
                            "service_name": svc_name,
                            "product_version": version
                        })
                    except (ValueError, IndexError):
                        pass
        print(f"[INFO] Caricato recon_results.json — {len(discovered_services)} servizi")

    else:
        #Fallback finale: dati di test
        target_ip = "192.168.56.4"
        discovered_services = [
            {"port": 22,  "protocol": "tcp", "service_name": "openssh", "product_version": "OpenSSH 4.7p1"},
            {"port": 21,  "protocol": "tcp", "service_name": "vsftpd",  "product_version": "vsftpd 2.3.4"},
            {"port": 80,  "protocol": "tcp", "service_name": "apache",  "product_version": "Apache 2.2.8"},
            {"port": 3306,"protocol": "tcp", "service_name": "mysql",   "product_version": "MySQL 5.0.51"},
        ]
        print("[INFO] Usando dati di test (nessun file output trovato)")

    input_data = {
        "target_ip":           target_ip,
        "target_os":           target_os,
        "discovered_services": discovered_services
    }

    print(f"\n[INFO] Target: {input_data['target_ip']}")
    print(f"[INFO] Sistema operativo: {input_data['target_os']}")
    print(f"[INFO] Servizi da analizzare: {len(input_data['discovered_services'])}")
    for s in input_data["discovered_services"]:
        print(f"  - {s['port']}/tcp  {s['service_name']}  {s['product_version']}")

    #costruisci prompt e chiedi al LLM
    print("\n[INFO] Generazione ipotesi vulnerabilità con LLM...")
    prompt = llm.render_prompt("vuln_prompt.j2", input_data)

    raw_response = llm.generate(prompt, json_mode=True,
                                max_tokens=int(os.getenv("VULN_MAX_TOKENS", "1000")))

    #parsing strutturato
    hypotheses = parse_llm_hypotheses(raw_response)
    print(f"[INFO] LLM ha generato {len(hypotheses)} ipotesi iniziali")

    if not hypotheses:
        print("[FATAL] Nessuna ipotesi generata. Controlla il prompt o il LLM.")
        return

    #validazione contro NVD + CVE curate per versione
    validated, unverified, llm_weaknesses = validate_hypotheses(
        hypotheses, nvd, input_data["discovered_services"]
    )
    print(f"\n[INFO] Vulnerabilità confermate/applicabili: {len(validated)}")
    print(f"[INFO] Ipotesi CVE LLM non verificate (fuori dal report): {len(unverified)}")

 
    exposures = []
    llm_weaknesses = []

    # ranking
    ranked = rank_vulnerabilities(validated)

    # output finale
    print("\n" + "=" * 55)
    print("  VULNERABILITÀ RANKED (dal più critico)")
    print("=" * 55)
    for v in ranked:
        verified = "✓ NVD" if v.get("nvd_verified") else "? LLM"
        print(
            f"  #{v['rank']:02d} [{v.get('severity','?'):8s}] "
            f"Score:{v.get('risk_score',0):.2f}  "
            f"CVSS:{v.get('cvss_score',0):.1f}  "
            f"{verified}  {v.get('cve_id','?')}"
        )
        print(f"       {v.get('description','')[:80]}")

    # Salva output per il modulo ExploitDesigner
    output_path = os.path.join(current_dir, '..', 'output', 'vulnerabilities.json')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "target_ip":              input_data["target_ip"],
            "target_os":              input_data["target_os"],
            "total_found":            len(ranked),
            "vulnerabilities":        ranked,
            "unverified_hypotheses":  unverified,
            "exposures":              exposures,        # misconfig/esposizioni (scan)
            "llm_weaknesses":         llm_weaknesses    # debolezze ipotizzate dall'LLM
        }, f, indent=2)

    print(f"\n[INFO] Risultati salvati in output/vulnerabilities.json")
    print("[INFO] Pronto per il modulo Exploit Plan Designer.")


if __name__ == "__main__":
    main()
