# LLM Agent-based Autonomous Penetration Testing Framework

## Moduli di Sistema e Dipendenze

1. **Target Reconnaissance Agent**
   - Scopo: Pianifica dinamicamente le strategie di scansione usando il ragionamento LLM.
   - Dipendenze: core-shared (LLM Client), strumenti di rete (Nmap, Masscan).

2. **Attack Surface Mapper**
   - Scopo: Analizza i risultati grezzi delle scansioni e costruisce grafi di attacco strutturati (IP -> Porta -> Servizio -> OS).
   - Dipendenze: Parser XML (es. libnmap), librerie per grafi (NetworkX).

3. **Vulnerability Hypothesis Generator**
   - Scopo: Predice le probabili vulnerabilità (CVE) in base ai servizi rilevati.
   - Dipendenze: core-shared (LLM Client), database CVE (NVD API o locali).

4. **Exploit Plan Designer**
   - Scopo: Progetta catene di exploit multi-stadio creando un playbook strutturato.
   - **Dipendenze: core-shared (LLM Client).

5. **Attack Executor**
   - Scopo: Esegue in modo sicuro le azioni pianificate (sandbox/ambiente controllato).
   - Dipendenze: Metasploit RPC, pwntools, subprocess.

6. **Reporting Engine**
   - Scopo: Genera un report leggibile e strutturato con i risultati.
   - Dipendenze: core-shared (LLM Client), Motore di template (Jinja2).


## Diagramma dei Flussi Dati
```mermaid
graph TD
    User([Utente]) -->|Input Target IP/Domain| Recon(Target Recon Agent)
    Recon -->|Raw Scan Data| Mapper(Attack Surface Mapper)
    
    Mapper -->|JSON: Discovered Services| VulnGen(Vulnerability Hypothesis Generator)
    
    VulnGen -->|JSON: Identified CVEs| Report(Reporting Engine)
    
    Report -->|Generates PDF/HTML| User
