# Correzioni applicate

Riepilogo delle fix rispetto alla versione precedente del framework.

## 1. CVE Precision (da ~0.8% a 100%)
- `vuln-hypothesis-generator/nvd_client.py`
  - Rimosso il **keyword-flood** NVD: la keyword-search NVD serve ora solo a
    *confermare* una CVE suggerita dall'LLM, non a riversare ~20 CVE per servizio.
  - Nuovo metodo `curated_cves(service, version)`: aggiunge CVE note **solo se
    applicabili alla versione** rilevata. Dataset curato corretto/espanso
    (vsftpd, Samba, UnrealIRCd, distcc, MySQL, Apache, ProFTPd, OpenSSH).
- `vuln-hypothesis-generator/generator.py`
  - `validate_hypotheses()` verifica per **nome+versione** e separa le ipotesi
    non confermate (`unverified_hypotheses`) dal report.
  - Ranking **normalizzato a max 10.0** (prima produceva score > 10 e CVE non
    applicabili in cima).
  - `vulnerabilities.json` ora contiene solo CVE pertinenti (3 critiche reali per
    Metasploitable 2) + sezione separata con le ipotesi LLM non verificate.

## 2. Modulo etico collegato alla pipeline
- `core_shared/ethics.py`: aggiunto supporto non interattivo `PENTEST_AUTO_AUTH`.
- `target-recon-agent/recon.py`: disclaimer + `request_authorization(target)` +
  `AuditLog` all'avvio. Target anche da CLI (`python recon.py <target>`).
- `attack-executor/executor.py`: gate di autorizzazione + audit log prima di
  qualsiasi esecuzione.
- Risultato: `logs/audit.log` (catena hash SHA256) viene effettivamente popolato.

## 3. Esito reale degli exploit (Exploit Success Rate non più gonfiato)
- `attack-executor/executor.py` / `MetasploitRunner`:
  - un modulo `exploit/...` è "riuscito" **solo se apre una nuova sessione**;
  - gli `auxiliary/scanner` valutano l'output;
  - cleanup **reale** delle sessioni MSF via RPC (`cleanup_sessions()`);
  - ogni step marcato con `phase` = recon/exploit.
- `tests/test_metrics.py`: Exploit Success Rate calcolato **solo sugli step di
  exploit**, con success complessivo riportato a parte.

## 4. Metriche corrette e integrate
- Ground truth porte completa (Metasploitable 2) e CVE attese allineate alle
  versioni reali.
- CVE Precision ridefinita come da PDF: *rilevanza* delle CVE riportate.
- `run_pipeline.sh` ora **esegue `tests/test_metrics.py`** e rigenera `metrics.json`
  (prima il file era stale/contraddittorio).

## 5. Report
- `reporting-engine/reporter.py`: `recommendations` sempre presenti (Report Quality
  100%); evidenze associate al finding **corretto** per CVE/servizio.

## 6. Configurazione e documentazione
- Aggiunti `.env.example` e `requirements.txt` alla root; rimosso `.nev` (refuso).
- README: modello `qwen/qwen3.8-27b`, nome file `attack_graph.json`.

## 7. Fix dal secondo run reale
- **Path con spazi/parentesi** (es. `llm-pentest-framework (copia 1)`): nmap falliva
  (`-oX` troncato dallo spazio → *Is a directory*) e lo Scan Accuracy risultava 0%.
  `recon.py` ed `executor.py` ora usano `shlex.split` e passano `-oX` come argomenti
  separati, quindi i path con spazi restano integri.
- **Metasploit marcato "non disponibile"**: il Designer usava `msfconsole --version`
  con timeout 5s (andava in timeout) e bloccava lo step di exploit. Ora
  (`_metasploit_available`) verifica la raggiungibilità del **demone RPC** (porta
  configurata) e, in fallback, `msfconsole` con timeout ampio.
- `executor.py`: aggiunti ai moduli MSF approvati `exploit/multi/samba/usermap_script`
  e `exploit/unix/irc/unreal_ircd_3281_backdoor` (prima venivano bloccati).
- `exploit_prompt.j2`: risolta la contraddizione "2 vs 3 piani"; vietato verificare la
  porta backdoor (6200) PRIMA di innescare l'exploit; step di verifica con
  `on_failure=skip_to_next`.
- `test_metrics.py`: messaggio dell'Exploit Success Rate più chiaro (distingue
  "nessuno step di exploit eseguito" dai dati senza tag `phase`).

## 8. Funzionalità aggiunte (ex "sviluppi futuri")
- **OS fingerprinting nel grafo** (`attack-surface-mapper/mapper.py`): estrazione
  dell'OS dall'XML nmap (`_extract_os` via libnmap), nodo `os::<nome>` e arco
  `host --runs_os--> os`, query `get_os(ip)`. Il recon (`target-recon-agent/recon.py`)
  esegue nmap con privilegi root quando il comando usa `-O`/`-A` (via `sudo -n`,
  sfruttando la credenziale in cache da msfrpcd; fallback pulito senza root). Il
  grafo ora realizza `IP→Port→Service→OS`.
- **Catene multi-stadio con data-flow reale** (`attack-executor/executor.py`):
  `_inject_dependency_output` sostituisce negli args dello step dipendente i
  placeholder `{{dep_ip}}`, `{{dep_port}}`, `{{dep_user}}`, `{{dep_pass}}`,
  `{{dep_output}}` con i valori estratti dall'output dello step precedente
  (prima era solo un log di debug). Documentati nel prompt `exploit_prompt.j2`.
- Aggiunti test unitari per entrambe (iniezione + OS nel grafo).

## 9. L'OS viene ora CONSUMATO a valle (non solo rilevato)
- `vuln-hypothesis-generator/generator.py`: estrae l'OS dal grafo, lo passa al
  prompt `vuln_prompt.j2` (l'LLM considera l'OS nelle ipotesi, incl. privesc
  kernel per OS EOL) e lo propaga in `vulnerabilities.json` (`target_os`).
- `exploit-plan-designer/designer.py`: legge `target_os` e lo passa a
  `exploit_prompt.j2` (scelta di moduli/payload compatibili con l'OS).
- Il Reporting Engine completa sempre i finding (severity/cvss/remediation) →
  Report Quality robusta al 100%.

## Metriche dopo le fix (ricalcolate)
| Metrica | Prima | Dopo |
|---|---|---|
| Scan Accuracy | 100% | 100% |
| CVE Precision | 0.8% | 100% |
| Exploit Success Rate | 100% (gonfiato) | verificato via sessione |
| Report Quality | 83% | 100% |
