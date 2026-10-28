# LLM Agent-based Autonomous Penetration Testing Framework

Framework autonomo di **penetration testing guidato da Large Language Model (LLM)**, sviluppato per il corso di *Penetration Testing and Ethical Hacking* (A.A. 2025/2026, Università degli Studi di Salerno).

Il sistema automatizza l'intero ciclo di vita di un penetration test — ricognizione, mappatura della superficie d'attacco, generazione di ipotesi di vulnerabilità, pianificazione ed esecuzione degli exploit e reporting — a partire da un singolo input (l'indirizzo del target) e fino a un report finale strutturato.

> **Principio guida: _"l'LLM propone, il codice verifica"._**
> L'LLM fornisce ragionamento e linguaggio naturale; il codice garantisce determinismo, verifica e assenza di falsi positivi nel report finale.

---

## Architettura: pipeline a 6 agenti

| # | Modulo | L'LLM propone | Il codice verifica / garantisce |
|---|--------|---------------|----------------------------------|
| 01 | **Target Reconnaissance Agent** | Strategia e comando di scansione | Whitelist/blocklist dei comandi, esecuzione di `nmap` / `gobuster` |
| 02 | **Attack Surface Mapper** | — | Parsing deterministico dell'XML e grafo `Host → Porta → Servizio → OS` (NetworkX) |
| 03 | **Vulnerability Hypothesis Generator** | CVE candidate per servizio | Verifica su NVD + database curato per versione, deduplica |
| 04 | **Exploit Plan Designer** | Piani d'attacco (playbook) | Validazione tool ammessi e argomenti bloccati, ordinamento, dipendenze |
| 05 | **Attack Executor** | — | Esecuzione via Metasploit RPC, proof-of-access, cleanup |
| 06 | **Reporting Engine** | Executive summary, remediation, raccomandazioni | Tracciabilità di ogni consiglio (LLM vs codice), output HTML/PDF/JSON |

Ogni modulo comunica con il successivo tramite file JSON nella cartella `output/`.

---

## Ambiente di laboratorio

| Ruolo | Sistema |
|-------|---------|
| **Attaccante** | Kali Linux (`192.168.56.5`) — nmap, gobuster, masscan, Metasploit (RPC 55553), Hydra |
| **Target** | Metasploitable 2 (`192.168.56.4`), VM Linux volutamente vulnerabile |
| **Rete** | VirtualBox Host-Only, completamente isolata |
| **LLM** | `qwen` via API Groq (tier gratuito) · verifica CVE via NVD API 2.0 |

---

## Installazione

```bash
git clone https://github.com/salurso/ProgettoPTEH.git
cd ProgettoPTEH

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configurazione

Copia il template e inserisci le tue chiavi (Groq e NVD, entrambe gratuite):

```bash
cp .env.example .env
# poi apri .env e inserisci GROQ_API_KEY e NVD_API_KEY
```

Il file `.env` è ignorato da git e **non va mai committato**.

### Servizio Metasploit RPC

L'Attack Executor si interfaccia a Metasploit via RPC. Avvia il demone prima della pipeline:

```bash
sudo msfrpcd -P msfrpc -S
```

---

## Uso

### Pipeline completa (orchestratore)

```bash
source .venv/bin/activate
./run_pipeline.sh
```

Esegue in sequenza i 6 moduli, calcola le metriche e genera il report.

### Esecuzione modulo per modulo

Ogni agente legge i JSON prodotti dal precedente, quindi va rispettato l'ordine:

```bash
python target-recon-agent/recon.py            # scan → recon_results.json, nmap_scan.xml
python attack-surface-mapper/mapper.py         # XML → attack_graph.json
python vuln-hypothesis-generator/generator.py  # CVE + NVD → vulnerabilities.json
python exploit-plan-designer/designer.py       # → playbooks.json / playbooks.yaml
python attack-executor/executor.py             # Metasploit RPC → execution_results.json
python reporting-engine/reporter.py            # → final_report.json, pentest_report.html/.pdf
python tests/test_metrics.py                   # (opzionale) → metrics.json
```

---

## Risultati (esecuzione di riferimento su Metasploitable 2)

| Metrica | Valore | Significato |
|---------|--------|-------------|
| **Scan Accuracy** | 100% | 23/23 porte identificate, 0 mancate, 0 falsi positivi |
| **CVE Precision** | 50% | CVE confermate / (confermate + ipotesi LLM bocciate) = 4/8 |
| **Precision proposte LLM** | 20% | CVE proposte dall'LLM e confermate su NVD = 1/5 |
| **Exploit Success Rate** | 100% | 2/2 piani eseguiti con esito positivo (accesso root) |
| **Report Quality** | 100% | completezza del report generato |
| **Score complessivo** | **87,5%** | media delle 4 metriche principali |

**4 vulnerabilità confermate** (3 Critical + 1 Low), di cui **2 sfruttate fino a root** (vsftpd `CVE-2011-2523` e Samba `CVE-2007-2447`). La precisione è misurata in modo *onesto*: le ipotesi dell'LLM non confermate da NVD vengono conteggiate, ma non entrano mai nel report finale.

---

## Struttura del repository

```
.
├── target-recon-agent/        # 01 — ricognizione
├── attack-surface-mapper/     # 02 — grafo della superficie d'attacco
├── vuln-hypothesis-generator/ # 03 — ipotesi CVE + verifica NVD/DB curato
├── exploit-plan-designer/     # 04 — generazione playbook
├── attack-executor/           # 05 — esecuzione via Metasploit RPC
├── reporting-engine/          # 06 — report HTML/PDF/JSON
├── core_shared/               # LLM client, templates (Jinja2), schemas, ethics
├── tests/                     # test unitari e calcolo metriche
├── docs/                      # architettura, contratti dei moduli, disclosure
├── run_pipeline.sh            # orchestratore
├── requirements.txt
└── .env.example               # template di configurazione
```

---

## Meccanismi di sicurezza

Trattandosi di uno strumento offensivo autonomo, il framework integra controlli per un'esecuzione sicura e confinata:

- **Whitelist degli strumenti** — solo tool noti e previsti (nmap, hydra, gobuster, netcat, curl, sqlmap, metasploit).
- **Blocklist degli argomenti** — comandi ad alto rischio distruttivo (`rm -rf`, `mkfs`, `dd if=`, fork bomb, …) vengono bloccati.
- **Sandbox e target whitelist** — azioni limitate alla rete autorizzata `192.168.56.0/24`.
- **Autorizzazione esplicita** — il target deve risultare autorizzato prima di qualsiasi azione.
- **Cleanup** — le sessioni aperte vengono chiuse al termine, senza modifiche permanenti all'asset.

---

## ⚠️ Disclaimer etico

Questo progetto ha **finalità esclusivamente didattiche e di ricerca**. È stato sviluppato e testato in un **ambiente di laboratorio isolato** (rete host-only) su una macchina volutamente vulnerabile (Metasploitable 2), di proprietà dell'autore.

L'uso di questo strumento contro sistemi per i quali **non si dispone di autorizzazione esplicita è illegale** e non è in alcun modo autorizzato né supportato. L'autore non è responsabile di usi impropri. Rispettare sempre i principi di *responsible disclosure* (vedi `docs/RESPONSIBLE_DISCLOSURE.md`).

---

## Autore

**Andrea Salurso** — Università degli Studi di Salerno
Corso di *Penetration Testing and Ethical Hacking*, Prof. Arcangelo Castiglione — A.A. 2025/2026
