# Wiki — LLM Pentest Framework

## Aggiungere un nuovo tool di scanning

1. **Dockerfile** — aggiungi il tool:
```dockerfile
   RUN apt-get install -y nuovo-tool
```
2. **recon.py** — crea il wrapper:
```python
   def run_nuovo_tool(command: str, timeout: int = 60) -> dict:
       try:
           result = subprocess.run(command.split(),
                       capture_output=True, text=True, timeout=timeout)
           return {"tool": "nuovo-tool", "success": result.returncode == 0,
                   "output": result.stdout, "error": result.stderr}
       except subprocess.TimeoutExpired:
           return {"tool": "nuovo-tool", "success": False,
                   "error": f"Timeout dopo {timeout}s"}
```
3. **Aggiungi in TOOL_RUNNERS**:
```python
   TOOL_RUNNERS = {
       "nmap": run_nmap,
       "nuovo-tool": run_nuovo_tool,   # ← aggiungi qui
   }
```
4. **Aggiorna il prompt** `recon_prompt.j2` aggiungendo il tool
   alla lista dei tool disponibili.

---

## Personalizzare i prompt LLM

Tutti i prompt sono in `core_shared/templates/` come file Jinja2.
Variabili disponibili per ogni template:

| Template | Variabili |
|---|---|
| `recon_prompt.j2` | `target`, `mode` |
| `vuln_prompt.j2` | `target_ip`, `discovered_services` |
| `exploit_prompt.j2` | `target_ip`, `vulnerabilities` |
| `report_prompt.j2` | `target_ip`, `date`, `discovered_services`, `vulnerabilities`, `execution_results` |

---

## Cambiare provider LLM

Nel `.env`:
```env
# Groq (gratuito, veloce)
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_...
LLM_MODEL=llama3-70b-8192

# OpenAI
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
LLM_MODEL=gpt-4o

# Anthropic
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
LLM_MODEL=claude-sonnet-4-6
```

---

## Aggiungere un target alla whitelist

Nel `.env`:
```env
TARGET_WHITELIST=192.168.56.0/24,10.10.10.0/24
```

---

## Interpretare le metriche (Punto 8)

### Scan Accuracy
**Cosa misura:** quante porte e servizi il framework riesce
a identificare rispetto al totale realmente presenti.

**Come migliorarla:**
- Aumenta il range di porte nmap (`-p 1-65535` invece di `--top-ports 100`)
- Aggiungi Masscan per la fase iniziale di discovery
- Modifica il prompt recon per essere più aggressivo in modalità `aggressive`

### CVE Precision
**Cosa misura:** quante delle CVE suggerite dall'LLM sono
realmente rilevanti per i servizi trovati.

**Come migliorarla:**
- Inserisci la NVD API key nel `.env` quando il server torna online
- Aggiungi più entry nel dataset `EXPLOITDB_FALLBACK` di `nvd_client.py`
- Fine-tuna il prompt `vuln_prompt.j2` specificando meglio la versione

### Exploit Success Rate
**Cosa misura:** quanti step del playbook vengono eseguiti
con successo (exit code 0).

**Come interpretarla:**
- 0% con tutti step BLOCKED → Safety Validator sta funzionando correttamente
- 0% con step FAILED → tool non installati o target non raggiungibile
- > 50% → pipeline operativa su target vulnerabile

### Report Quality
**Cosa misura:** completezza del report finale.
100% significa che tutti i finding hanno severity, CVSS score,
exploitation path, evidenze e remediation.
