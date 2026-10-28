#!/bin/bash

# run_pipeline.sh — Esegue l'intera pipeline del framework in un solo comando



set -uo pipefail



PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$PROJECT_DIR"



GREEN='\033[0;32m'

RED='\033[0;31m'

YELLOW='\033[1;33m'

NC='\033[0m'



step() {

    echo -e "\n${YELLOW}════════════════════════════════════════════════════════${NC}"

    echo -e "${YELLOW}  $1${NC}"

    echo -e "${YELLOW}════════════════════════════════════════════════════════${NC}"

}



fail() {

    echo -e "${RED}[ERRORE] $1 — pipeline interrotta.${NC}"

    exit 1

}



mkdir -p logs output



# ── 0. Virtualenv ──────────────────────────────────────────

if [ -f ".venv/bin/activate" ]; then

    source .venv/bin/activate

else

    fail "Virtualenv non trovato in .venv/ — esegui prima: python3 -m venv .venv && pip install -r requirements.txt"

fi



# ── 1. Metasploit RPC ───────────────────────────────────────

step "Verifica Metasploit RPC (porta 55553)"

if ! nc -z 127.0.0.1 55553 2>/dev/null; then

    echo "[INFO] msfrpcd non attivo — avvio in background (potrebbe chiedere la password sudo)..."

    # Senza -f: msfrpcd si demonizza da solo. Al primo avvio carica tutto il
    # framework prima di mettersi in ascolto, quindi attendiamo fino a 40s il bind.
    sudo msfrpcd -P msfrpc -S > logs/msfrpcd.log 2>&1 &

    for i in $(seq 1 40); do
        nc -z 127.0.0.1 55553 2>/dev/null && break
        sleep 1
    done

    if nc -z 127.0.0.1 55553 2>/dev/null; then

        echo -e "${GREEN}[OK] Metasploit RPC avviato.${NC}"

    else

        echo -e "${YELLOW}[WARNING] msfrpcd non raggiungibile — l'Attack Executor userà la modalità mock.${NC}"

    fi

else

    echo -e "${GREEN}[OK] Metasploit RPC già attivo.${NC}"

fi



# ── 2. Pipeline sequenziale ─────────────────────────────────

step "1/6 — Target Reconnaissance Agent"

python target-recon-agent/recon.py || fail "Recon Agent"



step "2/6 — Attack Surface Mapper"

python attack-surface-mapper/mapper.py || fail "Attack Surface Mapper"



step "3/6 — Vulnerability Hypothesis Generator"

python vuln-hypothesis-generator/generator.py || fail "Vulnerability Generator"



step "4/6 — Exploit Plan Designer"

python exploit-plan-designer/designer.py || fail "Exploit Plan Designer"



step "5/6 — Attack Executor"

python attack-executor/executor.py || fail "Attack Executor"



step "6/6 — Reporting Engine"

python reporting-engine/reporter.py || fail "Reporting Engine"



# ── 2b. Calcolo metriche (rigenera output/metrics.json) ─────

step "Calcolo metriche pipeline"

python tests/test_metrics.py || echo -e "${YELLOW}[WARNING] Calcolo metriche non riuscito (output incompleto).${NC}"



# ── 3. Riepilogo finale ──────────────────────────────────────

step "PIPELINE COMPLETATA"

echo -e "${GREEN}Report HTML: output/pentest_report.html${NC}"

echo -e "${GREEN}Report PDF:  output/pentest_report.pdf${NC}"

echo -e "${GREEN}Metriche:    output/metrics.json${NC}"



read -p "Aprire il report nel browser? [s/N] " choice

if [[ "$choice" =~ ^[Ss]$ ]]; then

    xdg-open output/pentest_report.html

fi
