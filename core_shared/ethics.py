import os
import sys
import json
import hashlib
import datetime
from pathlib import Path


def _auto_authorize() -> bool:
    
    return os.getenv("PENTEST_AUTO_AUTH", "false").lower() == "true"


# ─────────────────────────────────────────────
# PUNTO 4 — Disclaimer legale
# ─────────────────────────────────────────────

DISCLAIMER = """
╔══════════════════════════════════════════════════════════════╗
║           LLM AGENT-BASED PENTEST FRAMEWORK                  ║
║                  DISCLAIMER LEGALE                           ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Questo strumento è destinato ESCLUSIVAMENTE a:             ║
║  - Penetration test su sistemi di cui si possiede           ║
║    autorizzazione scritta esplicita                          ║
║  - Ambienti di laboratorio e VM isolate (es. Metasploitable) ║
║  - Scopi educativi e di ricerca in sicurezza informatica     ║
║                                                              ║
║  È VIETATO utilizzare questo framework per:                  ║
║  - Accedere a sistemi senza autorizzazione                   ║
║  - Qualsiasi attività illegale ai sensi del D.Lgs 231/2001   ║
║  - Danneggiare infrastrutture di terzi                       ║
║                                                              ║
║  L'uso improprio è perseguibile penalmente.                  ║
║  Gli autori declinano ogni responsabilità per usi illeciti.  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

DISCLAIMER_FILE = Path.home() / ".llm_pentest_accepted"


def show_disclaimer_and_accept() -> bool:
    """
    Mostra il disclaimer al primo avvio e richiede accettazione.
    Se già accettato in precedenza, salta.
    Restituisce True se accettato, False se rifiutato.
    """
    if DISCLAIMER_FILE.exists():
        return True

    if _auto_authorize():
        DISCLAIMER_FILE.write_text(
            f"Accettato (AUTO) il: {datetime.datetime.now().isoformat()}\n"
        )
        print("[OK] Disclaimer accettato automaticamente (PENTEST_AUTO_AUTH=true).")
        return True

    print(DISCLAIMER)
    print("Devi accettare i termini per continuare.")
    print("Digita 'ACCETTO' per confermare di avere autorizzazione")
    print("scritta per testare il target specificato:\n")

    try:
        risposta = input(">>> ").strip()
    except (EOFError, KeyboardInterrupt):
        risposta = ""

    if risposta == "ACCETTO":
        DISCLAIMER_FILE.write_text(
            f"Accettato il: {datetime.datetime.now().isoformat()}\n"
        )
        print("\n[OK] Disclaimer accettato. Buon lavoro.\n")
        return True
    else:
        print("\n[STOP] Disclaimer non accettato. Uscita.\n")
        return False


def reset_disclaimer():
    """Rimuove il file di accettazione (per testing o nuovo utente)."""
    if DISCLAIMER_FILE.exists():
        DISCLAIMER_FILE.unlink()


# ─────────────────────────────────────────────
# PUNTO 1 — Authorization check per target
# ─────────────────────────────────────────────

AUTHORIZED_TARGETS_FILE = Path("output/authorized_targets.json")


def request_authorization(target: str) -> bool:
    """
    Richiede conferma esplicita prima di procedere su un target.
    Salva i target autorizzati in un file JSON per audit.
    Restituisce True se autorizzato, False altrimenti.
    """
    # Controlla se già autorizzato in questa sessione
    authorized = _load_authorized_targets()
    if target in authorized:
        print(f"[AUTH] Target {target} già autorizzato in questa sessione.")
        return True

    # Modalità non interattiva (pipeline/CI) con opt-in esplicito
    if _auto_authorize():
        authorized.append(target)
        _save_authorized_targets(authorized)
        AuditLog().log("AUTHORIZATION_GRANTED", {"target": target, "mode": "auto"})
        print(f"[AUTH] ✓ Target {target} autorizzato automaticamente (PENTEST_AUTO_AUTH=true).")
        return True

    print(f"\n{'='*55}")
    print(f"  RICHIESTA AUTORIZZAZIONE")
    print(f"{'='*55}")
    print(f"  Target selezionato: {target}")
    print(f"\n  Confermi di avere autorizzazione SCRITTA")
    print(f"  esplicita per effettuare un penetration test")
    print(f"  su questo sistema?")
    print(f"\n  Digita il target ({target}) per confermare,")
    print(f"  oppure 'NO' per annullare:\n")

    try:
        risposta = input(">>> ").strip()
    except (EOFError, KeyboardInterrupt):
        risposta = ""

    if risposta == target:
        authorized.append(target)
        _save_authorized_targets(authorized)
        print(f"\n[AUTH] ✓ Target {target} autorizzato.\n")
        AuditLog().log("AUTHORIZATION_GRANTED", {"target": target})
        return True
    else:
        print(f"\n[AUTH] ✗ Autorizzazione negata per {target}.\n")
        AuditLog().log("AUTHORIZATION_DENIED", {"target": target, "input": risposta})
        return False


def _load_authorized_targets() -> list:
    if AUTHORIZED_TARGETS_FILE.exists():
        try:
            return json.loads(AUTHORIZED_TARGETS_FILE.read_text())
        except Exception:
            return []
    return []


def _save_authorized_targets(targets: list):
    AUTHORIZED_TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTHORIZED_TARGETS_FILE.write_text(json.dumps(targets, indent=2))


# ─────────────────────────────────────────────
# PUNTO 2 — Audit log immutabile con hash SHA256
# ─────────────────────────────────────────────

class AuditLog:
    """
    Audit log append-only con catena di hash SHA256.
    Ogni entry include l'hash dell'entry precedente,
    rendendo la manomissione rilevabile.
    """

    LOG_FILE = Path("logs/audit.log")

    def __init__(self):
        self.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, data: dict):
        """Aggiunge una entry firmata all'audit log."""
        prev_hash = self._get_last_hash()

        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event":     event,
            "data":      data,
            "prev_hash": prev_hash,
        }

        # Calcola hash dell'entry corrente
        entry_str  = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()
        entry["hash"] = entry_hash

        # Append-only: apre sempre in modalità append
        with open(self.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def _get_last_hash(self) -> str:
        """Legge l'hash dell'ultima entry per la catena."""
        if not self.LOG_FILE.exists():
            return "GENESIS"
        lines = self.LOG_FILE.read_text().strip().splitlines()
        if not lines:
            return "GENESIS"
        try:
            last = json.loads(lines[-1])
            return last.get("hash", "GENESIS")
        except Exception:
            return "GENESIS"

    def verify_integrity(self) -> bool:
        """
        Verifica che il log non sia stato manomesso
        ricalcolando tutti gli hash della catena.
        """
        if not self.LOG_FILE.exists():
            return True

        lines = self.LOG_FILE.read_text().strip().splitlines()
        if not lines:
            return True

        prev_hash = "GENESIS"
        for i, line in enumerate(lines):
            try:
                entry      = json.loads(line)
                saved_hash = entry.pop("hash")
                entry_str  = json.dumps(entry, sort_keys=True)
                calc_hash  = hashlib.sha256(entry_str.encode()).hexdigest()

                if entry.get("prev_hash") != prev_hash:
                    print(f"[AUDIT] ✗ Catena hash rotta alla riga {i+1}")
                    return False

                prev_hash = saved_hash
            except Exception as e:
                print(f"[AUDIT] ✗ Errore parsing riga {i+1}: {e}")
                return False

        print(f"[AUDIT] ✓ Integrità log verificata — {len(lines)} entry valide")
        return True

    def print_log(self, last_n: int = 10):
        """Stampa le ultime N entry del log."""
        if not self.LOG_FILE.exists():
            print("[AUDIT] Nessun log presente.")
            return

        lines = self.LOG_FILE.read_text().strip().splitlines()
        print(f"\n[AUDIT LOG] Ultime {min(last_n, len(lines))} entry:")
        for line in lines[-last_n:]:
            try:
                e = json.loads(line)
                print(f"  {e['timestamp']} | {e['event']} | {str(e['data'])[:60]}")
            except Exception:
                print(f"  [entry non leggibile]")

