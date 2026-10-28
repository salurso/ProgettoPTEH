import sys
import os
import json
import shlex
import ipaddress
import urllib.parse
import subprocess
import asyncio
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Optional

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core_shared.llm_client import LLMClient
from core_shared.ethics import show_disclaimer_and_accept, request_authorization, AuditLog


#analisi preliminare del target

def analyze_target(target: str) -> dict:
    """
    Analizza il target e restituisce info utili.
    Gestisce: IP privati, IP pubblici, domini, URL con autenticazione.
    """
    info = {
        "original": target,
        "resolved": target,
        "type": None,
        "is_private": False,
        "has_auth": False,
        "mode": "passive",
        "warning": None
    }

    
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urllib.parse.urlparse(target)

       
        if parsed.username or parsed.password:
            info["has_auth"] = True
            info["warning"] = (
                "[WARNING] URL contiene credenziali in chiaro. "
                "Le credenziali NON verranno passate ai tool di scansione."
            )
            # Ricostruisce l'URL senza credenziali
            netloc_clean = parsed.hostname
            if parsed.port:
                netloc_clean += f":{parsed.port}"
            cleaned = parsed._replace(netloc=netloc_clean)
            info["resolved"] = urllib.parse.urlunparse(cleaned)
        else:
            info["resolved"] = target

        info["type"] = "url"
        # Estrae l'host puro per i tool che non accettano URL
        info["host"] = parsed.hostname
        info["mode"] = "passive"  # Per URL pubblici partiamo passivi
        return info

    # Caso: IP address
    try:
        ip = ipaddress.ip_address(target)
        info["type"] = "ip"
        info["host"] = target

        if ip.is_private:
            info["is_private"] = True
            info["mode"] = "aggressive"
            info["warning"] = (
                "[WARNING] Target è un IP privato (rete locale). "
                "Modalità aggressiva attivata. "
                "Assicurati di avere autorizzazione a scansionare questo host."
            )
        elif ip.is_loopback:
            info["type"] = "loopback"
            info["warning"] = "[WARNING] Target è localhost (127.0.0.1). Scansione limitata."
        else:
            info["mode"] = "passive"

        return info

    except ValueError:
        pass

    info["type"] = "domain"
    info["host"] = target
    info["mode"] = "passive"
    return info


#disponibilità dei tool

def check_tool_availability() -> dict:
    """
    Verifica che nmap, masscan e gobuster siano installati.
    Restituisce un dict con lo stato di ogni tool.
    """
    tools = ["nmap", "masscan", "gobuster"]
    status = {}

    print("[INFO] Verifica disponibilità tool di sistema...")
    for tool in tools:
        try:
            result = subprocess.run(
                [tool, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Prima riga NON vuota (masscan stampa una riga vuota iniziale)
            all_lines   = (result.stdout or result.stderr or "").splitlines()
            non_empty   = [l for l in all_lines if l.strip()]
            first_line  = non_empty[0] if non_empty else "(versione non disponibile)"
            status[tool] = {"available": True, "version": first_line}
            print(f"  [OK] {tool}: {first_line}")
        except FileNotFoundError:
            status[tool] = {"available": False, "error": "non trovato nel PATH"}
            print(f"  [ERRORE] {tool}: non installato o non nel PATH")
        except subprocess.TimeoutExpired:
            status[tool] = {"available": False, "error": "timeout"}
            print(f"  [ERRORE] {tool}: timeout durante il check")

    return status


def run_nmap(command: str, timeout: int = 120) -> dict:
    """
    Wrapper per nmap. Esegue il comando e restituisce output strutturato.
    Salva SEMPRE anche un file XML in output/nmap_scan.xml per il modulo
    Attack Surface Mapper (indipendentemente dal comando generato dal LLM).
    """
    if "-Pn" not in command.split():
        command += " -Pn"

    # Forza l'OS detection dal comando generato dall'LLM che non include semrpe -A/-O.
    if "-O" not in shlex.split(command) and "-A" not in shlex.split(command):
        command += " -O"


    if "--script" in command:
        if "--script-timeout" not in command:
            command += " --script-timeout 60s"
        if "--host-timeout" not in command:
            command += " --host-timeout 540s"
        timeout = max(timeout, 600)

    xml_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', 'output', 'nmap_scan.xml'
    )
    os.makedirs(os.path.dirname(xml_path), exist_ok=True)

    base_cmd = shlex.split(command) + ["-oX", xml_path]

   
    toks = shlex.split(command)
    needs_root = ("-O" in toks) or ("-A" in toks)
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    cmd_list = (["sudo", "-n"] + base_cmd) if (needs_root and not is_root) else base_cmd

    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        # Fallback: se sudo -n non ha credenziali, riesegue senza root
        if cmd_list[:2] == ["sudo", "-n"] and result.returncode != 0 and \
           ("password" in (result.stderr or "").lower() or "sudo" in (result.stderr or "").lower()):
            print("  [INFO] sudo non disponibile — nmap senza OS detection (no root)")
            result = subprocess.run(base_cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "tool": "nmap",
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
            "command": command,
            "xml_path": xml_path
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "nmap",
            "success": False,
            "output": None,
            "error": f"Timeout dopo {timeout} secondi",
            "command": command
        }
    except Exception as e:
        return {
            "tool": "nmap",
            "success": False,
            "output": None,
            "error": str(e),
            "command": command
        }


def run_masscan(command: str, timeout: int = 60) -> dict:
    """
    Wrapper per masscan. Attenzione: masscan richiede i privilegi di root.
    """
    try:
        result = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "tool": "masscan",
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
            "command": command
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "masscan",
            "success": False,
            "output": None,
            "error": f"Timeout dopo {timeout} secondi",
            "command": command
        }
    except Exception as e:
        return {
            "tool": "masscan",
            "success": False,
            "output": None,
            "error": str(e),
            "command": command
        }


def run_gobuster(command: str, timeout: int = 60) -> dict:
    """
    Wrapper per gobuster.
    """
    try:
        result = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "tool": "gobuster",
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
            "command": command
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "gobuster",
            "success": False,
            "output": None,
            "error": f"Timeout dopo {timeout} secondi",
            "command": command
        }
    except Exception as e:
        return {
            "tool": "gobuster",
            "success": False,
            "output": None,
            "error": str(e),
            "command": command
        }


TOOL_RUNNERS = {
    "nmap": run_nmap,
    "masscan": run_masscan,
    "gobuster": run_gobuster,
}


#parsing strutturato dell'LLM

def parse_llm_response(response_str: str) -> Optional[dict]:
    """
    Parsing della risposta del LLM ed estrae i comandi in modo robusto.
    Gestisce: JSON valido, JSON con testo prima/dopo, JSON malformato.
    """
  
    try:
        return json.loads(response_str)
    except json.JSONDecodeError:
        pass

    
    try:
        start = response_str.index("{")
        end = response_str.rindex("}") + 1
        return json.loads(response_str[start:end])
    except (ValueError, json.JSONDecodeError):
        pass

 
    try:
        if "```json" in response_str:
            start = response_str.index("```json") + 7
            end = response_str.index("```", start)
            return json.loads(response_str[start:end].strip())
    except (ValueError, json.JSONDecodeError):
        pass

    
    print("[ERROR] Impossibile estrarre JSON dalla risposta LLM:")
    print(response_str[:300])
    return None


def validate_commands(parsed: dict, tool_status: dict) -> list:
   
    BLOCKED_PATTERNS = [
        "rm -rf", "mkfs", "dd if=", "> /dev/", "fork", ":(){",
        "--script=exploit", "--script exploit"
    ]

    clean_tools = []
    for item in parsed.get("tools_to_use", []):
        tool_name = item.get("tool", "").lower()
        command = item.get("command", "")

        # ontrolla se il tool è disponibile
        if tool_name in tool_status and not tool_status[tool_name]["available"]:
            print(f"  [SKIP] {tool_name} non disponibile, salto questo step.")
            continue

        #Controlla pattern pericolosi
        blocked = any(p in command for p in BLOCKED_PATTERNS)
        if blocked:
            print(f"  [BLOCKED] Comando bloccato per sicurezza: {command}")
            continue

        clean_tools.append(item)

    return clean_tools

#esecuzione asincrona

async def execute_tools_async(tools: list) -> list:
    """
    Esegue tutti i tool in parallelo usando ThreadPoolExecutor
    (subprocess è bloccante, asyncio da solo non basta).
    """
    loop = asyncio.get_event_loop()
    results = []

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for item in tools:
            tool_name = item.get("tool", "").lower()
            command = item.get("command", "")
            timeout = item.get("timeout_seconds", 60)

            runner = TOOL_RUNNERS.get(tool_name)
            if not runner:
                print(f"  [SKIP] Nessun wrapper per il tool: {tool_name}")
                continue

            print(f"  [START] Avvio {tool_name}: {command}")
            future = loop.run_in_executor(executor, runner, command, timeout)
            futures.append((tool_name, future))

        for tool_name, future in futures:
            try:
                result = await asyncio.wait_for(future, timeout=180)
                results.append(result)
                status = "OK" if result["success"] else "FAIL"
                print(f"  [{status}] {tool_name} completato.")
            except asyncio.TimeoutError:
                print(f"  [TIMEOUT] {tool_name} superato il timeout globale di 180s.")
                results.append({
                    "tool": tool_name,
                    "success": False,
                    "error": "Timeout globale superato",
                    "output": None
                })

    return results


#main

async def main():
    print("=" * 55)
    print("  TARGET RECON AGENT — LLM Pentest Framework")
    print("=" * 55)

    #check tool
    tool_status = check_tool_availability()
    print()

    # Inizializza LLM client
    current_dir = os.path.dirname(os.path.abspath(__file__))
    templates_path = os.path.abspath(
        os.path.join(current_dir, '..', 'core_shared', 'templates')
    )
    llm = LLMClient(templates_dir=templates_path)

    
    target = sys.argv[1] if len(sys.argv) > 1 else os.getenv("PENTEST_TARGET", "192.168.56.4")

   
    if not show_disclaimer_and_accept():
        print("[STOP] Disclaimer non accettato. Uscita.")
        return
    if not request_authorization(target):
        print("[STOP] Autorizzazione negata per il target. Uscita.")
        return
    AuditLog().log("RECON_STARTED", {"target": target})

    #analisi target
    print(f"[INFO] Analisi target: {target}")
    target_info = analyze_target(target)
    print(f"  Tipo:     {target_info['type']}")
    print(f"  Modalità: {target_info['mode']}")
    if target_info.get("warning"):
        print(f"  {target_info['warning']}")
    print()

    #genera il prompt e chiedi all'LLM
    print(f"[INFO] Richiesta strategia di scansione all'LLM...")
    prompt = llm.render_prompt("recon_prompt.j2", {
        "target": target_info["host"] if "host" in target_info else target,
        "mode": target_info["mode"]
    })

    raw_response = llm.generate(prompt, json_mode=True)

    #parsing  della risposta
    parsed = parse_llm_response(raw_response)
    if not parsed:
        print("[FATAL] Impossibile procedere senza una risposta valida dall'LLM.")
        return

    print(f"[SUCCESS] Strategia: {parsed.get('strategy_description', 'N/A')}")
    print()

  
    valid_tools = validate_commands(parsed, tool_status)
    if not valid_tools:
        print("[WARNING] Nessun comando valido da eseguire.")
        return

    print(f"[INFO] Esecuzione di {len(valid_tools)} tool in parallelo...")
    print()

    
    results = await execute_tools_async(valid_tools)

    # Output finale 
    print()
    print("=" * 55)
    print("  RISULTATI SCANSIONE")
    print("=" * 55)
    for r in results:
        print(f"\n[{r['tool'].upper()}]")
        if r["success"]:
          
            print((r["output"] or "").rstrip())
        else:
            print(f"  Errore: {r['error']}")

    #Salva i risultati per SurfaceMapper
    output_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '..', 'output', 'recon_results.json'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "target_info": target_info,
            "strategy": parsed.get("strategy_description"),
            "results": results
        }, f, indent=2)

    print(f"\n[INFO] Risultati salvati in: output/recon_results.json")
    print("[INFO] Pronto per il modulo Attack Surface Mapper.")


if __name__ == "__main__":
    asyncio.run(main())
