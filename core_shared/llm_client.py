import os
import re
import time
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

# Carica le variabili d'ambiente dal file .env
load_dotenv()

class LLMClient:
    def __init__(self, templates_dir="templates"):
        self.provider = os.getenv("LLM_PROVIDER", "groq").lower()
        
        # Configurazione Jinja2 per i prompt
        self.jinja_env = Environment(loader=FileSystemLoader(templates_dir))
        
        # Inizializzazione dei client API
        if self.provider == "groq":
            from groq import Groq
            self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))
            self.model = os.getenv("LLM_MODEL", "qwen/qwen3.8-27b")
        elif self.provider == "mock":
            print("[INFO] Avvio in modalità SIMULATA (Mock).")
        else:
            raise ValueError(f"Provider {self.provider} non supportato.")

    def render_prompt(self, template_name, context: dict) -> str:
        """Renderizza un template Jinja2 con le variabili passate."""
        template = self.jinja_env.get_template(template_name)
        return template.render(context)

    def generate(self, prompt: str, json_mode: bool = False, max_tokens: int = 900) -> str:
        """Invia il prompt all'LLM e restituisce la risposta. 
           Se json_mode=True, forza l'LLM a restituire un JSON valido.
        """
        if self.provider == "groq":
            kwargs = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": max_tokens
            }
            
            # Se richiesto, attiviamo il formato JSON nativo di Groq
            if json_mode:
                kwargs["response_format"] = {"type": "json_object"}

            # RESILIENZA AL RATE LIMIT (429): il tier gratuito Groq limita l'OUTPUT a
            # ~1000 token/minuto (OTPM) CUMULATIVI su tutte le chiamate. La pipeline fa
            # più chiamate LLM di fila (recon, generator, designer, reporting) e nello
            # stesso minuto può superare il limite. Qui, invece di crashare, aspettiamo
            # il tempo che Groq stesso indica ("try again in X.XXs") e ritentiamo.
            max_retries = int(os.getenv("LLM_MAX_RETRIES", "6"))
            for attempt in range(max_retries + 1):
                try:
                    response = self.client.chat.completions.create(**kwargs)
                    return response.choices[0].message.content
                except Exception as e:
                    msg = str(e)
                    is_rate = ("rate_limit" in msg.lower()) or ("429" in msg) \
                              or (getattr(e, "status_code", None) == 429)
                    if not is_rate or attempt == max_retries:
                        raise
                    m = re.search(r"try again in ([0-9.]+)\s*s", msg)
                    wait = (float(m.group(1)) + 1.0) if m else min(2 ** attempt * 2, 30)
                    print(f"  [LLM] Rate limit 429 — attendo {wait:.1f}s e ritento "
                          f"({attempt + 1}/{max_retries})...")
                    time.sleep(wait)

        elif self.provider == "mock":
            return '{"status": "mock_success", "discovered_services": []}'
