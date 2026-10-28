from core_shared.llm_client import LLMClient

# Inizializziamo il client passando il percorso corretto alla cartella templates
llm = LLMClient(templates_dir="core_shared/templates")

# Simuliamo i dati in arrivo dall'Attack Surface Mapper
dati_scansione = {
    "target_ip": "10.0.0.5",
    "services": [
        {"port": 80, "name": "http", "version": "Apache 2.4.41"},
        {"port": 22, "name": "ssh", "version": "OpenSSH 8.2p1"}
    ]
}

print("1. Renderizzo il prompt con Jinja2...")
prompt_compilato = llm.render_prompt("recon_prompt.j2", dati_scansione)
print("Prompt generato:\n", prompt_compilato)
print("-" * 40)


print("2. Invio richiesta all'LLM...")
risposta = llm.generate(prompt_compilato)
print("Risposta:\n", risposta)