import sys
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Aggiunge root e ogni cartella-modulo al path
MODULES = [
    "attack-executor",
    "target-recon-agent",
    "vuln-hypothesis-generator",
    "exploit-plan-designer",
    "reporting-engine",
    "core_shared",
]

sys.path.insert(0, ROOT)
for m in MODULES:
    path = os.path.join(ROOT, m)
    if os.path.isdir(path) and path not in sys.path:
        sys.path.insert(0, path)
