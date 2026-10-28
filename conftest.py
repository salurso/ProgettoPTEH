import sys

import os

import importlib



ROOT = os.path.dirname(os.path.abspath(__file__))



# Aggiungi la root al path

sys.path.insert(0, ROOT)



# Mappa nome-Python → cartella-reale

MODULE_MAP = {

    "attack_executor":          "attack-executor",

    "target_recon_agent":       "target-recon-agent",

    "vuln_hypothesis_generator":"vuln-hypothesis-generator",

    "exploit_plan_designer":    "exploit-plan-designer",

    "reporting_engine":         "reporting-engine",

    "attack_surface_mapper":    "attack-surface-mapper",

}



for python_name, folder_name in MODULE_MAP.items():

    folder_path = os.path.join(ROOT, folder_name)

    if os.path.isdir(folder_path):

        # Aggiungi la cartella al path

        if folder_path not in sys.path:

            sys.path.insert(0, folder_path)

        # Crea un alias: import attack_executor → attack-executor/

        import types

        spec = importlib.util.spec_from_file_location(

            python_name,

            os.path.join(folder_path, "__init__.py")

            if os.path.exists(os.path.join(folder_path, "__init__.py"))

            else None

        )

        # Crea modulo virtuale che punta alla cartella giusta

        mod = types.ModuleType(python_name)

        mod.__path__ = [folder_path]

        mod.__package__ = python_name

        sys.modules[python_name] = mod
