# Contratti I/O dei moduli

## ReconAgent

- Input:  `{ "target": "192.168.1.1", "mode": "passive" }`
- Output: `{ "commands": ["nmap -sS ...", "gobuster ..."] }`

## SurfaceMapper

- Input:  `{ "scan_results": "path/to/scan.xml" }`
- Output: `{ "graph": { "nodes": [...], "edges": [...] } }`

## VulnGenerator

- Input:  `{ "graph": {...} }`
- Output: `{ "vulnerabilities": [{ "cve_id": "...", "severity": "high" }] }`

## ExploitDesigner

- Input:  `{ "vulnerabilities": [...] }`
- Output: `{ "playbook": [{ "step": 1, "tool": "hydra", "args": "..." }] }`

## AttackExecutor

- Input:  `{ "playbook": [...], "target": "..." }`
- Output: `{ "results": [{ "step": 1, "status": "success", "output": "..." }] }`

## ReportingEngine

- Input:  `{ "results": [...], "vulnerabilities": [...] }`
- Output: `{ "report_path": "output/report.html" }`
