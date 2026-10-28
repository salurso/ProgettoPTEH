# Scenari di Test End-to-End

Target: Metasploitable 2 (192.168.56.101)

## Scenario 1 — FTP Backdoor (vsftpd 2.3.4)
Pipeline completa su CVE-2011-2523
Metrica attesa: scan trova porta 21, LLM suggerisce CVE, executor tenta exploit

## Scenario 2 — Apache Path Traversal
Pipeline completa su CVE-2021-41773
Metrica attesa: porta 80 rilevata, Apache identificato, CVE suggerita

## Scenario 3 — SSH Bruteforce
Pipeline completa su porta 22 OpenSSH
Metrica attesa: porta 22 rilevata, hydra tenta login con wordlist

## Scenario 4 — MySQL senza password
Pipeline completa su porta 3306
Metrica attesa: MySQL rilevato, LLM suggerisce credenziali default

## Scenario 5 — Scansione completa + report
Pipeline completa su tutti i servizi
Metrica attesa: report HTML generato con tutti i finding
