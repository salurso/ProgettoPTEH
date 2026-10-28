# Responsible Disclosure Policy

## Scopo
Questo documento definisce la policy di responsible disclosure
per vulnerabilità scoperte tramite il LLM Pentest Framework.

## Regole fondamentali

### Prima di ogni test
- Ottieni autorizzazione scritta esplicita dal proprietario del sistema
- Definisci chiaramente lo scope del test (IP, porte, servizi inclusi)
- Stabilisci un periodo di tempo concordato per il test
- Firma un accordo di non divulgazione (NDA) se richiesto

### Durante il test
- Non accedere a dati personali o sensibili se non strettamente necessario
- Non interrompere i servizi in produzione
- Documenta ogni azione eseguita con timestamp
- Segnala immediatamente vulnerabilità critiche al cliente

### Dopo il test
- Consegna il report entro i termini concordati
- Dai al cliente almeno 90 giorni per correggere le vulnerabilità
  prima di qualsiasi divulgazione pubblica
- Non pubblicare exploit o PoC senza consenso esplicito
- Segui il processo CVE per vulnerabilità 0-day in software pubblico

## Riferimenti legali
- D.Lgs 231/2001 (Italia) — Responsabilità amministrativa delle imprese
- Computer Fraud and Abuse Act (USA)
- Direttiva NIS2 (Europa)
- GDPR — per dati personali eventualmente esposti

## Contatti per segnalazioni
Per vulnerabilità nel framework stesso, apri una Issue privata
su GitHub usando il tag `security`.
