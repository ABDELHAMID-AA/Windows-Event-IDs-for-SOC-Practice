# Windows Event IDs for SOC Practice

This subdirectory is where I study and practice the most important Windows security events as a future SOC analyst.  
I'm also using Splunk in my lab to test every event and understand how it looks in real investigations.

---

## 🌐 What’s this repo about?

I created a full Splunk lab (documented in [SPLUNK-LAB-REPORT.md](./SPLUNK-LAB-REPORT.md)) where I collect logs from two Windows endpoints.

---

## 📂 Structure
```
windows-event-ids-soc/
│
├── SPLUNK-LAB-REPORT.md   # How I built the lab (UF + Splunk + Tailscale)
├── README.md               # You are here
│
├── logon-events/           # Authentication events
├── account-management/     # User & group changes
├── powershell/             # PowerShell logging
├── system-process/         # Processes, services & audit logs
├── firewall/               # Firewall events
└── file-share/             # SMB and share access events
```

---
## 🎯 Goal

This subdirectory is basically my journey to truly understand Windows event logs like a SOC analyst — not just definitions, but how they appear inside Splunk.

Here’s what I’m working toward:

- **Master the most important Windows Security Events**
  - Each event gets its own `.md` file with:
    - What the event actually means  
    - Why it's important in a SOC environment  
    - Real attack use-cases  
    - How to detect it in Splunk  
    - SPL queries I created  
    - Screenshots of the results  

- **Master Splunk Search (SPL)**
  - Writing clean, efficient queries  
  - Understanding indexes, sourcetypes, fields  
  - Using eval, stats, where, timecharts, lookups, etc.  

- **Get good at building Splunk Dashboards**
  - Dashboards for:
    - Logon patterns  
    - Account changes  
    - PowerShell activity  
    - Process creation  
    - Firewall activity  
    - File share access  
  - Basically dashboards that show:
    - anomalies  
    - spikes  
    - suspicious actions  
    - admin activity  

- **Understand UF + Deployment Server + Indexer workflow**
  - UF → 9997 → Indexer  
  - DS → 8089 → push configs to UFs  
  - Knowing exactly how logs travel from endpoint → Splunk  

This subdirectory is where I document everything I learn, test, break, and fix — step by step.
