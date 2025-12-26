# Usage Guide: Vulnscanner

This document explains how to set up and run the vulnscanner tool.  
It is intended as a teaching artifact to demonstrate ethical scanning practices.

---

## ⚙️ Prerequisites
- Python 3.10+ installed
- Virtual environment (`venv`) created and activated
- Dependencies installed from `requirements.txt`:
  ```bash
  pip install -r requirements.txt
 
 
 
 ## 1. Activate Virtual Environment
source .venv/Scripts/activate   # Git Bash / Linux / macOS
.venv\Scripts\activate          # Windows PowerShell / CMD


## 2.Run the Scanner
python -m src.scanner



This will:

Crawl the target site

Fingerprint technologies

Run probes with safe payloads

Apply heuristics to detect signals

Generate reports in reports/ and logs in logs/


