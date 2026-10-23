# Axium Cyber LLC — CyberLab Toolkit

Educational starter toolkit for Windows and Python 3.11+.

## Included
- Password strength heuristic (uses fictional classroom passwords)
- Localhost-only web security-header audit
- Localhost service inventory on a fixed list of ports
- Classroom guide
- JSON report output in `reports/`

## Setup (Windows PowerShell)
```powershell
cd AxiumCyberLab
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py axium_cyberlab.py
```

No third-party packages are required.

If PowerShell blocks virtual-environment activation, you can run the script
directly with `py axium_cyberlab.py`; activation is optional for this project.

## Quick web-header exercise
In a second PowerShell window, navigate to the project folder and run:
```powershell
py -m http.server 8000 --bind 127.0.0.1
```
Then choose option 2 and accept `http://127.0.0.1:8000`.
This basic server is for learning connectivity only, not production use.

## Safety
Use only systems you own or are explicitly authorized to assess. The web
audit and port inventory are restricted to localhost. Do not use real
passwords; the analyzer does not store the entered password.

## Limitations
This is a starter educational tool, not a comprehensive penetration-testing
suite. Password entropy is a rough theoretical estimate, not a crack-time
prediction. Missing headers and open ports require context and are not, by
themselves, proof of vulnerabilities.
