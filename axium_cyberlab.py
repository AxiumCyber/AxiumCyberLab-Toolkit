#!/usr/bin/env python3
"""
AXIUM CYBER LLC | CyberLab Toolkit
Educational security assessment for Windows and Python 3.

Scope: localhost-only web and service checks.
No exploitation, credential attacks, or remote scanning.
"""

import json
import math
import os
import re
import socket
import urllib.error
import urllib.request
from datetime import datetime
from getpass import getpass
from pathlib import Path
from urllib.parse import urlparse

APP_NAME = "AXIUM CYBER LLC | CYBERLAB"
REPORT_DIR = Path("reports")
LAB_PORTS = [3000, 5000, 8000, 8080, 8443, 9000]


def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print("=" * 58)
    print("       AXIUM CYBER LLC | CYBERLAB TOOLKIT")
    print("       EDUCATIONAL SECURITY ASSESSMENT")
    print("=" * 58)
    print("Authorized classroom and local-lab use only.\n")


def save_report(title, findings):
    REPORT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"{title}_{timestamp}.json"
    report = {
        "tool": APP_NAME,
        "created_at": datetime.now().astimezone().isoformat(),
        "assessment": title,
        "findings": findings,
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nReport saved to: {path}")


def password_audit():
    print("\n--- PASSWORD STRENGTH LAB ---")
    print("Enter a fictional classroom password.")
    password = getpass("Password: ")
    if not password:
        print("No password entered.")
        return

    length = len(password)
    categories = {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digits": any(c.isdigit() for c in password),
        "symbols": any(not c.isalnum() for c in password),
    }
    pool = (
        (26 if categories["lowercase"] else 0)
        + (26 if categories["uppercase"] else 0)
        + (10 if categories["digits"] else 0)
        + (33 if categories["symbols"] else 0)
    )
    entropy = length * math.log2(pool) if pool else 0
    findings = {
        "length": length,
        "character_categories": categories,
        "theoretical_entropy_bits": round(entropy, 1),
        "warnings": [],
        "recommendations": [
            "Prefer long, unique passwords or a password manager.",
            "Enable multifactor authentication where available.",
            "Never reuse passwords across services.",
        ],
    }
    if length < 12:
        findings["warnings"].append(
            "Shorter than the recommended 12-character minimum."
        )
    if len(set(password)) <= 3:
        findings["warnings"].append(
            "Very limited variety of distinct characters."
        )
    if re.search(
        r"(password|qwerty|letmein|admin|welcome|123456)",
        password,
        re.IGNORECASE,
    ):
        findings["warnings"].append(
            "Contains a commonly used password pattern."
        )

    print(f"\nLength: {length}")
    print(f"Theoretical entropy estimate: {entropy:.1f} bits")
    print("Character categories:")
    for category, present in categories.items():
        print(f"  {category}: {'Yes' if present else 'No'}")
    print("\nWarnings:")
    if findings["warnings"]:
        for warning in findings["warnings"]:
            print(f"  [!] {warning}")
    else:
        print("  No basic warning patterns detected.")
    print("\nNote: This is a heuristic, not a full password-strength")
    print("model. Entropy estimates can overstate real-world strength.")
    # Password is never saved in the report.
    save_report("password_audit", findings)


def local_web_audit():
    print("\n--- LOCAL WEB SECURITY HEADER AUDIT ---")
    print("Use a local classroom web server, such as localhost:8000.")
    raw_url = input("Local URL [http://127.0.0.1:8000]: ").strip()
    url = raw_url or "http://127.0.0.1:8000"

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        if parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("This classroom version permits localhost only.")
        if parsed.username or parsed.password:
            raise ValueError("Do not include credentials in the URL.")
    except ValueError as exc:
        print(f"Invalid target: {exc}")
        return

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "AxiumCyberLab-Educational-Audit/1.0"},
        method="GET",
    )

    findings = {"target": url, "checks": [], "status": None}

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    try:
        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(request, timeout=4) as response:
            findings["status"] = response.status
            headers = response.headers
    except urllib.error.HTTPError as exc:
        findings["status"] = exc.code
        headers = exc.headers
        if 300 <= exc.code < 400:
            print("Redirect detected; it was not followed.")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"Could not reach local service: {exc}")
        return

    checks = {
        "Content-Security-Policy":
            "Helps restrict content sources and reduce certain injection risks.",
        "X-Content-Type-Options":
            "Helps prevent MIME-type sniffing; commonly set to nosniff.",
        "X-Frame-Options":
            "Can help prevent clickjacking; CSP frame-ancestors is the modern option.",
        "Referrer-Policy":
            "Controls how much referrer information browsers send.",
        "Strict-Transport-Security":
            "Instructs browsers to use HTTPS; meaningful when served over HTTPS.",
    }
    for name, explanation in checks.items():
        value = headers.get(name)
        findings["checks"].append({
            "header": name,
            "present": value is not None,
            "value": value,
            "guidance": explanation,
        })
        print(f"\n{name}: {value if value else 'NOT PRESENT'}")
        if not value:
            print(f"  Guidance: {explanation}")

    print("\nA missing header is a review item, not proof of a vulnerability.")
    save_report("web_header_audit", findings)


def local_port_audit():
    print("\n--- LOCAL SERVICE INVENTORY ---")
    print("Checks predefined ports on this computer only.")
    findings = {"target": "127.0.0.1", "ports": []}
    for port in LAB_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.35)
        try:
            result = sock.connect_ex(("127.0.0.1", port))
            status = "open" if result == 0 else "closed_or_filtered"
        except OSError:
            status = "check_error"
        finally:
            sock.close()
        findings["ports"].append({"port": port, "status": status})
        print(f"127.0.0.1:{port} -> {status}")
    print("\nAn open port is not automatically a vulnerability.")
    save_report("local_service_inventory", findings)


def classroom_guide():
    print("""
--- CLASSROOM LAB GUIDE ---

Exercise 1: Password hygiene
  Analyze fictional passwords and discuss length, uniqueness,
  password managers, MFA, and why entropy estimates have limits.

Exercise 2: HTTP security headers
  Start a local test server or training application.
  Compare its headers against recommended browser protections.

Exercise 3: Service inventory
  Start a local development service and observe its port status.
  Discuss unnecessary services and least-privilege configuration.

Exercise 4: Findings and remediation
  Open the JSON reports in the reports/ folder.
  For each finding, record impact, evidence, severity, and a fix.

Suggested intentionally vulnerable training environment:
  OWASP Juice Shop, run locally using its official documentation.
  Keep vulnerable applications isolated from public networks.

Rules:
  Test only systems you own or have explicit authorization to assess.
  Do not use real passwords in classroom demonstrations.
""")


def main():
    while True:
        banner()
        print("1. Password strength analyzer")
        print("2. Local web security header audit")
        print("3. Local service inventory")
        print("4. Classroom exercises and safety guide")
        print("5. Exit")
        choice = input("\nSelect an option: ").strip()
        if choice == "1":
            password_audit()
        elif choice == "2":
            local_web_audit()
        elif choice == "3":
            local_port_audit()
        elif choice == "4":
            classroom_guide()
        elif choice == "5":
            print("Axium Cyber LLC CyberLab closed.")
            break
        else:
            print("Invalid selection.")
        input("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    main()
