#!/usr/bin/env python3
"""
Confused Deputy Demonstration Suite (Late 1970s - 2026).

Runs all four demonstration modules sequentially:
1. Late 1970s Fortran Compiler Vulnerable Simulation (Home Files License Authority)
2. Late 1970s Capability Mitigation (Explicit File Capabilities)
3. 2026 AI Agent Vulnerable Pipeline (Prompt Injection -> Ambient App Privilege)
4. 2026 Capability Guardrail Mitigation (Deterministic Token Scope Validation)

Usage:
    python3 run_demo.py
"""

from pathlib import Path
import sys

from src.classic_deputy import run_classic_deputy_demo
from src.classic_capability import run_classic_capability_demo
from src.agent_deputy import run_agent_deputy_demo
from src.agent_capability import run_agent_capability_demo


def print_banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {title.upper()}")
    print("=" * 78)


def main() -> None:
    print_banner("Confused Deputy Demonstration Suite")
    print("Reference: Norman Hardy (1988) | Dennis & Van Horn (1966) | OWASP LLM (2025: LLM01, LLM05, LLM06)")

    # ----------------------------------------------------
    # Module 1: Late 1970s Classic Vulnerability
    # ----------------------------------------------------
    print_banner("Module 1: Late 1970s Classic Confused Deputy Vulnerability")
    res_c_vuln = run_classic_deputy_demo()
    print(res_c_vuln.message)
    print(f"\nResult: Billing Log (SYSX)BILL Corrupted? -> {res_c_vuln.billing_file_corrupted}")
    print("\nBilling Log Snippet (Corrupted by Home Files License Ambient Authority):")
    billing_lines = res_c_vuln.billing_log_path.read_text().splitlines()
    for line in billing_lines[:5]:
        print(f"  | {line}")

    # ----------------------------------------------------
    # Module 2: Late 1970s Capability Mitigation
    # ----------------------------------------------------
    print_banner("Module 2: Late 1970s Capability Security Mitigation")
    res_c_mit = run_classic_capability_demo()
    print(f"Attack Blocked by Capability Engine? -> {res_c_mit['attack_blocked']}")
    print(f"Reason: {res_c_mit['attack_message']}")
    print(f"Legitimate Operation Succeeded?     -> {res_c_mit['legitimate_success']}")
    print(f"Billing File (SYSX)BILL Corrupted?  -> {res_c_mit['billing_file_corrupted']}")

    # ----------------------------------------------------
    # Module 3: 2026 AI Agent Vulnerability
    # ----------------------------------------------------
    print_banner("Module 3: 2026 AI Agent Confused Deputy Vulnerability")
    res_a_vuln = run_agent_deputy_demo()
    for log_line in res_a_vuln.logs:
        print(f"  [AGENT LOG] {log_line}")
    print(f"\nResult: Production Database Destroyed? -> {res_a_vuln.target_destroyed}")

    # ----------------------------------------------------
    # Module 4: 2026 AI Agent Capability Mitigation
    # ----------------------------------------------------
    print_banner("Module 4: 2026 AI Agent Capability Guardrail Mitigation")
    res_a_mit = run_agent_capability_demo()
    for log_line in res_a_mit.logs:
        print(f"  [GUARDRAIL LOG] {log_line}")
    print(f"\nAttack Blocked by Deterministic Gate? -> {res_a_mit.attack_blocked}")
    print(f"Flawed LLM Self-Confirmation Bypassed?  -> {res_a_mit.naive_confirmation_bypassed}")
    print(f"Production Database Destroyed?         -> {res_a_mit.target_destroyed}")

    # ----------------------------------------------------
    # Summary Table
    # ----------------------------------------------------
    print_banner("Summary Matrix")
    print(f"{'ERA / SCENARIO':<38} | {'AUTHORITY MODEL':<24} | {'ATTACK RESULT':<12}")
    print("-" * 78)
    print(f"{'1970s Classic Compiler (Vulnerable)':<38} | {'Home Files License':<24} | {'EXPLOITED':<12}")
    print(f"{'1970s Classic Compiler (Mitigated)':<38} | {'File Capability Token':<24} | {'BLOCKED':<12}")
    print(f"{'2026 AI Agent Pipeline (Vulnerable)':<38} | {'Ambient App Authority':<24} | {'EXPLOITED':<12}")
    print(f"{'2026 AI Agent Pipeline (Mitigated)':<38} | {'Scoped Session Token':<24} | {'BLOCKED':<12}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()

