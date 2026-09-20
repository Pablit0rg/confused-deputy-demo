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
import tempfile

from src.classic_deputy import run_classic_deputy_demo
from src.classic_capability import (
    run_classic_capability_demo,
    CapabilityFactory,
    FileCapability,
    PermissionDeniedError,
)
from src.agent_deputy import run_agent_deputy_demo
from src.agent_capability import (
    run_agent_capability_demo,
    AgentSessionCapability,
)


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

    # ----------------------------------------------------
    # Self-audit regressions (v1.1)
    # ----------------------------------------------------
    print_banner("Self-audit regressions (v1.1)")

    # Regression 1: Path traversal against Classic CapabilityFactory
    reg_sandbox = Path(tempfile.gettempdir()) / "confused_deputy_demo" / "audit_traversal"
    reg_sandbox.mkdir(parents=True, exist_ok=True)
    (reg_sandbox / "sysx_bill.log").write_text("[SYSTEM BILLING LOG]", encoding="utf-8")
    factory = CapabilityFactory(system_dir=reg_sandbox)
    try:
        factory.request_write_capability("alice", "x/../sysx_bill.log")
        traversal_status = "EXPLOITED"
        traversal_detail = "Capability granted inappropriately for traversed path"
    except PermissionDeniedError as e:
        traversal_status = "BLOCKED"
        traversal_detail = str(e)

    # Regression 2: Scope mutation on AgentSessionCapability
    session_cap = AgentSessionCapability(
        session_id="audit_session_001",
        allowed_actions={"summarize_doc"},
        allowed_targets={"user_notes.txt"},
    )
    try:
        session_cap.allowed_actions.add("delete_file")  # type: ignore[attr-defined]
        mutation_status = "EXPLOITED"
        mutation_detail = "Runtime scope enlarged via set.add()"
    except AttributeError as e:
        mutation_status = "BLOCKED"
        mutation_detail = f"Scope immutable ({type(session_cap.allowed_actions).__name__}): {e}"

    # Regression 3: Capability retargeting via dataclasses.replace
    import dataclasses
    alice_cap = factory.request_write_capability("alice", "alice_out.bin")
    billing_file = reg_sandbox / "sysx_bill.log"
    try:
        retargeted = dataclasses.replace(alice_cap, target_path=billing_file)
        retargeted.write_text("[EXPLOITED RETARGET]")
        replace_status = "EXPLOITED"
        replace_detail = "Capability retargeted to billing log via dataclasses.replace"
    except (TypeError, PermissionDeniedError, AttributeError) as e:
        replace_status = "BLOCKED"
        replace_detail = f"Not a dataclass / retarget rejected ({type(e).__name__}): {e}"

    # Regression 4: Authority substitution via object.__new__ and object.__setattr__
    evil_cap = object.__new__(FileCapability)
    object.__setattr__(evil_cap, "_target_path", billing_file)
    object.__setattr__(evil_cap, "_owner_id", "alice")
    object.__setattr__(evil_cap, "_read_only", False)
    object.__setattr__(
        evil_cap,
        "_write_op",
        lambda *args, **kwargs: billing_file.write_text("[CORRUPTED BY FABRICATED CAPABILITY]", encoding="utf-8"),
    )
    try:
        evil_cap.write_text("[ATTEMPTED CORRUPTION]")
        if billing_file.read_text(encoding="utf-8") != "[SYSTEM BILLING LOG]":
            fake_factory_status = "EXPLOITED"
            fake_factory_detail = "Billing log corrupted via fabricated capability"
        else:
            fake_factory_status = "BLOCKED"
            fake_factory_detail = "Write did not corrupt target"
    except PermissionDeniedError as e:
        fake_factory_status = "BLOCKED"
        fake_factory_detail = f"Fabricated instance rejected at write time: {e}"

    print(f"{'AUDIT REGRESSION':<42} | {'VULNERABILITY / BYPASS':<20} | {'RESULT':<12}")
    print("-" * 78)
    print(f"{'Classic Path Traversal (x/../sysx_bill.log)':<42} | {'CWE-22 / CWE-59':<20} | {traversal_status:<12}")
    print(f"  Detail: {traversal_detail}")
    print(f"{'Agent Scope Mutation (allowed_actions.add)':<42} | {'Mutable Scope':<20} | {mutation_status:<12}")
    print(f"  Detail: {mutation_detail}")
    print(f"{'Capability Retargeting (dataclasses.replace)':<42} | {'Public API Retarget':<20} | {replace_status:<12}")
    print(f"  Detail: {replace_detail}")
    print(f"{'Authority Substitution (object.__new__)':<42} | {'Slot Forgery Bypass':<20} | {fake_factory_status:<12}")
    print(f"  Detail: {fake_factory_detail}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()

