"""
Tests for Classic Confused Deputy modules (Late 1970s Era).
"""

from pathlib import Path
import pytest

from src.classic_deputy import run_classic_deputy_demo, ClassicVulnerableCompiler
from src.classic_capability import (
    run_classic_capability_demo,
    CapabilityFactory,
    ClassicCapabilityCompiler,
    PermissionDeniedError,
)


def test_vulnerable_compiler_attack_succeeds(tmp_path: Path) -> None:
    """
    INTENTIONAL ASSERTION OF VULNERABILITY:
    Verifies that in the vulnerable architecture, an unauthorized user ('alice')
    can trick the compiler into overwriting the system billing log '(SYSX)BILL' ('sysx_bill.log')
    by taking advantage of the compiler's ambient Home Files License authority.
    """
    result = run_classic_deputy_demo(sandbox_dir=tmp_path)
    
    # Assert that the attack successfully corrupted the billing file
    assert result.success is True
    assert result.billing_file_corrupted is True
    
    billing_content = result.billing_log_path.read_text(encoding="utf-8")
    assert "DEBUG OUTPUT FROM (SYSX)FORT FOR ALICE" in billing_content
    assert "[SYSTEM BILLING LOG (SYSX)BILL - CONFIDENTIAL]" not in billing_content


def test_capability_compiler_attack_fails(tmp_path: Path) -> None:
    """
    Verifies that under capability-based security, user 'alice' cannot acquire
    a write capability for '(SYSX)BILL' ('sysx_bill.log'), blocking the confused deputy attack.
    """
    cap_factory = CapabilityFactory(system_dir=tmp_path)
    
    with pytest.raises(PermissionDeniedError) as exc_info:
        cap_factory.request_write_capability(caller_id="alice", relative_or_abs_path="sysx_bill.log")
        
    assert "lacks authority to acquire a write capability" in str(exc_info.value)


def test_capability_compiler_legitimate_operation(tmp_path: Path) -> None:
    """
    Verifies that legitimate user operations function correctly using explicit capabilities.
    """
    res = run_classic_capability_demo(sandbox_dir=tmp_path)
    
    assert res["attack_blocked"] is True
    assert res["legitimate_success"] is True
    assert res["billing_file_corrupted"] is False
    assert "[SYSTEM BILLING LOG (SYSX)BILL - CONFIDENTIAL]" in res["billing_log_content"]

