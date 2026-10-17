"""
Adversarial bypass and regression tests for confused-deputy mitigations (v1.1.0).

These tests prove:
1. Classic capability bypasses (path traversal, absolute paths, symlinks, directory escape).
2. Agent capability bypasses (scope mutability, direct forgery, non-string/missing payload handling).
"""

from pathlib import Path
import os
import pytest

from src.classic_capability import (
    CapabilityFactory,
    FileCapability,
    PermissionDeniedError,
)
from src.agent_capability import (
    AgentSessionCapability,
    DeterministicCapabilityValidator,
    CapabilityValidationError,
)


def test_path_traversal_bypass_attempt(tmp_path: Path) -> None:
    """
    BRECHA 1 (CWE-22): Path traversal in classic_capability.CapabilityFactory.
    Alice requests write capability for 'x/../sysx_bill.log'.
    Must be denied with PermissionDeniedError after canonicalization.
    """
    billing_log = tmp_path / "sysx_bill.log"
    billing_log.write_text("CONFIDENTIAL BILLING LOG", encoding="utf-8")

    cap_factory = CapabilityFactory(system_dir=tmp_path)
    with pytest.raises(PermissionDeniedError):
        cap_factory.request_write_capability("alice", "x/../sysx_bill.log")


def test_absolute_path_bypass_attempt(tmp_path: Path) -> None:
    """
    BRECHA 1 (CWE-22): Absolute path resolution bypass.
    When CapabilityFactory is initialized with a non-canonical or relative system_dir,
    or when an unprivileged caller supplies the absolute path to sysx_bill.log,
    it must be canonicalized and denied with PermissionDeniedError.
    """
    billing_log = tmp_path / "sysx_bill.log"
    billing_log.write_text("CONFIDENTIAL BILLING LOG", encoding="utf-8")

    # Use a relative representation of system_dir to reproduce uncanonicalized mismatch
    rel_system_dir = Path(os.path.relpath(tmp_path, Path.cwd()))
    cap_factory = CapabilityFactory(system_dir=rel_system_dir)
    billing_abs = str(billing_log.resolve())

    with pytest.raises(PermissionDeniedError):
        cap_factory.request_write_capability("alice", billing_abs)


def test_symlink_bypass_attempt(tmp_path: Path) -> None:
    """
    BRECHA 1 (CWE-59): Link following bypass.
    An adversary creates an innocent-looking symlink inside the sandbox
    pointing to the protected billing file. Requesting a capability for the
    symlink must be canonicalized and denied with PermissionDeniedError.
    """
    billing_log = tmp_path / "sysx_bill.log"
    billing_log.write_text("CONFIDENTIAL BILLING LOG", encoding="utf-8")

    innocent_link = tmp_path / "innocent.log"
    innocent_link.symlink_to(billing_log)

    cap_factory = CapabilityFactory(system_dir=tmp_path)
    with pytest.raises(PermissionDeniedError):
        cap_factory.request_write_capability("alice", "innocent.log")


def test_directory_escape_attempt(tmp_path: Path) -> None:
    """
    BRECHA 1 (CWE-22): Directory escape.
    Requests for paths that, canonicalized, fall outside the system_dir
    must be denied with PermissionDeniedError.
    """
    cap_factory = CapabilityFactory(system_dir=tmp_path)

    # Relative path escaping system_dir
    with pytest.raises(PermissionDeniedError):
        cap_factory.request_write_capability("alice", "../outside.log")

    # Absolute path escaping system_dir
    outside_abs = str((tmp_path.parent / "outside.log").resolve())
    with pytest.raises(PermissionDeniedError):
        cap_factory.request_write_capability("alice", outside_abs)


def test_agent_capability_immutability() -> None:
    """
    BRECHA 2: Mutable scope in AgentSessionCapability.
    Attempting to add an action or target to an issued AgentSessionCapability must raise an error.
    Constructing the capability passing a common set, list, or tuple must result in immutable fields.
    """
    cap = AgentSessionCapability(
        session_id="session_alice_982",
        allowed_actions={"summarize_doc"},
        allowed_targets={"user_notes.txt"},
    )

    # In v1.0.0, allowed_actions is a mutable set; calling add() mutates runtime scope.
    # In v1.1.0, allowed_actions must be immutable (frozenset), raising AttributeError on add().
    with pytest.raises(AttributeError):
        cap.allowed_actions.add("delete_file")  # type: ignore[attr-defined]

    with pytest.raises(AttributeError):
        cap.allowed_targets.add("production_database.db")  # type: ignore[attr-defined]

    # Passing list or tuple must also be converted to immutable frozenset
    cap_from_list = AgentSessionCapability(
        session_id="session_test_list",
        allowed_actions=["summarize_doc"],  # type: ignore[arg-type]
        allowed_targets=("user_notes.txt",),  # type: ignore[arg-type]
    )
    assert isinstance(cap_from_list.allowed_actions, frozenset)
    assert isinstance(cap_from_list.allowed_targets, frozenset)


def test_agent_capability_rejects_raw_string_and_non_string_items() -> None:
    """
    ACHADO 3: AgentSessionCapability must reject raw strings and non-string items.
    Passing a raw string like 'summarize_doc' must raise TypeError instead of
    silently splitting it into character sets.
    Passing non-string elements (e.g. None, int) inside the iterable must also raise TypeError.
    """
    # Raw string passed to allowed_actions
    with pytest.raises(TypeError) as exc_info1:
        AgentSessionCapability(
            session_id="session_test",
            allowed_actions="summarize_doc",  # type: ignore[arg-type]
        )
    assert "must not be a string" in str(exc_info1.value) or "iterable of strings" in str(exc_info1.value)

    # Raw string passed to allowed_targets
    with pytest.raises(TypeError) as exc_info2:
        AgentSessionCapability(
            session_id="session_test",
            allowed_targets="user_notes.txt",  # type: ignore[arg-type]
        )
    assert "must not be a string" in str(exc_info2.value) or "iterable of strings" in str(exc_info2.value)

    # Non-string item in allowed_actions
    with pytest.raises(TypeError) as exc_info3:
        AgentSessionCapability(
            session_id="session_test",
            allowed_actions={"summarize_doc", 123},  # type: ignore[arg-type]
        )
    assert "strings" in str(exc_info3.value).lower()

    # None item in allowed_targets
    with pytest.raises(TypeError) as exc_info4:
        AgentSessionCapability(
            session_id="session_test",
            allowed_targets={"user_notes.txt", None},  # type: ignore[arg-type]
        )
    assert "strings" in str(exc_info4.value).lower()


def test_file_capability_direct_forgery_fails(tmp_path: Path) -> None:
    """
    Secondary finding: FileCapability direct forgery.
    Instantiating FileCapability directly without passing through CapabilityFactory
    (i.e. without the private factory brand) must fail.
    """
    target = tmp_path / "sysx_bill.log"
    with pytest.raises((TypeError, PermissionDeniedError)):
        FileCapability(target_path=target, owner_id="alice", read_only=False)  # type: ignore[call-arg]


def test_file_capability_retargeting_via_replace_fails(tmp_path: Path) -> None:
    """
    ACHADO 1 (CRÍTICO) & RODADA 5: Capability retargeting via dataclasses.replace.
    Alice legitimately obtains a capability for 'alice_out.bin'.
    Attempting to retarget the capability to 'sysx_bill.log' using the standard library
    dataclasses.replace API fails directly with TypeError because FileCapability is not a dataclass.
    """
    import dataclasses

    cap_factory = CapabilityFactory(system_dir=tmp_path)
    alice_good_cap = cap_factory.request_write_capability("alice", "alice_out.bin")

    with pytest.raises(TypeError) as exc_info:
        dataclasses.replace(alice_good_cap, target_path=tmp_path / "sysx_bill.log")
    assert "dataclass" in str(exc_info.value).lower()


def test_file_capability_fabricated_instance_with_attacker_write_op_fails(tmp_path: Path) -> None:
    """
    RODADA 4 — ACHADO 1: Fabricação por object.__new__ com slots preenchidos e operação de escrita do atacante.
    Contorna o __init__ via object.__new__(FileCapability) e preenche os slots com object.__setattr__,
    incluindo uma operação de escrita escolhida pelo atacante apontando para o arquivo de cobrança.
    A escrita deve ser recusada com PermissionDeniedError no momento do uso.
    """
    billing_log = tmp_path / "sysx_bill.log"
    billing_log.write_text("[SYSTEM BILLING LOG]", encoding="utf-8")

    # Attacker constructs instance bypassing __init__
    evil_cap = object.__new__(FileCapability)
    object.__setattr__(evil_cap, "_target_path", billing_log)
    object.__setattr__(evil_cap, "_owner_id", "alice")
    object.__setattr__(evil_cap, "_read_only", False)
    # Attacker supplies their own write operation targeting the protected billing log
    object.__setattr__(
        evil_cap,
        "_write_op",
        lambda *args, **kwargs: billing_log.write_text("[CORRUPTED BY FABRICATED CAPABILITY]", encoding="utf-8"),
    )

    with pytest.raises(PermissionDeniedError):
        evil_cap.write_text("[ATTEMPTED CORRUPTION]")

    # Ensure the billing log was not corrupted
    assert billing_log.read_text(encoding="utf-8") == "[SYSTEM BILLING LOG]"


def test_file_capability_copy_and_pickle_fail(tmp_path: Path) -> None:
    """
    RODADA 3: copy.copy, copy.deepcopy, and pickle.dumps on FileCapability
    must fail or produce an unusable capability.
    """
    import copy
    import pickle

    cap_factory = CapabilityFactory(system_dir=tmp_path)
    alice_good_cap = cap_factory.request_write_capability("alice", "alice_out.bin")

    with pytest.raises(TypeError):
        copy.copy(alice_good_cap)

    with pytest.raises(TypeError):
        copy.deepcopy(alice_good_cap)

    with pytest.raises(TypeError):
        pickle.dumps(alice_good_cap)


def test_file_capability_attribute_assignment_fails(tmp_path: Path) -> None:
    """
    RODADA 3: Attempting to assign or mutate any attribute on FileCapability must raise AttributeError.
    """
    cap_factory = CapabilityFactory(system_dir=tmp_path)
    alice_good_cap = cap_factory.request_write_capability("alice", "alice_out.bin")

    with pytest.raises(AttributeError):
        alice_good_cap.target_path = tmp_path / "sysx_bill.log"  # type: ignore[misc]

    with pytest.raises(AttributeError):
        alice_good_cap.owner_id = "sys_admin"  # type: ignore[misc]

    with pytest.raises(AttributeError):
        alice_good_cap.arbitrary_attr = "evil"  # type: ignore[attr-defined]


def test_file_capability_legitimate_path_succeeds(tmp_path: Path) -> None:
    """
    RODADA 3: Legitimate operation continues working:
    Alice writes to her own file, and the compiler records billing using the system capability.
    """
    from src.classic_capability import run_classic_capability_demo

    res = run_classic_capability_demo(sandbox_dir=tmp_path)
    assert res["attack_blocked"] is True
    assert res["legitimate_success"] is True
    assert res["billing_file_corrupted"] is False
    assert "[SYSTEM BILLING LOG (SYSX)BILL - CONFIDENTIAL]" in res["billing_log_content"]


@pytest.mark.parametrize(
    "invalid_payload",
    [
        {},  # missing action and target
        {"action": "summarize_doc"},  # missing target
        {"target": "user_notes.txt"},  # missing action
        {"action": None, "target": "user_notes.txt"},  # None action
        {"action": "summarize_doc", "target": None},  # None target
        {"action": 123, "target": "user_notes.txt"},  # non-string action
        {"action": "summarize_doc", "target": ["user_notes.txt"]},  # non-string target
        {"action": ["summarize_doc"], "target": "user_notes.txt"},  # unhashable non-string action
        {"action": {"nested": "action"}, "target": "user_notes.txt"},  # unhashable dict action
    ],
)
def test_validator_denies_invalid_payload_by_default(invalid_payload: dict) -> None:
    """
    Deterministic gate: Deny by default.
    LLM payload with missing, None, or non-string action/target must be rejected
    with CapabilityValidationError (never crash with unhandled TypeError or allow through).
    """
    validator = DeterministicCapabilityValidator()
    cap = AgentSessionCapability(
        session_id="session_test",
        allowed_actions={"summarize_doc"},
        allowed_targets={"user_notes.txt"},
    )
    with pytest.raises(CapabilityValidationError):
        validator.validate_action(invalid_payload, cap)
