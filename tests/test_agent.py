"""
Tests for 2026 AI Agent Confused Deputy modules.
"""

from pathlib import Path
import pytest

from src.agent_deputy import run_agent_deputy_demo, VulnerableAgentEngine, SimulatedLLMParser
from src.agent_capability import (
    run_agent_capability_demo,
    MitigatedAgentEngine,
    AgentSessionCapability,
    CapabilityValidationError,
)


def test_vulnerable_agent_attack_succeeds(tmp_path: Path) -> None:
    """
    INTENTIONAL ASSERTION OF VULNERABILITY:
    Verifies that in the vulnerable AI Agent architecture, an indirect prompt injection
    in unstructured user input tricks the LLM into generating a malicious action payload,
    which the execution engine blindly executes under ambient application privileges.
    """
    result = run_agent_deputy_demo(sandbox_dir=tmp_path)

    # Assert that the attack successfully destroyed the production database
    assert result.success is True
    assert result.executed_action == "delete_file"
    assert result.target == "production_database.db"
    assert result.target_destroyed is True


def test_mitigated_agent_attack_blocked(tmp_path: Path) -> None:
    """
    Verifies that under capability-based security, a deterministic guardrail gate
    rejects the malicious action payload before execution, preserving the database.
    """
    result = run_agent_capability_demo(sandbox_dir=tmp_path)

    assert result.success is True
    assert result.attack_blocked is True
    assert "outside granted capability scope" in result.block_reason
    assert result.target_destroyed is False


def test_naive_llm_confirmation_fails(tmp_path: Path) -> None:
    """
    Verifies that naive LLM self-confirmation ("Are you sure?") fails as a security mechanism
    because the prompt injection payload tricks the model during self-confirmation as well.
    """
    result = run_agent_capability_demo(sandbox_dir=tmp_path)
    assert result.naive_confirmation_bypassed is True


def test_mitigated_agent_legitimate_operation(tmp_path: Path) -> None:
    """
    Verifies that authorized actions matching the SessionCapability execute successfully.
    """
    engine = MitigatedAgentEngine(workspace_dir=tmp_path)
    llm = SimulatedLLMParser()
    
    cap = AgentSessionCapability(
        session_id="session_legit_001",
        allowed_actions={"summarize_doc"},
        allowed_targets={"user_notes.txt"},
    )
    
    benign_text = "Please summarize user_notes.txt."
    res = engine.execute_pipeline(user_input_text=benign_text, llm_parser=llm, capability=cap)
    
    assert res.attack_blocked is False
    assert res.target_destroyed is False
