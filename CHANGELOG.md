# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-09-20

### Security
- **Object Fabrication & Degenerate Test Proof (Audit Round 4)**: Fixed critical flaw where the Round 3 authority substitution test was degenerate: it called `dataclasses.replace` first, which failed on class type rather than exercising authority substitution, producing an identical error message to the retargeting test. When separated, an attacker could construct an instance via `object.__new__` and populate slots with `object.__setattr__`, including an attacker-chosen write operation pointing to `sysx_bill.log`. Restored time-of-use verification without duck typing: `write_text` validates that `_write_op` was issued by `CapabilityFactory` (carrying `_FACTORY_TOKEN`), and `_bound_write_op` verifies by closure that the executing instance is active in the factory's `WeakSet` registry. Fabricated instances are rejected with `PermissionDeniedError`. Explicit lesson: a test that passes for the wrong reason provides false confidence, and was identified only because two separate regressions displayed identical output.
- **Authority Substitution & Dataclass Retargeting (Audit Round 3)**: Fixed critical vulnerability where the time-of-use check introduced in Round 2 queried the `_factory` field on the capability itself via duck typing. Because `_factory` remained a dataclass field, `dataclasses.replace` could swap both `target_path` and `_factory` in a single call, allowing an attacker to supply a `FakeFactory` whose `is_valid_capability` always returned `True`.
- **Address Reuse in Capability Registry (Audit Round 3)**: Fixed vulnerability where tracking capabilities by numeric `id()` in `CapabilityFactory` allowed CPython memory address reuse after garbage collection to validate unintended objects.
- **Fundamental Capability Redesign (Audit Round 3)**: Eliminated the root cause of the previous bypasses: as long as authority is represented as rewritable data fields on a dataclass, standard library copying APIs (`dataclasses.replace`) can decouple authority from the designated resource. The first two mitigation attempts failed because they treated symptoms while authority remained rewritable data. Redesigned `FileCapability` as a standard class (not a dataclass) with explicit `__slots__`, immutable properties, and disabled copying (`copy.copy`, `copy.deepcopy`, `pickle.dumps` raise `TypeError`). Authority is no longer stored in any field: at issuance, `CapabilityFactory` binds the write operation directly as a private closure (`_write_op`) to the verified canonical target path. Active instances are tracked in `CapabilityFactory` via `weakref.WeakSet` (real object identity) instead of numeric `id()`.
- **Path Traversal & Symlink Following (CWE-22, CWE-59)**: Fixed vulnerability in `classic_capability.CapabilityFactory` where uncanonicalized path comparison against `protected_files` allowed unauthorized callers to obtain write capabilities for protected resources via relative segments (`"x/../sysx_bill.log"`) or symbolic links. All target paths are now canonicalized via `pathlib.Path.resolve()` and verified against `system_dir` via `pathlib.Path.relative_to()` before authorization.
- **Capability Retargeting via `dataclasses.replace` (Audit Round 2)**: Identified vulnerability where `FileCapability` checked authorization only at construction, allowing standard library `dataclasses.replace` to copy valid tokens while swapping `target_path`.
- **Mutable Scope in Frozen Dataclass**: Fixed vulnerability in `agent_capability.AgentSessionCapability` where mutable `set` attributes (`allowed_actions`, `allowed_targets`) in a `@dataclass(frozen=True)` allowed in-place runtime scope expansion via `.add()`. Attributes are now converted to immutable `frozenset` during `__post_init__`.
- **Strict Scope Type Validation**: Fixed `agent_capability.AgentSessionCapability` to reject raw strings (preventing silent unpacking into character sets) and non-string elements in `allowed_actions` and `allowed_targets` with `TypeError` on construction.
- **Fail-Closed Validation (Deny by Default)**: Fixed `agent_capability.DeterministicCapabilityValidator` to reject payloads with missing, `None`, or non-string actions and targets with `CapabilityValidationError` instead of raising unhandled `TypeError` on unhashable types.
- **Direct Capability Forgery**: Restricted `classic_capability.FileCapability` construction to `CapabilityFactory` via a module-private sentinel token (`_FACTORY_TOKEN`), raising `PermissionDeniedError` on direct construction. Documented inherent limitations of Python runtime unforgeability compared to true object-capability systems, explicitly noting `object.__new__` and `object.__setattr__` as constructor bypasses.

### Changed
- Redesigned `FileCapability` from a frozen dataclass to a standard slotted class with bound closure operations.
- Updated `CapabilityFactory` to use `weakref.WeakSet` instead of an `id()` set.
- Updated `agent_capability.DeterministicCapabilityValidator` error messages to use sorted lists for deterministic, reproducible output.
- Removed unused `executor_id` parameter from `FileCapability.write_text` and callers.
- Replaced hardcoded `/tmp` paths with operating-system-derived temp paths via `tempfile.gettempdir()`.
- Updated `agent_deputy.py` vulnerable engine unknown action logging to honestly reflect simulated ambient dispatch rather than claiming execution.
- Removed unused imports across modules (`os` in `classic_deputy`, `sys` in `run_demo`, `typing.Set` in `agent_capability`).
- Added adversarial bypass regression tests in `tests/test_mitigation_bypasses.py` (covering traversal, scope mutation, retargeting via replace, authority substitution via fake factory, copy/pickle rejection, and attribute immutability).
- Added dynamic execution block `Self-audit regressions (v1.1)` in `run_demo.py` covering all four audit regressions.

## [1.0.0] - 2026-08-09

### Added
- Initial release demonstrating the Confused Deputy problem across two eras:
  - Late 1970s Fortran compiler vulnerable to ambient Home Files License (`src/classic_deputy.py`).
  - Late 1970s capability mitigation using explicit file capability tokens (`src/classic_capability.py`).
  - 2026 AI Agent pipeline vulnerable to indirect prompt injection under ambient application authority (`src/agent_deputy.py`).
  - 2026 AI Agent capability mitigation using deterministic guardrail validation (`src/agent_capability.py`).
- Single-command demonstration runner (`run_demo.py`).
- Pytest test suite covering classic and agent scenarios (`tests/test_classic.py`, `tests/test_agent.py`).
- Bilingual documentation in English and Portuguese (`README.md`).
