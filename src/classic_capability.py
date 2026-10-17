"""
Classic Capability-Based Security Mitigation (Late 1970s Era).

This module reimplements the Fortran Compiler using Capability-Based Security,
as proposed by Dennis & Van Horn (1966) and Norman Hardy (1988).

Mitigation Principle:
- Eliminate ambient Home Files License authority and path-name resolution inside the service.
- The caller must provide an explicit Capability object (a reference encapsulating
  both object identity and authorized access operations).
- The user can only instantiate a Capability for files where the user possesses
  legitimate authority.
- When 'alice' attempts to reference '(SYSX)BILL' ('sysx_bill.log'), she cannot create a valid
  write capability for that protected file. The request is rejected before reaching
  the compiler.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable
import shutil
import tempfile
import weakref


class PermissionDeniedError(PermissionError):
    """Raised when a user attempts to create a capability without requisite authority."""
    pass


# Module-private token used to mark legitimate factory issuance.
_FACTORY_TOKEN = object()


class FileCapability:
    """
    A capability token representing authorized write access to a specific file.

    In capability-based security (Dennis & Van Horn 1966, Hardy 1988), a capability
    is not an inert data record of permissions evaluated against ambient tables;
    it is the unforgeable reference to the resource operation itself.

    Design details (v1.1.0 Round 3/4 redesign):
    - NOT a dataclass: Eliminates vulnerability to standard library public copying APIs
      (such as `dataclasses.replace`).
    - Explicit `__slots__`: Prevents dynamic attribute injection, modification, or dictionary tampering.
    - Bound execution authority: The capability holds a private, callable write operation
      (`_write_op`) bound directly to the canonical target path and owner at the moment of
      issuance inside `CapabilityFactory`. The capability does not store an external factory reference
      nor does it perform duck-typed delegation to any caller-supplied validator.
    - Time-of-use verification: The bound write operation verifies that the executing capability
      instance remains active in the issuing factory's internal `WeakSet` registry.
    - Immutable properties: `target_path`, `owner_id`, and `read_only` are read-only properties.
      Attribute assignment raises `AttributeError`.
    - Non-copyable and non-serializable: `__copy__`, `__deepcopy__`, and `__reduce__` raise `TypeError`
      to prevent object duplication via standard library serialization or copying tools.
    - Construction restriction: Construction via `__init__` requires the module-private `_FACTORY_TOKEN`
      and a valid bound write operation from `CapabilityFactory`. Direct construction without
      these raises `PermissionDeniedError`.

    What this design prevents:
    - Retargeting via `dataclasses.replace`: `FileCapability` is not a dataclass, raising `TypeError`.
    - Authority substitution: No `_factory` field or duck-typed authority checking exists.
      The write operation is fixed to the canonical path and owner determined at issuance, and
      consults the issuing factory's internal registry at write time.
    - Object duplication via `copy.copy`, `copy.deepcopy`, or `pickle.dumps`: All raise `TypeError`.
    - Direct instantiation via `__init__`: Direct construction without `_FACTORY_TOKEN` raises `PermissionDeniedError`.

    What Python still cannot prevent:
    - In-process memory reflection and interpreter builtins: Any code running in the same Python
      interpreter process can bypass constructors using `object.__new__`, manipulate attributes
      using `object.__setattr__`, inspect closures via `__closure__`, manipulate bytecode, or use
      `ctypes`/`gc` to inspect and modify interpreter state. True unforgeability requires an
      operating system with microkernel capability lists (C-lists) or an object-capability
      programming language.
    """

    __slots__ = ("_target_path", "_owner_id", "_read_only", "_write_op", "__weakref__")

    def __init__(
        self,
        target_path: Path,
        owner_id: str,
        read_only: bool = False,
        *,
        _token: object = None,
        _write_op: Callable[..., None] | None = None,
    ) -> None:
        if _token is not _FACTORY_TOKEN or _write_op is None:
            raise PermissionDeniedError(
                "FORGERY DETECTED: FileCapability instances cannot be constructed directly. "
                "Capabilities must be acquired through CapabilityFactory."
            )
        object.__setattr__(self, "_target_path", target_path)
        object.__setattr__(self, "_owner_id", owner_id)
        object.__setattr__(self, "_read_only", read_only)
        object.__setattr__(self, "_write_op", _write_op)

    @property
    def target_path(self) -> Path:
        return self._target_path

    @property
    def owner_id(self) -> str:
        return self._owner_id

    @property
    def read_only(self) -> bool:
        return self._read_only

    def write_text(self, content: str) -> None:
        """Write content using the authority designated by this capability."""
        if self._read_only:
            raise PermissionDeniedError(
                f"Capability for '{self._target_path}' is read-only."
            )
        # Verify that _write_op is a legitimate factory-bound operation
        if not callable(self._write_op) or getattr(self._write_op, "_token", None) is not _FACTORY_TOKEN:
            raise PermissionDeniedError(
                "FORGERY DETECTED: Capability write operation was not issued by CapabilityFactory."
            )
        self._write_op(self, content)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"FileCapability is immutable; cannot modify attribute '{name}'.")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"FileCapability is immutable; cannot delete attribute '{name}'.")

    def __copy__(self) -> "FileCapability":
        raise TypeError("FileCapability cannot be copied.")

    def __deepcopy__(self, memo: dict) -> "FileCapability":
        raise TypeError("FileCapability cannot be deep-copied.")

    def __reduce__(self) -> None:
        raise TypeError("FileCapability cannot be serialized or pickled.")

    def __repr__(self) -> str:
        return (
            f"FileCapability(target_path={self._target_path!r}, "
            f"owner_id={self._owner_id!r}, read_only={self._read_only!r})"
        )


class CapabilityFactory:
    """
    Simulates the OS Capability Authority / Directory Manager.
    Enforces that users can only receive capabilities for resources they own
    or are explicitly granted access to, and binds write authority directly
    to the issued capability.
    """

    def __init__(self, system_dir: Path):
        self.system_dir = system_dir.resolve()
        # System-protected files where only 'sys_admin' has write authority (canonicalized)
        self.protected_files = {(self.system_dir / "sysx_bill.log").resolve()}
        # WeakSet tracking legitimately issued active capabilities by real object identity
        self._issued_capabilities: weakref.WeakSet[FileCapability] = weakref.WeakSet()

    def is_valid_capability(self, cap: FileCapability) -> bool:
        """
        Verify that the capability was legitimately issued by this factory
        and remains active, tracked by real object identity (WeakSet).
        """
        return cap in self._issued_capabilities

    def request_write_capability(self, caller_id: str, relative_or_abs_path: str) -> FileCapability:
        """
        Request a write capability for a given file path on behalf of caller_id.
        Enforces path canonicalization (CWE-22, CWE-59) and directory containment
        before checking authorization, and binds the write operation directly to
        the canonical path.
        """
        target_path = Path(relative_or_abs_path)
        if not target_path.is_absolute():
            target_path = self.system_dir / target_path

        # Canonicalize path: resolves '..', symlinks, and absolute path
        canonical_target = target_path.resolve()

        # Enforce directory containment: canonical target must be inside system_dir (CWE-22)
        try:
            canonical_target.relative_to(self.system_dir)
        except ValueError:
            raise PermissionDeniedError(
                f"ACCESS DENIED: Path '{relative_or_abs_path}' resolves outside the allowed system directory."
            )

        # Check authorization against canonical protected files (CWE-22, CWE-59)
        if canonical_target in self.protected_files and caller_id != "sys_admin":
            raise PermissionDeniedError(
                f"ACCESS DENIED: User '{caller_id}' lacks authority to acquire "
                f"a write capability for protected system file '{canonical_target.name}'."
            )

        # The write operation is bound to the exact canonical path verified under caller_id's authority.
        # Authority is not a mutable field: it is the callable itself.
        def _bound_write_op(instance: FileCapability, content: str) -> None:
            if not self.is_valid_capability(instance):
                raise PermissionDeniedError(
                    "ACCESS DENIED: Capability is not registered with the issuing factory."
                )
            canonical_target.write_text(content, encoding="utf-8")

        _bound_write_op._token = _FACTORY_TOKEN  # type: ignore[attr-defined]

        cap = FileCapability(
            target_path=canonical_target,
            owner_id=caller_id,
            read_only=False,
            _token=_FACTORY_TOKEN,
            _write_op=_bound_write_op,
        )
        self._issued_capabilities.add(cap)
        return cap


@dataclass
class CapabilityCompilationResult:
    success: bool
    output_path: Path | None
    billing_log_path: Path
    message: str
    billing_file_corrupted: bool


class ClassicCapabilityCompiler:
    """
    Compiler service that relies exclusively on explicit Capabilities.
    
    The compiler does NOT accept path strings or exercise ambient authority.
    It receives an explicit FileCapability for the user's debug output file and
    an internal System FileCapability for logging usage.
    """

    def __init__(self, system_dir: Path, system_billing_cap: FileCapability):
        self.system_dir = system_dir
        self.system_billing_cap = system_billing_cap

    def compile(
        self,
        source_code: str,
        output_cap: FileCapability,
        caller_id: str,
    ) -> CapabilityCompilationResult:
        """
        Compile source code using provided capability references.
        """
        # 1. Compile source code
        compiled_binary = f"[COMPILED BINARY FROM {caller_id.upper()}]\n{source_code.upper()}\n[END BINARY]\n"

        # 2. Write output file USING THE CALLER-PROVIDED CAPABILITY (not ambient authority)
        output_cap.write_text(compiled_binary)

        # 3. Append usage charge using system internal capability
        current_log = self.system_billing_cap.target_path.read_text(encoding="utf-8")
        updated_log = current_log + f"RECORD 003: USER {caller_id} | CPU SEC: 1.0 | FEE: $0.10\n"
        self.system_billing_cap.write_text(updated_log)

        billing_content = self.system_billing_cap.target_path.read_text(encoding="utf-8")
        corrupted = "[SYSTEM BILLING LOG (SYSX)BILL - CONFIDENTIAL]" not in billing_content

        msg = (
            f"Compilation succeeded for '{caller_id}'. Output written via explicit capability to '{output_cap.target_path}'.\n"
            f"Capability Model: Authority was attached to the object reference itself. No path name resolution occurred inside the deputy."
        )

        return CapabilityCompilationResult(
            success=True,
            output_path=output_cap.target_path,
            billing_log_path=self.system_billing_cap.target_path,
            message=msg,
            billing_file_corrupted=corrupted,
        )


def run_classic_capability_demo(sandbox_dir: Path | None = None) -> dict:
    """Run the classic capability mitigation demonstration."""
    if sandbox_dir is None:
        sandbox_dir = Path(tempfile.gettempdir()) / "confused_deputy_demo" / "classic_capability"

    if sandbox_dir.exists():
        shutil.rmtree(sandbox_dir)

    sandbox_dir.mkdir(parents=True, exist_ok=True)
    billing_log = sandbox_dir / "sysx_bill.log"
    billing_log.write_text(
        "[SYSTEM BILLING LOG (SYSX)BILL - CONFIDENTIAL]\n"
        "RECORD 001: USER sys_admin | CPU SEC: 12.4 | FEE: $1.24\n",
        encoding="utf-8",
    )

    cap_factory = CapabilityFactory(system_dir=sandbox_dir)
    sys_billing_cap = cap_factory.request_write_capability("sys_admin", "sysx_bill.log")
    compiler = ClassicCapabilityCompiler(system_dir=sandbox_dir, system_billing_cap=sys_billing_cap)

    results = {}

    # 1. Attack Attempt: Alice tries to acquire capability for '(SYSX)BILL' ('sysx_bill.log')
    try:
        alice_bad_cap = cap_factory.request_write_capability("alice", "sysx_bill.log")
        results["attack_blocked"] = False
        results["attack_message"] = "VULNERABILITY DETECTED: Capability granted inappropriately!"
    except PermissionDeniedError as e:
        results["attack_blocked"] = True
        results["attack_message"] = f"ATTACK BLOCKED: {str(e)}"

    # 2. Legitimate Operation: Alice acquires capability for her own file 'alice_out.bin'
    alice_good_cap = cap_factory.request_write_capability("alice", "alice_out.bin")
    legit_res = compiler.compile(
        source_code="PROGRAM ALICE_VALID; WRITE(*,*) 'OK'; END.",
        output_cap=alice_good_cap,
        caller_id="alice",
    )

    results["legitimate_success"] = legit_res.success
    results["billing_file_corrupted"] = legit_res.billing_file_corrupted
    results["billing_log_content"] = billing_log.read_text(encoding="utf-8")

    return results


if __name__ == "__main__":
    res = run_classic_capability_demo()
    print("=== LATE 1970s CAPABILITY MITIGATION DEMO ===")
    print(f"Attack Blocked: {res['attack_blocked']}")
    print(f"Message: {res['attack_message']}")
    print(f"Legitimate Compilation Success: {res['legitimate_success']}")
    print(f"Billing File Corrupted: {res['billing_file_corrupted']}")
    print("\n--- Protected Billing Log Content ---")
    print(res["billing_log_content"])

