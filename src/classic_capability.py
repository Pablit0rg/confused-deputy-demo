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
import shutil


class PermissionDeniedError(PermissionError):
    """Raised when a user attempts to create a capability without requisite authority."""
    pass


@dataclass(frozen=True)
class FileCapability:
    """
    An unforgeable capability token representing write access to a specific file.
    
    In a true capability OS, capabilities are held in protected C-lists (Capability Lists)
    managed by the microkernel hardware/OS. Here, we model it as a capability object
    bound to the owner's authority upon creation.
    """
    target_path: Path
    owner_id: str
    read_only: bool = False

    def write_text(self, content: str, executor_id: str) -> None:
        """Write content using the authority designated by this capability."""
        if self.read_only:
            raise PermissionDeniedError(
                f"Capability for '{self.target_path}' is read-only."
            )
        self.target_path.write_text(content, encoding="utf-8")


class CapabilityFactory:
    """
    Simulates the OS Capability Authority / Directory Manager.
    Enforces that users can only receive capabilities for resources they own
    or are explicitly granted access to.
    """

    def __init__(self, system_dir: Path):
        self.system_dir = system_dir
        # System-protected files where only 'sys_admin' has write authority
        self.protected_files = {self.system_dir / "sysx_bill.log"}

    def request_write_capability(self, caller_id: str, relative_or_abs_path: str) -> FileCapability:
        """
        Request a write capability for a given file path on behalf of caller_id.
        """
        target_path = Path(relative_or_abs_path)
        if not target_path.is_absolute():
            target_path = self.system_dir / target_path

        # Check authorization at capability creation time under caller_id's authority
        if target_path in self.protected_files and caller_id != "sys_admin":
            raise PermissionDeniedError(
                f"ACCESS DENIED: User '{caller_id}' lacks authority to acquire "
                f"a write capability for protected system file '{target_path.name}'."
            )

        return FileCapability(target_path=target_path, owner_id=caller_id, read_only=False)


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
        output_cap.write_text(compiled_binary, executor_id=caller_id)

        # 3. Append usage charge using system internal capability
        current_log = self.system_billing_cap.target_path.read_text(encoding="utf-8")
        updated_log = current_log + f"RECORD 003: USER {caller_id} | CPU SEC: 1.0 | FEE: $0.10\n"
        self.system_billing_cap.write_text(updated_log, executor_id="sys_admin")

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
        sandbox_dir = Path("/tmp/confused_deputy_demo/classic_capability")

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

