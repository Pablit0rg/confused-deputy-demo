"""
Classic Confused Deputy Vulnerability Simulation (Late 1970s Tymshare Era).

This module simulates the classic scenario described by Norman Hardy (1988),
based on an incident at Tymshare on a PDP-10 time-sharing system.

Historical Scenario:
- The Fortran compiler executable '(SYSX)FORT' needed to append usage statistics to '(SYSX)STAT'.
- System administrators granted '(SYSX)FORT' a 'home files license', allowing it to write
  to any file in its home directory 'SYSX'.
- The system billing log '(SYSX)BILL' was also located in 'SYSX'. Access to '(SYSX)BILL'
  was a collateral consequence of the broad license scope (Excessive Agency).
- The compiler accepted an optional filename from the caller for OPTIONAL DEBUGGING OUTPUT.
- Exploit: User 'alice' supplied '(SYSX)BILL' as the debug output destination.
- The compiler opened '(SYSX)BILL' using its home files license. It served two masters
  without any mechanism to distinguish caller authority from compiler authority.
"""

from dataclasses import dataclass
from pathlib import Path
import shutil
import tempfile


@dataclass
class CompilationResult:
    success: bool
    output_path: Path
    billing_log_path: Path
    message: str
    billing_file_corrupted: bool


class ClassicVulnerableCompiler:
    """
    Simulates the late 1970s Fortran compiler (SYSX)FORT.
    
    Operates under a 'home files license' over directory SYSX. Writes usage statistics
    to (SYSX)STAT and accepts a user-provided filename for optional debugging output.
    Because it resolves filenames using its home files license, it overwrites (SYSX)BILL
    when requested by an unprivileged user.
    """

    def __init__(self, system_dir: Path):
        self.system_dir = system_dir
        self.billing_log_path = self.system_dir / "sysx_bill.log"  # Represents (SYSX)BILL
        self.stats_log_path = self.system_dir / "sysx_stat.log"    # Represents (SYSX)STAT
        self._initialize_system()

    def _initialize_system(self) -> None:
        """Initialize (SYSX)BILL and (SYSX)STAT with initial system records."""
        self.system_dir.mkdir(parents=True, exist_ok=True)
        initial_billing_data = (
            "[SYSTEM BILLING LOG (SYSX)BILL - CONFIDENTIAL]\n"
            "RECORD 001: USER sys_admin | CPU SEC: 12.4 | FEE: $1.24\n"
            "RECORD 002: USER bob       | CPU SEC:  5.1 | FEE: $0.51\n"
        )
        self.billing_log_path.write_text(initial_billing_data, encoding="utf-8")
        self.stats_log_path.write_text("[SYSX STAT LOG]\n", encoding="utf-8")

    def compile(self, source_code: str, debug_output_filename: str, caller_id: str) -> CompilationResult:
        """
        Compile source code, record usage statistics in (SYSX)STAT, and write
        optional debugging output to debug_output_filename.
        
        VULNERABILITY:
        The compiler opens debug_output_filename using its ambient Home Files License.
        If caller_id='alice' supplies 'sysx_bill.log', the compiler overwrites (SYSX)BILL.
        """
        target_path = Path(debug_output_filename)
        if not target_path.is_absolute():
            target_path = self.system_dir / target_path

        # 1. Generate optional debugging output text
        debug_output_text = (
            f"[DEBUG OUTPUT FROM (SYSX)FORT FOR {caller_id.upper()}]\n"
            f"SOURCE: {source_code}\n"
            f"SYMBOL TABLE: ALICE_SYM_01\n"
        )

        # 2. Write debugging output using Home Files License (Confused Deputy flaw!)
        target_path.write_text(debug_output_text, encoding="utf-8")

        # 3. Append usage stats to (SYSX)STAT hardcoded statistics file
        with open(self.stats_log_path, "a", encoding="utf-8") as f:
            f.write(f"STAT RECORD: USER {caller_id} | FORTRAN COMPILATION RUN\n")

        # Read current billing log to check if it was corrupted
        billing_content = self.billing_log_path.read_text(encoding="utf-8")
        corrupted = "[SYSTEM BILLING LOG (SYSX)BILL - CONFIDENTIAL]" not in billing_content

        msg = (
            f"Compilation completed for '{caller_id}'. Debug output written to '{target_path.name}'.\n"
            f"Authority Check: Home Files License on (SYSX)FORT allowed write access to '{target_path.name}'. "
            f"No OS permissions were violated—the deputy exercised its own ambient authority."
        )

        return CompilationResult(
            success=True,
            output_path=target_path,
            billing_log_path=self.billing_log_path,
            message=msg,
            billing_file_corrupted=corrupted,
        )


def run_classic_deputy_demo(sandbox_dir: Path | None = None) -> CompilationResult:
    """Run the classic confused deputy demonstration."""
    if sandbox_dir is None:
        sandbox_dir = Path(tempfile.gettempdir()) / "confused_deputy_demo" / "classic_vulnerable"
    
    if sandbox_dir.exists():
        shutil.rmtree(sandbox_dir)

    compiler = ClassicVulnerableCompiler(system_dir=sandbox_dir)

    # User Alice requests optional debugging output sent to (SYSX)BILL ('sysx_bill.log')
    malicious_debug_filename = "sysx_bill.log"
    alice_source_code = "PROGRAM ALICE; PRINT *, 'TEST'; END"

    result = compiler.compile(
        source_code=alice_source_code,
        debug_output_filename=malicious_debug_filename,
        caller_id="alice",
    )

    return result


if __name__ == "__main__":
    res = run_classic_deputy_demo()
    print("=== LATE 1970s CLASSIC CONFUSED DEPUTY DEMO ===")
    print(res.message)
    print(f"Billing File (SYSX)BILL Corrupted: {res.billing_file_corrupted}")
    print("\n--- Billing File Contents After Attack ---")
    print(res.billing_log_path.read_text())

