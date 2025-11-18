"""Control flow instruction semantics - handled by execution_engine."""

from ..cpu_state import CPUState
from ..disassembler import Instruction


def execute_control_flow(state: CPUState, insn: Instruction) -> bool:
    """Execute control flow instruction (stub - handled by ExecutionEngine)."""
    return False
