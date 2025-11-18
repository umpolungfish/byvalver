"""Shift instruction semantics - handled by execution_engine."""

from ..cpu_state import CPUState
from ..disassembler import Instruction


def execute_shift(state: CPUState, insn: Instruction) -> bool:
    """Execute shift instruction (stub - handled by ExecutionEngine)."""
    return False
