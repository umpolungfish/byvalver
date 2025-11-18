"""Data movement instruction semantics - handled by execution_engine."""

from ..cpu_state import CPUState
from ..disassembler import Instruction


def execute_data_movement(state: CPUState, insn: Instruction) -> bool:
    """Execute data movement instruction (stub - handled by ExecutionEngine)."""
    return False
