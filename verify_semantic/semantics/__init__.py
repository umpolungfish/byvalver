"""
Instruction semantics modules.

Each module implements the semantic behavior of a class of x86 instructions.
"""

from .arithmetic import execute_arithmetic
from .logic import execute_logic
from .data_movement import execute_data_movement
from .shift import execute_shift
from .control_flow import execute_control_flow

__all__ = [
    'execute_arithmetic',
    'execute_logic',
    'execute_data_movement',
    'execute_shift',
    'execute_control_flow',
]
