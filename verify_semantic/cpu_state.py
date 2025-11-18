"""
CPU state representation for symbolic execution.

Tracks registers, flags, memory, and stack state during shellcode execution.
"""

from typing import Dict, List, Optional, Any
from enum import Enum


class RegisterName(Enum):
    """x86 register names."""
    # 32-bit general purpose
    EAX = "eax"
    EBX = "ebx"
    ECX = "ecx"
    EDX = "edx"
    ESI = "esi"
    EDI = "edi"
    EBP = "ebp"
    ESP = "esp"

    # 16-bit
    AX = "ax"
    BX = "bx"
    CX = "cx"
    DX = "dx"
    SI = "si"
    DI = "di"
    BP = "bp"
    SP = "sp"

    # 8-bit
    AL = "al"
    AH = "ah"
    BL = "bl"
    BH = "bh"
    CL = "cl"
    CH = "ch"
    DL = "dl"
    DH = "dh"


class FlagName(Enum):
    """x86 CPU flags."""
    CF = "cf"  # Carry flag
    PF = "pf"  # Parity flag
    AF = "af"  # Auxiliary carry flag
    ZF = "zf"  # Zero flag
    SF = "sf"  # Sign flag
    OF = "of"  # Overflow flag
    DF = "df"  # Direction flag


class CPUState:
    """
    Represents the state of x86 CPU during execution.

    Tracks:
    - General purpose registers (32-bit view, sub-registers are aliases)
    - CPU flags
    - Memory (sparse representation)
    - Stack
    - Instruction pointer
    """

    def __init__(self):
        # 32-bit registers (canonical storage)
        self.registers: Dict[str, int] = {
            "eax": 0,
            "ebx": 0,
            "ecx": 0,
            "edx": 0,
            "esi": 0,
            "edi": 0,
            "ebp": 0,
            "esp": 0x7fff0000,  # Stack starts high
        }

        # CPU flags
        self.flags: Dict[str, bool] = {
            "cf": False,
            "pf": False,
            "af": False,
            "zf": False,
            "sf": False,
            "of": False,
            "df": False,
        }

        # Memory: address -> value (sparse)
        self.memory: Dict[int, int] = {}

        # Stack (for easier PUSH/POP tracking)
        self.stack: List[int] = []

        # Instruction pointer
        self.eip: int = 0

        # Memory writes log (for comparison)
        self.memory_writes: List[tuple[int, int]] = []

    def get_register(self, name: str) -> int:
        """Get register value by name (handles sub-registers)."""
        name = name.lower()

        # 32-bit registers
        if name in self.registers:
            return self.registers[name]

        # 16-bit registers (low word)
        if name in ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"]:
            full_name = "e" + name
            return self.registers[full_name] & 0xFFFF

        # 8-bit low registers
        if name in ["al", "bl", "cl", "dl"]:
            full_name = "e" + name[0] + "x"
            return self.registers[full_name] & 0xFF

        # 8-bit high registers
        if name in ["ah", "bh", "ch", "dh"]:
            full_name = "e" + name[0] + "x"
            return (self.registers[full_name] >> 8) & 0xFF

        raise ValueError(f"Unknown register: {name}")

    def set_register(self, name: str, value: int):
        """Set register value by name (handles sub-registers)."""
        name = name.lower()
        value = value & 0xFFFFFFFF  # Ensure 32-bit

        # 32-bit registers
        if name in self.registers:
            self.registers[name] = value
            return

        # 16-bit registers (update low word, preserve high word)
        if name in ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"]:
            full_name = "e" + name
            old_value = self.registers[full_name]
            new_value = (old_value & 0xFFFF0000) | (value & 0xFFFF)
            self.registers[full_name] = new_value
            return

        # 8-bit low registers
        if name in ["al", "bl", "cl", "dl"]:
            full_name = "e" + name[0] + "x"
            old_value = self.registers[full_name]
            new_value = (old_value & 0xFFFFFF00) | (value & 0xFF)
            self.registers[full_name] = new_value
            return

        # 8-bit high registers
        if name in ["ah", "bh", "ch", "dh"]:
            full_name = "e" + name[0] + "x"
            old_value = self.registers[full_name]
            new_value = (old_value & 0xFFFF00FF) | ((value & 0xFF) << 8)
            self.registers[full_name] = new_value
            return

        raise ValueError(f"Unknown register: {name}")

    def get_flag(self, name: str) -> bool:
        """Get CPU flag value."""
        name = name.lower()
        if name in self.flags:
            return self.flags[name]
        raise ValueError(f"Unknown flag: {name}")

    def set_flag(self, name: str, value: bool):
        """Set CPU flag value."""
        name = name.lower()
        if name in self.flags:
            self.flags[name] = bool(value)
        else:
            raise ValueError(f"Unknown flag: {name}")

    def update_flags_arithmetic(self, result: int, size: int = 32):
        """
        Update flags based on arithmetic result.

        Args:
            result: Result value (may be > 32-bit for overflow detection)
            size: Operation size in bits (8, 16, or 32)
        """
        mask = (1 << size) - 1
        masked_result = result & mask

        # Zero flag: result is zero
        self.flags["zf"] = (masked_result == 0)

        # Sign flag: MSB is set
        self.flags["sf"] = bool(masked_result & (1 << (size - 1)))

        # Parity flag: even number of 1s in low byte
        low_byte = masked_result & 0xFF
        self.flags["pf"] = (bin(low_byte).count('1') % 2) == 0

        # Carry flag: result exceeds size
        self.flags["cf"] = (result > mask)

    def update_flags_logic(self, result: int, size: int = 32):
        """
        Update flags for logical operations (AND, OR, XOR).
        Clears CF and OF, updates ZF/SF/PF.
        """
        self.update_flags_arithmetic(result, size)
        self.flags["cf"] = False
        self.flags["of"] = False

    def read_memory(self, address: int, size: int = 4) -> int:
        """
        Read from memory.

        Args:
            address: Memory address
            size: Number of bytes to read (1, 2, or 4)

        Returns:
            Value read from memory (little-endian)
        """
        value = 0
        for i in range(size):
            byte_addr = address + i
            byte_val = self.memory.get(byte_addr, 0)
            value |= (byte_val << (i * 8))
        return value

    def write_memory(self, address: int, value: int, size: int = 4):
        """
        Write to memory.

        Args:
            address: Memory address
            value: Value to write
            size: Number of bytes to write (1, 2, or 4)
        """
        for i in range(size):
            byte_addr = address + i
            byte_val = (value >> (i * 8)) & 0xFF
            self.memory[byte_addr] = byte_val

        # Log the write
        self.memory_writes.append((address, value))

    def push(self, value: int):
        """Push value onto stack."""
        self.registers["esp"] -= 4
        self.write_memory(self.registers["esp"], value, 4)
        self.stack.append(value)

    def pop(self) -> int:
        """Pop value from stack."""
        value = self.read_memory(self.registers["esp"], 4)
        self.registers["esp"] += 4
        if self.stack:
            self.stack.pop()
        return value

    def clone(self) -> 'CPUState':
        """Create a deep copy of this state."""
        new_state = CPUState()
        new_state.registers = self.registers.copy()
        new_state.flags = self.flags.copy()
        new_state.memory = self.memory.copy()
        new_state.stack = self.stack.copy()
        new_state.eip = self.eip
        new_state.memory_writes = self.memory_writes.copy()
        return new_state

    def diff(self, other: 'CPUState') -> Dict[str, Any]:
        """
        Compare this state with another and return differences.

        Returns:
            Dictionary of differences
        """
        differences = {}

        # Register differences
        reg_diff = {}
        for reg in self.registers:
            if self.registers[reg] != other.registers[reg]:
                reg_diff[reg] = {
                    "self": self.registers[reg],
                    "other": other.registers[reg]
                }
        if reg_diff:
            differences["registers"] = reg_diff

        # Flag differences
        flag_diff = {}
        for flag in self.flags:
            if self.flags[flag] != other.flags[flag]:
                flag_diff[flag] = {
                    "self": self.flags[flag],
                    "other": other.flags[flag]
                }
        if flag_diff:
            differences["flags"] = flag_diff

        # Memory differences
        all_addrs = set(self.memory.keys()) | set(other.memory.keys())
        mem_diff = {}
        for addr in all_addrs:
            self_val = self.memory.get(addr, 0)
            other_val = other.memory.get(addr, 0)
            if self_val != other_val:
                mem_diff[f"0x{addr:08x}"] = {
                    "self": self_val,
                    "other": other_val
                }
        if mem_diff:
            differences["memory"] = mem_diff

        return differences

    def __str__(self) -> str:
        """Human-readable state representation."""
        lines = ["CPU State:"]

        # Registers (in a nice grid)
        lines.append("  Registers:")
        for i, reg in enumerate(["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]):
            val = self.registers[reg]
            lines.append(f"    {reg.upper():4s} = 0x{val:08x}")

        # Flags
        flags_str = " ".join(f"{f.upper()}={int(v)}" for f, v in self.flags.items())
        lines.append(f"  Flags: {flags_str}")

        # Memory (if any)
        if self.memory:
            lines.append(f"  Memory: {len(self.memory)} bytes written")

        # Stack
        lines.append(f"  Stack: {len(self.stack)} items")

        return "\n".join(lines)
