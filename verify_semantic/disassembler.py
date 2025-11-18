"""
Disassembler module - wrapper around Capstone.

Provides convenient access to x86 instruction disassembly.
"""

from typing import List, Optional
import capstone


class Instruction:
    """Wrapper around Capstone instruction with convenience methods."""

    def __init__(self, cs_insn):
        """
        Initialize from Capstone instruction.

        Args:
            cs_insn: Capstone instruction object
        """
        self.cs_insn = cs_insn
        self.address = cs_insn.address
        self.mnemonic = cs_insn.mnemonic
        self.op_str = cs_insn.op_str
        self.size = cs_insn.size
        self.bytes = bytes(cs_insn.bytes)
        self.operands = cs_insn.operands if hasattr(cs_insn, 'operands') else []

    def __str__(self) -> str:
        """Human-readable instruction string."""
        return f"{self.mnemonic} {self.op_str}"

    def __repr__(self) -> str:
        """Debug representation."""
        return f"<Instruction 0x{self.address:x}: {self}>"

    @property
    def is_jump(self) -> bool:
        """Check if instruction is a jump."""
        return self.mnemonic.startswith('j')

    @property
    def is_call(self) -> bool:
        """Check if instruction is a call."""
        return self.mnemonic == 'call'

    @property
    def is_ret(self) -> bool:
        """Check if instruction is a return."""
        return self.mnemonic in ['ret', 'retn', 'retf']

    @property
    def is_conditional(self) -> bool:
        """Check if instruction is conditional (conditional jump)."""
        if not self.is_jump:
            return False
        return self.mnemonic not in ['jmp', 'jmpf']

    def get_operand_count(self) -> int:
        """Get number of operands."""
        return len(self.operands)

    def get_operand_type(self, index: int) -> Optional[int]:
        """Get operand type (REG, IMM, MEM)."""
        if index < len(self.operands):
            return self.operands[index].type
        return None

    def get_register_name(self, index: int) -> Optional[str]:
        """Get register name for operand at index."""
        if index < len(self.operands):
            op = self.operands[index]
            if op.type == capstone.x86.X86_OP_REG:
                return self.cs_insn.reg_name(op.reg)
        return None

    def get_immediate_value(self, index: int) -> Optional[int]:
        """Get immediate value for operand at index."""
        if index < len(self.operands):
            op = self.operands[index]
            if op.type == capstone.x86.X86_OP_IMM:
                return op.imm
        return None

    def get_memory_base(self, index: int) -> Optional[str]:
        """Get base register for memory operand at index."""
        if index < len(self.operands):
            op = self.operands[index]
            if op.type == capstone.x86.X86_OP_MEM:
                if op.mem.base != 0:
                    return self.cs_insn.reg_name(op.mem.base)
        return None

    def get_memory_disp(self, index: int) -> Optional[int]:
        """Get displacement for memory operand at index."""
        if index < len(self.operands):
            op = self.operands[index]
            if op.type == capstone.x86.X86_OP_MEM:
                return op.mem.disp
        return None


class Disassembler:
    """Disassembler for x86/x86_64 code using Capstone."""

    def __init__(self, arch=capstone.CS_ARCH_X86, mode=capstone.CS_MODE_32):
        """
        Initialize disassembler.

        Args:
            arch: Capstone architecture (default: x86)
            mode: Capstone mode (default: 32-bit)
        """
        self.md = capstone.Cs(arch, mode)
        self.md.detail = True  # Enable detailed information
        self.arch = arch
        self.mode = mode

    def disassemble(self, code: bytes, address: int = 0) -> List[Instruction]:
        """
        Disassemble code bytes.

        Args:
            code: Raw code bytes
            address: Starting address (default: 0)

        Returns:
            List of Instruction objects
        """
        instructions = []
        for cs_insn in self.md.disasm(code, address):
            instructions.append(Instruction(cs_insn))
        return instructions

    def disassemble_one(self, code: bytes, address: int = 0) -> Optional[Instruction]:
        """
        Disassemble a single instruction.

        Args:
            code: Raw code bytes
            address: Starting address (default: 0)

        Returns:
            First instruction or None
        """
        for cs_insn in self.md.disasm(code, address, count=1):
            return Instruction(cs_insn)
        return None

    def disassemble_from_file(self, filepath: str) -> List[Instruction]:
        """
        Disassemble code from a binary file.

        Args:
            filepath: Path to binary file

        Returns:
            List of Instruction objects
        """
        with open(filepath, 'rb') as f:
            code = f.read()
        return self.disassemble(code)


def create_disassembler(bits: int = 32) -> Disassembler:
    """
    Create a disassembler for the specified architecture.

    Args:
        bits: Architecture bits (32 or 64)

    Returns:
        Disassembler instance
    """
    if bits == 32:
        return Disassembler(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif bits == 64:
        return Disassembler(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        raise ValueError(f"Unsupported architecture: {bits}-bit")


# Convenience functions
def disassemble(code: bytes, address: int = 0, bits: int = 32) -> List[Instruction]:
    """
    Disassemble code bytes (convenience function).

    Args:
        code: Raw code bytes
        address: Starting address (default: 0)
        bits: Architecture bits (default: 32)

    Returns:
        List of Instruction objects
    """
    disasm = create_disassembler(bits)
    return disasm.disassemble(code, address)


def disassemble_file(filepath: str, bits: int = 32) -> List[Instruction]:
    """
    Disassemble code from a binary file (convenience function).

    Args:
        filepath: Path to binary file
        bits: Architecture bits (default: 32)

    Returns:
        List of Instruction objects
    """
    disasm = create_disassembler(bits)
    return disasm.disassemble_from_file(filepath)
