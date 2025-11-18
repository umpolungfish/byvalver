"""
Execution engine for concrete and symbolic instruction execution.

Coordinates between instructions, CPU state, and semantic handlers.
"""

import capstone
from typing import Optional, List
from .cpu_state import CPUState
from .disassembler import Instruction


class ExecutionEngine:
    """Engine for executing instructions and updating CPU state."""

    def __init__(self, state: Optional[CPUState] = None):
        """
        Initialize execution engine.

        Args:
            state: Initial CPU state (creates new if None)
        """
        self.state = state if state is not None else CPUState()
        self.trace: List[dict] = []  # Execution trace

    def execute(self, insn: Instruction) -> bool:
        """
        Execute a single instruction.

        Args:
            insn: Instruction to execute

        Returns:
            True if successfully executed, False otherwise
        """
        # Save state before execution for tracing
        state_before = self.state.clone()

        # Dispatch to appropriate handler
        success = self._dispatch_instruction(insn)

        # Record trace
        if success:
            self.trace.append({
                'address': insn.address,
                'instruction': str(insn),
                'bytes': insn.bytes.hex(),
                'state_before': state_before,
                'state_after': self.state.clone(),
            })

        return success

    def execute_sequence(self, instructions: List[Instruction]) -> bool:
        """
        Execute a sequence of instructions.

        Args:
            instructions: List of instructions to execute

        Returns:
            True if all executed successfully
        """
        for insn in instructions:
            if not self.execute(insn):
                return False
        return True

    def _dispatch_instruction(self, insn: Instruction) -> bool:
        """Dispatch instruction to appropriate handler."""
        mnem = insn.mnemonic

        # Data movement
        if mnem in ['mov', 'lea', 'push', 'pop', 'xchg', 'movzx', 'movsx', 'cdq']:
            return self._execute_data_movement(insn)

        # Arithmetic
        elif mnem in ['add', 'sub', 'inc', 'dec', 'neg', 'cmp']:
            return self._execute_arithmetic(insn)

        # Logic
        elif mnem in ['and', 'or', 'xor', 'not', 'test']:
            return self._execute_logic(insn)

        # Shift/rotate
        elif mnem in ['shl', 'shr', 'sal', 'sar', 'rol', 'ror']:
            return self._execute_shift(insn)

        # Control flow
        elif mnem.startswith('j') or mnem in ['call', 'ret', 'loop', 'jecxz']:
            return self._execute_control_flow(insn)

        # Multiplication/division
        elif mnem in ['mul', 'imul', 'div', 'idiv']:
            return self._execute_muldiv(insn)

        # NOP and other instructions that don't change state
        elif mnem == 'nop':
            return True

        # Unknown instruction
        return False

    # Data movement instructions

    def _execute_data_movement(self, insn: Instruction) -> bool:
        """Execute data movement instructions."""
        mnem = insn.mnemonic

        if mnem == 'mov':
            return self._mov(insn)
        elif mnem == 'lea':
            return self._lea(insn)
        elif mnem == 'push':
            return self._push(insn)
        elif mnem == 'pop':
            return self._pop(insn)
        elif mnem == 'xchg':
            return self._xchg(insn)
        elif mnem == 'movzx':
            return self._movzx(insn)
        elif mnem == 'movsx':
            return self._movsx(insn)
        elif mnem == 'cdq':
            return self._cdq(insn)

        return False

    def _mov(self, insn: Instruction) -> bool:
        """MOV dst, src"""
        value = self._get_operand_value(insn, 1)
        if value is None:
            return False
        return self._set_operand_value(insn, 0, value)

    def _lea(self, insn: Instruction) -> bool:
        """LEA dst, [src]"""
        if len(insn.operands) < 2:
            return False
        src_op = insn.operands[1]
        if src_op.type == capstone.x86.X86_OP_MEM:
            address = self._calculate_address(src_op)
            return self._set_operand_value(insn, 0, address)
        return False

    def _push(self, insn: Instruction) -> bool:
        """PUSH src"""
        value = self._get_operand_value(insn, 0)
        if value is None:
            return False
        self.state.push(value)
        return True

    def _pop(self, insn: Instruction) -> bool:
        """POP dst"""
        value = self.state.pop()
        return self._set_operand_value(insn, 0, value)

    def _xchg(self, insn: Instruction) -> bool:
        """XCHG op1, op2"""
        val1 = self._get_operand_value(insn, 0)
        val2 = self._get_operand_value(insn, 1)
        if val1 is None or val2 is None:
            return False
        self._set_operand_value(insn, 0, val2)
        self._set_operand_value(insn, 1, val1)
        return True

    def _movzx(self, insn: Instruction) -> bool:
        """MOVZX dst, src (zero extend)"""
        value = self._get_operand_value(insn, 1)
        if value is None:
            return False
        # Zero extension is automatic since we mask values
        return self._set_operand_value(insn, 0, value)

    def _movsx(self, insn: Instruction) -> bool:
        """MOVSX dst, src (sign extend)"""
        if len(insn.operands) < 2:
            return False
        src_op = insn.operands[1]
        value = self._get_operand_value(insn, 1)
        if value is None:
            return False

        # Sign extend based on source size
        src_size = src_op.size * 8
        if value & (1 << (src_size - 1)):
            # Sign bit set - extend with 1s
            mask = (1 << src_size) - 1
            value = value | (~mask & 0xFFFFFFFF)

        return self._set_operand_value(insn, 0, value)

    def _cdq(self, insn: Instruction) -> bool:
        """CDQ - sign extend EAX to EDX:EAX"""
        eax = self.state.get_register("eax")
        if eax & 0x80000000:
            self.state.set_register("edx", 0xFFFFFFFF)
        else:
            self.state.set_register("edx", 0)
        return True

    # Arithmetic instructions

    def _execute_arithmetic(self, insn: Instruction) -> bool:
        """Execute arithmetic instructions."""
        mnem = insn.mnemonic

        if mnem == 'add':
            return self._add(insn)
        elif mnem == 'sub':
            return self._sub(insn)
        elif mnem == 'inc':
            return self._inc(insn)
        elif mnem == 'dec':
            return self._dec(insn)
        elif mnem == 'neg':
            return self._neg(insn)
        elif mnem == 'cmp':
            return self._cmp(insn)

        return False

    def _add(self, insn: Instruction) -> bool:
        """ADD dst, src"""
        dst_val = self._get_operand_value(insn, 0)
        src_val = self._get_operand_value(insn, 1)
        if dst_val is None or src_val is None:
            return False

        result = dst_val + src_val
        size = self._get_operand_size(insn.operands[0])
        self.state.update_flags_arithmetic(result, size)
        return self._set_operand_value(insn, 0, result & ((1 << size) - 1))

    def _sub(self, insn: Instruction) -> bool:
        """SUB dst, src"""
        dst_val = self._get_operand_value(insn, 0)
        src_val = self._get_operand_value(insn, 1)
        if dst_val is None or src_val is None:
            return False

        result = dst_val - src_val
        size = self._get_operand_size(insn.operands[0])
        self.state.update_flags_arithmetic(result, size)
        return self._set_operand_value(insn, 0, result & ((1 << size) - 1))

    def _inc(self, insn: Instruction) -> bool:
        """INC dst"""
        value = self._get_operand_value(insn, 0)
        if value is None:
            return False

        result = value + 1
        size = self._get_operand_size(insn.operands[0])
        # INC doesn't affect CF
        old_cf = self.state.get_flag("cf")
        self.state.update_flags_arithmetic(result, size)
        self.state.set_flag("cf", old_cf)
        return self._set_operand_value(insn, 0, result & ((1 << size) - 1))

    def _dec(self, insn: Instruction) -> bool:
        """DEC dst"""
        value = self._get_operand_value(insn, 0)
        if value is None:
            return False

        result = value - 1
        size = self._get_operand_size(insn.operands[0])
        # DEC doesn't affect CF
        old_cf = self.state.get_flag("cf")
        self.state.update_flags_arithmetic(result, size)
        self.state.set_flag("cf", old_cf)
        return self._set_operand_value(insn, 0, result & ((1 << size) - 1))

    def _neg(self, insn: Instruction) -> bool:
        """NEG dst (two's complement)"""
        value = self._get_operand_value(insn, 0)
        if value is None:
            return False

        size = self._get_operand_size(insn.operands[0])
        mask = (1 << size) - 1
        result = (-value) & mask
        self.state.update_flags_arithmetic(result, size)
        # NEG sets CF if value != 0
        self.state.set_flag("cf", value != 0)
        return self._set_operand_value(insn, 0, result)

    def _cmp(self, insn: Instruction) -> bool:
        """CMP dst, src (subtract and set flags, don't store)"""
        dst_val = self._get_operand_value(insn, 0)
        src_val = self._get_operand_value(insn, 1)
        if dst_val is None or src_val is None:
            return False

        result = dst_val - src_val
        size = self._get_operand_size(insn.operands[0])
        self.state.update_flags_arithmetic(result, size)
        # Don't store result
        return True

    # Logic instructions

    def _execute_logic(self, insn: Instruction) -> bool:
        """Execute logic instructions."""
        mnem = insn.mnemonic

        if mnem == 'and':
            return self._and(insn)
        elif mnem == 'or':
            return self._or(insn)
        elif mnem == 'xor':
            return self._xor(insn)
        elif mnem == 'not':
            return self._not(insn)
        elif mnem == 'test':
            return self._test(insn)

        return False

    def _and(self, insn: Instruction) -> bool:
        """AND dst, src"""
        dst_val = self._get_operand_value(insn, 0)
        src_val = self._get_operand_value(insn, 1)
        if dst_val is None or src_val is None:
            return False

        result = dst_val & src_val
        size = self._get_operand_size(insn.operands[0])
        self.state.update_flags_logic(result, size)
        return self._set_operand_value(insn, 0, result)

    def _or(self, insn: Instruction) -> bool:
        """OR dst, src"""
        dst_val = self._get_operand_value(insn, 0)
        src_val = self._get_operand_value(insn, 1)
        if dst_val is None or src_val is None:
            return False

        result = dst_val | src_val
        size = self._get_operand_size(insn.operands[0])
        self.state.update_flags_logic(result, size)
        return self._set_operand_value(insn, 0, result)

    def _xor(self, insn: Instruction) -> bool:
        """XOR dst, src"""
        dst_val = self._get_operand_value(insn, 0)
        src_val = self._get_operand_value(insn, 1)
        if dst_val is None or src_val is None:
            return False

        result = dst_val ^ src_val
        size = self._get_operand_size(insn.operands[0])
        self.state.update_flags_logic(result, size)
        return self._set_operand_value(insn, 0, result)

    def _not(self, insn: Instruction) -> bool:
        """NOT dst (bitwise NOT - no flags affected)"""
        value = self._get_operand_value(insn, 0)
        if value is None:
            return False

        size = self._get_operand_size(insn.operands[0])
        mask = (1 << size) - 1
        result = (~value) & mask
        return self._set_operand_value(insn, 0, result)

    def _test(self, insn: Instruction) -> bool:
        """TEST dst, src (AND and set flags, don't store)"""
        dst_val = self._get_operand_value(insn, 0)
        src_val = self._get_operand_value(insn, 1)
        if dst_val is None or src_val is None:
            return False

        result = dst_val & src_val
        size = self._get_operand_size(insn.operands[0])
        self.state.update_flags_logic(result, size)
        # Don't store result
        return True

    # Shift/rotate instructions

    def _execute_shift(self, insn: Instruction) -> bool:
        """Execute shift/rotate instructions."""
        mnem = insn.mnemonic

        if mnem in ['shl', 'sal']:
            return self._shl(insn)
        elif mnem == 'shr':
            return self._shr(insn)
        elif mnem == 'sar':
            return self._sar(insn)
        elif mnem == 'rol':
            return self._rol(insn)
        elif mnem == 'ror':
            return self._ror(insn)

        return False

    def _shl(self, insn: Instruction) -> bool:
        """SHL dst, count (shift left)"""
        value = self._get_operand_value(insn, 0)
        count = self._get_operand_value(insn, 1)
        if value is None or count is None:
            return False

        size = self._get_operand_size(insn.operands[0])
        count = count & 0x1F  # Mask to 5 bits
        result = (value << count) & ((1 << size) - 1)

        self.state.update_flags_arithmetic(result, size)
        if count > 0:
            # CF = last bit shifted out
            self.state.set_flag("cf", bool(value & (1 << (size - count))))

        return self._set_operand_value(insn, 0, result)

    def _shr(self, insn: Instruction) -> bool:
        """SHR dst, count (logical shift right)"""
        value = self._get_operand_value(insn, 0)
        count = self._get_operand_value(insn, 1)
        if value is None or count is None:
            return False

        size = self._get_operand_size(insn.operands[0])
        count = count & 0x1F  # Mask to 5 bits
        result = value >> count

        self.state.update_flags_arithmetic(result, size)
        if count > 0:
            # CF = last bit shifted out
            self.state.set_flag("cf", bool(value & (1 << (count - 1))))

        return self._set_operand_value(insn, 0, result)

    def _sar(self, insn: Instruction) -> bool:
        """SAR dst, count (arithmetic shift right - preserves sign)"""
        value = self._get_operand_value(insn, 0)
        count = self._get_operand_value(insn, 1)
        if value is None or count is None:
            return False

        size = self._get_operand_size(insn.operands[0])
        count = count & 0x1F
        sign_bit = 1 << (size - 1)

        result = value >> count
        # Fill with sign bit
        if value & sign_bit:
            fill_mask = ((1 << count) - 1) << (size - count)
            result |= fill_mask

        result &= (1 << size) - 1
        self.state.update_flags_arithmetic(result, size)
        return self._set_operand_value(insn, 0, result)

    def _rol(self, insn: Instruction) -> bool:
        """ROL dst, count (rotate left)"""
        value = self._get_operand_value(insn, 0)
        count = self._get_operand_value(insn, 1)
        if value is None or count is None:
            return False

        size = self._get_operand_size(insn.operands[0])
        count = count % size
        mask = (1 << size) - 1

        result = ((value << count) | (value >> (size - count))) & mask
        return self._set_operand_value(insn, 0, result)

    def _ror(self, insn: Instruction) -> bool:
        """ROR dst, count (rotate right)"""
        value = self._get_operand_value(insn, 0)
        count = self._get_operand_value(insn, 1)
        if value is None or count is None:
            return False

        size = self._get_operand_size(insn.operands[0])
        count = count % size
        mask = (1 << size) - 1

        result = ((value >> count) | (value << (size - count))) & mask
        return self._set_operand_value(insn, 0, result)

    # Multiplication/division

    def _execute_muldiv(self, insn: Instruction) -> bool:
        """Execute multiplication/division instructions."""
        # Simplified - not fully implementing for MVP
        return True

    # Control flow

    def _execute_control_flow(self, insn: Instruction) -> bool:
        """Execute control flow instructions."""
        # For concrete execution, we don't actually jump
        # Just update state for LOOP-like instructions
        mnem = insn.mnemonic

        if mnem == 'loop':
            # Decrement ECX
            ecx = self.state.get_register("ecx")
            self.state.set_register("ecx", (ecx - 1) & 0xFFFFFFFF)
            return True

        elif mnem == 'jecxz':
            # No state change
            return True

        elif mnem in ['call', 'ret']:
            # Simplified - don't actually track call stack for MVP
            return True

        elif mnem.startswith('j'):
            # Jump instructions don't modify state
            return True

        return False

    # Helper methods

    def _get_operand_value(self, insn: Instruction, index: int) -> Optional[int]:
        """Get value of operand at index."""
        if index >= len(insn.operands):
            return None

        op = insn.operands[index]

        if op.type == capstone.x86.X86_OP_REG:
            reg_name = insn.cs_insn.reg_name(op.reg)
            return self.state.get_register(reg_name)

        elif op.type == capstone.x86.X86_OP_IMM:
            return op.imm & 0xFFFFFFFF

        elif op.type == capstone.x86.X86_OP_MEM:
            address = self._calculate_address(op)
            size = op.size
            return self.state.read_memory(address, size)

        return None

    def _set_operand_value(self, insn: Instruction, index: int, value: int) -> bool:
        """Set value of operand at index."""
        if index >= len(insn.operands):
            return False

        op = insn.operands[index]
        size = self._get_operand_size(op)
        mask = (1 << size) - 1
        value = value & mask

        if op.type == capstone.x86.X86_OP_REG:
            reg_name = insn.cs_insn.reg_name(op.reg)
            self.state.set_register(reg_name, value)
            return True

        elif op.type == capstone.x86.X86_OP_MEM:
            address = self._calculate_address(op)
            self.state.write_memory(address, value, op.size)
            return True

        return False

    def _get_operand_size(self, op) -> int:
        """Get operand size in bits."""
        return op.size * 8

    def _calculate_address(self, mem_op) -> int:
        """Calculate effective address for memory operand."""
        if mem_op.type != capstone.x86.X86_OP_MEM:
            return 0

        mem = mem_op.mem
        address = mem.disp

        # Add base register
        if mem.base != 0:
            # Get register name using Capstone's MD instance
            # For now, we'll use a lookup table
            base_reg = self._get_reg_name(mem.base)
            if base_reg:
                address += self.state.get_register(base_reg)

        # Add index * scale
        if mem.index != 0:
            index_reg = self._get_reg_name(mem.index)
            if index_reg:
                address += self.state.get_register(index_reg) * mem.scale

        return address & 0xFFFFFFFF

    def _get_reg_name(self, reg_id: int) -> Optional[str]:
        """Convert Capstone register ID to name."""
        # Map common register IDs
        reg_map = {
            capstone.x86.X86_REG_EAX: "eax",
            capstone.x86.X86_REG_EBX: "ebx",
            capstone.x86.X86_REG_ECX: "ecx",
            capstone.x86.X86_REG_EDX: "edx",
            capstone.x86.X86_REG_ESI: "esi",
            capstone.x86.X86_REG_EDI: "edi",
            capstone.x86.X86_REG_EBP: "ebp",
            capstone.x86.X86_REG_ESP: "esp",
            capstone.x86.X86_REG_AL: "al",
            capstone.x86.X86_REG_AH: "ah",
            capstone.x86.X86_REG_BL: "bl",
            capstone.x86.X86_REG_BH: "bh",
            capstone.x86.X86_REG_CL: "cl",
            capstone.x86.X86_REG_CH: "ch",
            capstone.x86.X86_REG_DL: "dl",
            capstone.x86.X86_REG_DH: "dh",
        }
        return reg_map.get(reg_id)
