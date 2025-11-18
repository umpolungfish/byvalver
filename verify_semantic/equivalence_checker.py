"""
Equivalence checker for verifying semantic equivalence between original and processed shellcode.
"""

from typing import List, Dict, Tuple, Optional
from .disassembler import Instruction
from .execution_engine import ExecutionEngine
from .cpu_state import CPUState


class EquivalenceResult:
    """Result of equivalence checking."""

    def __init__(self):
        self.passed: bool = False
        self.total_instructions: int = 0
        self.verified_instructions: int = 0
        self.failed_instructions: List[Tuple[int, str]] = []
        self.transformation_stats: Dict[str, int] = {}
        self.register_mismatches: List[Dict] = []
        self.flag_mismatches: List[Dict] = []
        self.memory_mismatches: List[Dict] = []
        self.details: List[str] = []

    def add_detail(self, message: str):
        """Add a detail message."""
        self.details.append(message)

    def get_score(self) -> float:
        """Get equivalence score (0-100)."""
        if self.total_instructions == 0:
            return 0.0
        return (self.verified_instructions / self.total_instructions) * 100

    def __str__(self) -> str:
        """Format result as string."""
        lines = []
        lines.append(f"Equivalence Check: {'PASSED' if self.passed else 'FAILED'}")
        lines.append(f"Score: {self.get_score():.1f}% ({self.verified_instructions}/{self.total_instructions})")

        if self.transformation_stats:
            lines.append("\nTransformations Detected:")
            for trans_type, count in sorted(self.transformation_stats.items()):
                lines.append(f"  {trans_type}: {count}")

        if self.register_mismatches:
            lines.append(f"\nRegister Mismatches: {len(self.register_mismatches)}")
            for mismatch in self.register_mismatches[:5]:  # Show first 5
                lines.append(f"  {mismatch}")

        if self.flag_mismatches:
            lines.append(f"\nFlag Mismatches: {len(self.flag_mismatches)}")

        if self.memory_mismatches:
            lines.append(f"\nMemory Mismatches: {len(self.memory_mismatches)}")

        return "\n".join(lines)


class EquivalenceChecker:
    """Check semantic equivalence between original and transformed shellcode."""

    def __init__(self):
        self.result = EquivalenceResult()
        self.debug = False

    def verify(self, original_insns: List[Instruction], processed_insns: List[Instruction]) -> EquivalenceResult:
        """
        Verify semantic equivalence.

        Args:
            original_insns: Original instructions
            processed_insns: Processed instructions

        Returns:
            EquivalenceResult with verification details
        """
        self.result = EquivalenceResult()
        self.result.total_instructions = len(original_insns)

        # Execute both versions with test vectors
        test_passed = self._verify_with_test_vectors(original_insns, processed_insns)

        # Check for specific transformation patterns
        self._detect_transformations(original_insns, processed_insns)

        # Determine overall result
        self.result.passed = test_passed
        self.result.verified_instructions = self.result.total_instructions if test_passed else 0

        return self.result

    def _verify_with_test_vectors(self, original_insns: List[Instruction], processed_insns: List[Instruction]) -> bool:
        """
        Verify using concrete execution with test vectors.

        Args:
            original_insns: Original instructions
            processed_insns: Processed instructions

        Returns:
            True if all test vectors pass
        """
        test_vectors = self._generate_test_vectors()
        all_passed = True

        for i, test_input in enumerate(test_vectors):
            # Execute original
            engine_orig = ExecutionEngine(test_input.clone())
            orig_success = engine_orig.execute_sequence(original_insns)

            # Execute processed
            engine_proc = ExecutionEngine(test_input.clone())
            proc_success = engine_proc.execute_sequence(processed_insns)

            if not orig_success or not proc_success:
                self.result.add_detail(f"Test vector {i}: Execution failed")
                continue

            # Compare final states
            diff = engine_orig.state.diff(engine_proc.state)

            if diff:
                all_passed = False
                self.result.add_detail(f"Test vector {i}: State mismatch")

                if 'registers' in diff:
                    self.result.register_mismatches.append({
                        'test_vector': i,
                        'differences': diff['registers']
                    })

                if 'flags' in diff:
                    self.result.flag_mismatches.append({
                        'test_vector': i,
                        'differences': diff['flags']
                    })

                if 'memory' in diff:
                    self.result.memory_mismatches.append({
                        'test_vector': i,
                        'differences': diff['memory']
                    })
            else:
                self.result.add_detail(f"Test vector {i}: PASSED")

        return all_passed

    def _generate_test_vectors(self) -> List[CPUState]:
        """
        Generate test input vectors for concrete execution.

        Returns:
            List of CPUState objects with different initial states
        """
        test_vectors = []

        # Test 1: All zeros
        state = CPUState()
        test_vectors.append(state)

        # Test 2: All ones
        state = CPUState()
        for reg in state.registers:
            state.registers[reg] = 0xFFFFFFFF
        test_vectors.append(state)

        # Test 3: Alternating pattern
        state = CPUState()
        state.registers["eax"] = 0xAAAAAAAA
        state.registers["ebx"] = 0x55555555
        state.registers["ecx"] = 0xAAAAAAAA
        state.registers["edx"] = 0x55555555
        test_vectors.append(state)

        # Test 4: Small values
        state = CPUState()
        state.registers["eax"] = 1
        state.registers["ebx"] = 2
        state.registers["ecx"] = 3
        state.registers["edx"] = 4
        test_vectors.append(state)

        # Test 5: Boundary values
        state = CPUState()
        state.registers["eax"] = 0x7FFFFFFF
        state.registers["ebx"] = 0x80000000
        state.registers["ecx"] = 0x00000001
        state.registers["edx"] = 0xFFFFFFFF
        test_vectors.append(state)

        return test_vectors

    def _detect_transformations(self, original_insns: List[Instruction], processed_insns: List[Instruction]):
        """
        Detect and catalog transformation patterns.

        Args:
            original_insns: Original instructions
            processed_insns: Processed instructions
        """
        # Look for common patterns
        orig_idx = 0
        proc_idx = 0

        while orig_idx < len(original_insns) and proc_idx < len(processed_insns):
            orig = original_insns[orig_idx]
            proc = processed_insns[proc_idx]

            # Direct match
            if str(orig) == str(proc):
                self._record_transformation("DIRECT")
                orig_idx += 1
                proc_idx += 1
                continue

            # Check for known patterns
            pattern_found = False

            # MOV reg, 0 -> XOR reg, reg
            if self._is_mov_zero(orig) and self._is_xor_self(proc):
                self._record_transformation("MOV_ZERO_TO_XOR")
                orig_idx += 1
                proc_idx += 1
                pattern_found = True

            # Byte construction pattern (MOV -> XOR + SHL + OR sequence)
            elif orig.mnemonic == 'mov' and proc.mnemonic == 'xor':
                # Look ahead for byte construction pattern
                if self._is_byte_construction_pattern(original_insns, processed_insns, orig_idx, proc_idx):
                    self._record_transformation("BYTE_CONSTRUCTION")
                    orig_idx += 1
                    proc_idx = self._skip_byte_construction(processed_insns, proc_idx)
                    pattern_found = True

            # LOOP -> DEC + JNZ
            elif orig.mnemonic == 'loop' and proc.mnemonic == 'dec':
                self._record_transformation("LOOP_TO_DEC_JNZ")
                orig_idx += 1
                proc_idx += 2  # Skip DEC and JNZ
                pattern_found = True

            if not pattern_found:
                # Unknown transformation or mismatch
                orig_idx += 1
                proc_idx += 1

    def _record_transformation(self, trans_type: str):
        """Record a transformation type."""
        if trans_type not in self.result.transformation_stats:
            self.result.transformation_stats[trans_type] = 0
        self.result.transformation_stats[trans_type] += 1

    def _is_mov_zero(self, insn: Instruction) -> bool:
        """Check if instruction is MOV reg, 0."""
        if insn.mnemonic != 'mov':
            return False
        if len(insn.operands) < 2:
            return False
        op2 = insn.operands[1]
        return op2.type == 19 and op2.imm == 0  # X86_OP_IMM

    def _is_xor_self(self, insn: Instruction) -> bool:
        """Check if instruction is XOR reg, reg (same register)."""
        if insn.mnemonic != 'xor':
            return False
        if len(insn.operands) < 2:
            return False
        # Check if both operands are the same register
        op1 = insn.operands[0]
        op2 = insn.operands[1]
        if op1.type != 1 or op2.type != 1:  # X86_OP_REG
            return False
        return op1.reg == op2.reg

    def _is_byte_construction_pattern(self, original: List[Instruction], processed: List[Instruction],
                                     orig_idx: int, proc_idx: int) -> bool:
        """
        Detect byte-by-byte construction pattern.

        Pattern: XOR reg, reg; MOV AL/BL/etc, byte; SHL reg, 8; OR AL, byte; ...
        """
        if proc_idx + 3 >= len(processed):
            return False

        # Should start with XOR reg, reg
        if not self._is_xor_self(processed[proc_idx]):
            return False

        # Look for SHL and OR pattern in next few instructions
        has_shl = False
        has_or = False

        for i in range(proc_idx + 1, min(proc_idx + 8, len(processed))):
            if processed[i].mnemonic == 'shl':
                has_shl = True
            if processed[i].mnemonic == 'or':
                has_or = True

        return has_shl and has_or

    def _skip_byte_construction(self, processed: List[Instruction], start_idx: int) -> int:
        """
        Skip past a byte construction sequence.

        Returns index of next instruction after the sequence.
        """
        idx = start_idx + 1  # Skip initial XOR

        # Skip MOV, SHL, OR patterns
        while idx < len(processed):
            insn = processed[idx]
            if insn.mnemonic in ['mov', 'shl', 'or']:
                idx += 1
            else:
                break

        return idx
