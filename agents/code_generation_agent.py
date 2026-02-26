"""
Code Generation Agent
Generates a complete C implementation (.h and .c files) for a proposed BYVALVER strategy.
Uses the AjintK BaseAgent template.
"""
import sys
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / "AjintK"))

from framework import BaseAgent, ToolDefinitions

# Sentinel strings used to delimit the two files in the LLM response
_H_START = "=== HEADER FILE ==="
_H_END = "=== END HEADER ==="
_C_START = "=== SOURCE FILE ==="
_C_END = "=== END SOURCE ==="


class CodeGenerationAgent(BaseAgent):
    """
    Given a technique proposal from TechniqueProposalAgent and the strategy catalog
    from StrategyDiscoveryAgent, generates a complete C implementation conforming to
    the BYVALVER strategy_t interface.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="code_generation_agent",
            name="Code Generation Agent",
            description="Generates C strategy implementation files for BYVALVER",
            capabilities=[
                "C code generation",
                "x86/x64 instruction encoding",
                "BYVALVER strategy_t interface implementation",
                "Capstone disassembly API usage",
            ],
            config=config,
        )
        self.src_dir = Path(__file__).parent.parent / "src"

    def get_tools(self) -> List[Dict[str, Any]]:
        return [
            ToolDefinitions.file_read(),
            ToolDefinitions.run_command(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        print("[CodeGenerationAgent] Generating C implementation...")

        # Unpack context — supports direct and pipeline shapes
        proposal: Dict[str, Any] = {}
        catalog: Dict[str, Any] = {}

        if context:
            proposal = context.get("proposal", {})
            catalog = context.get("catalog", {})
            if not proposal and "previous_stage" in context:
                prev = context["previous_stage"]
                proposal = prev.get("proposal", {})
                catalog = prev.get("catalog", {})

        if not proposal or "raw_proposal" in proposal:
            return {
                "status": "error",
                "error": "No valid structured proposal in context",
                "findings": None,
                "artifacts": [],
            }

        # Derive file base name (strip trailing _strategies if present so we don't double it)
        strategy_name: str = proposal.get("strategy_name", "custom_strategies")
        base_name = strategy_name.removesuffix("_strategies")

        # NOTE: BYVAL_ARCH_BOTH does not exist in byval_arch_t.
        # The compatibility layer in strategy_registry.c automatically
        # applies BYVAL_ARCH_X86 strategies to x64 targets (unless they
        # use removed instructions), so BYVAL_ARCH_X86 is the correct
        # value for strategies that target both architectures.
        arch_macro = {
            "x86": "BYVAL_ARCH_X86",
            "x64": "BYVAL_ARCH_X64",
            "both": "BYVAL_ARCH_X86",
        }.get(proposal.get("architecture", "both"), "BYVAL_ARCH_X86")

        try:
            # Pull reference material (prefer catalog if already fetched, else re-read)
            strategy_h: str = catalog.get("strategy_interface") or await self.tool_executor.execute_tool(
                "file_read", {"path": str(self.src_dir / "strategy.h")}
            )
            utils_h: str = catalog.get("utils_header") or await self.tool_executor.execute_tool(
                "file_read", {"path": str(self.src_dir / "utils.h")}
            )
            example_c: str = catalog.get("example_implementation") or await self.tool_executor.execute_tool(
                "file_read", {"path": str(self.src_dir / "mov_strategies.c")}
            )

            # Trim large blobs so we stay within context
            strategy_h_trimmed = strategy_h[:2000]
            utils_h_trimmed = utils_h[:2500]
            example_c_trimmed = example_c[:2500]

            prompt = f"""<role>
You are an expert C99 systems programmer. Your task is to implement a BYVALVER bad-byte elimination strategy as two complete, compilable C source files.
</role>

<system_context>
BYVALVER uses **Capstone** (cs_insn*) for disassembly and a simple byte buffer for output.
Every strategy is a `strategy_t` struct with three function pointers:
  can_handle(cs_insn*)           — returns 1 if this strategy applies, 0 otherwise
  get_size(cs_insn*)             — returns a **conservative upper-bound** byte count for the replacement
  generate(struct buffer*, cs_insn*) — writes the replacement bytes into the buffer
</system_context>

<strategy_specification>
  <name>{strategy_name}</name>
  <display_name>{proposal.get('display_name', 'Custom Strategy')}</display_name>
  <description>{proposal.get('description', '')}</description>
  <target_instruction>{proposal.get('target_instruction', 'any')}</target_instruction>
  <approach>{proposal.get('approach', '')}</approach>
  <target_arch>{arch_macro}</target_arch>
  <priority>{proposal.get('priority', 80)}</priority>
  <example>{proposal.get('example_transformation', '')}</example>
</strategy_specification>

<reference_interface>
<strategy_h>
{strategy_h_trimmed}
</strategy_h>
<utils_h>
{utils_h_trimmed}
</utils_h>
<canonical_example>
{example_c_trimmed}
</canonical_example>
</reference_interface>

<hard_constraints>
You **MUST** set `.target_arch` to one of exactly two values: `BYVAL_ARCH_X86` (for strategies targeting x86 or both x86 and x64) or `BYVAL_ARCH_X64` (for x64-exclusive strategies). `BYVAL_ARCH_BOTH` **DOES NOT EXIST** — you **MUST NOT** use it; doing so causes a compile error.

You **MUST NOT** write `0x00` to the output buffer under any circumstances inside `generate_*`. Every literal byte value you pass to `buffer_write_byte()`, `buffer_write_word()`, or `buffer_write_dword()` **MUST** be non-zero — no exceptions.

You **MUST** silence every unused function parameter with `(void)param_name;` as the **first line** of the function body — failure to do so is a compile warning under `-Wunused-parameter`.

You **MUST** remove every local variable that is declared but not subsequently read. Dead declarations are a compile warning and indicate incorrect logic — you are **EXPRESSLY PROHIBITED** from leaving them in the generated code.

Every `static` helper function you define **MUST** be called at least once. You **MUST NOT** define helper functions speculatively — any `static` function that is never called **MUST** be deleted.

You **MUST** use `cs_x86_op *` when declaring a pointer to an operand array element — **NOT** `x86_op *`. `x86_op` does not exist and will cause a compile error. Example: `cs_x86_op *ops = insn->detail->x86.operands;`

You **MUST NOT** add `#include "buffer.h"` — `buffer.h` does not exist in this project. `struct buffer` and all `buffer_write_*` functions (`buffer_write_byte`, `buffer_write_word`, `buffer_write_dword`) are declared in `utils.h`, which is already included.

You **MUST** access instruction fields exclusively via: `insn->id`, `insn->detail->x86.operands[N]`, `insn->detail->x86.op_count`, `insn->detail->x86.operands[N].type`, `insn->detail->x86.operands[N].reg`, `insn->detail->x86.operands[N].imm`.

Every `X86_INS_*` constant you use in a `switch` or `if` **MUST** exist in the installed Capstone headers. You **MUST NOT** invent or guess instruction ID names — `X86_INS_VRCPPD`, for example, does not exist. When unsure, you **MUST** fall back to `insn->id` comparisons against the known-good subset or omit the case entirely.

`get_size_*` **MUST** return a value strictly greater than or equal to the maximum number of bytes `generate_*` can ever write — you **MUST NOT** underestimate.

You **MUST NOT** redeclare `utils.h` or `core.h` functions — `utils.h` and `core.h` are both transitively included via `strategy.h`. You **MUST NOT** define a `static` version of any symbol they declare — doing so causes: `error: static declaration of 'X' follows non-static declaration`. You are **EXPRESSLY PROHIBITED** from using redefinitions including: `is_bad_byte_free`, `has_null_bytes`, `find_neg_equivalent`, `find_xor_key`, `find_addsub_key`, `buffer_write_byte`, `buffer_write_word`, `buffer_write_dword` (utils.h); `get_reg_index`, `is_rip_relative_operand`, `is_relative_jump`, `fallback_general_instruction`, `fallback_mov_reg_imm`, `fallback_arithmetic_reg_imm`, `fallback_memory_operation` (core.h). These symbols are already in scope — you **MUST** call them directly.

You **MUST NOT** declare a local variable with the same name as a function parameter. The `generate_*` functions always receive `struct buffer *b` as their first parameter — you are **EXPRESSLY PROHIBITED** from declaring any local variable named `b` inside these functions. For EVEX bit-field variables, you **MUST** use names like `broadcast`, `broadcast_bit`, or `evex_b_bit`. Shadowing causes the compiler to treat all subsequent uses of the name as the local type (e.g. `uint8_t`), silently breaking every `buffer_write_byte(b, ...)` call that follows.

`void register_{base_name}_strategies(void)` **MUST** call `register_strategy(&strategy_struct_name)` for every `strategy_t` defined in the file — you **MUST NOT** leave any strategy unregistered.
</hard_constraints>

<task>
GENERATE exactly two files delimited by the sentinel strings below.
The header file template is provided — reproduce it exactly.
The source file **MUST** be complete, correct, and compile without errors or warnings under GCC with -Wall -Wextra.
</task>

{_H_START}
/*
 * {base_name}_strategies.h
 * Auto-generated by BYVALVER CodeGenerationAgent
 */
#ifndef {base_name.upper()}_STRATEGIES_H
#define {base_name.upper()}_STRATEGIES_H

void register_{base_name}_strategies(void);

#endif /* {base_name.upper()}_STRATEGIES_H */
{_H_END}

{_C_START}
/* Complete .c implementation here */
{_C_END}"""

            response = await self.call_llm(
                prompt=prompt,
                max_tokens=6000,
                temperature=0.15,
            )

            # Extract header and source from delimited response
            header_content = _extract_between(response, _H_START, _H_END)
            source_content = _extract_between(response, _C_START, _C_END)

            # Fallback: pull from code fences if sentinels weren't respected
            if not header_content or not source_content:
                blocks = re.findall(r"```(?:c|cpp)?\n(.*?)```", response, re.DOTALL)
                if len(blocks) >= 1:
                    header_content = header_content or blocks[0].strip()
                if len(blocks) >= 2:
                    source_content = source_content or blocks[1].strip()

            if not header_content:
                header_content = _minimal_header(base_name)

            generated = {
                "base_name": base_name,
                "strategy_name": strategy_name,
                "header_filename": f"{base_name}_strategies.h",
                "source_filename": f"{base_name}_strategies.c",
                "header_content": header_content,
                "source_content": source_content,
                "arch_macro": arch_macro,
                "priority": proposal.get("priority", 80),
                "raw_response": response,
            }

            self.save_artifact(generated, "generated_code")
            print(
                f"[CodeGenerationAgent] Generated {base_name}_strategies.h "
                f"({len(header_content)} chars) and .c ({len(source_content)} chars)"
            )

            return {
                "status": "success",
                "findings": (
                    f"Generated {base_name}_strategies.h ({len(header_content)} chars) "
                    f"and {base_name}_strategies.c ({len(source_content)} chars)"
                ),
                "generated": generated,
                "artifacts": self.artifacts,
                "metadata": {
                    "task": task,
                    "base_name": base_name,
                    "model": self.config.get("model"),
                    "provider": self.config.get("provider", "anthropic"),
                },
            }

        except Exception as e:
            print(f"[CodeGenerationAgent] Error: {e}")
            return {
                "status": "error",
                "error": str(e),
                "findings": None,
                "artifacts": [],
            }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_between(text: str, start_sentinel: str, end_sentinel: str) -> str:
    """Return the text between two sentinel strings, stripped."""
    if start_sentinel in text and end_sentinel in text:
        return text.split(start_sentinel, 1)[1].split(end_sentinel, 1)[0].strip()
    return ""


def _minimal_header(base_name: str) -> str:
    guard = f"{base_name.upper()}_STRATEGIES_H"
    return (
        f"#ifndef {guard}\n"
        f"#define {guard}\n\n"
        f"void register_{base_name}_strategies(void);\n\n"
        f"#endif /* {guard} */\n"
    )
