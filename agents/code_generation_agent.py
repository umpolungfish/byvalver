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
**ARCHITECTURE ENUM** — The `.target_arch` field **MUST** be one of:
  BYVAL_ARCH_X86   (use this for strategies that target x86 OR both x86 and x64)
  BYVAL_ARCH_X64   (use this only for x64-exclusive strategies)
  **BYVAL_ARCH_BOTH DOES NOT EXIST** — using it causes a compile error.

**NULL-BYTE PROHIBITION** — The `generate_*` function **MUST NOT** write 0x00 to the output buffer under any circumstances. Every literal byte value passed to buffer_write_byte() / buffer_write_word() / buffer_write_dword() **MUST** be non-zero.

**UNUSED PARAMETER SUPPRESSION** — Every function parameter that is not used in the body **MUST** be silenced with `(void)param_name;` immediately as the first line of the function.

**UNUSED VARIABLE SUPPRESSION** — Every local variable declared but not subsequently read **MUST** be removed entirely. Dead declarations are a compile warning and indicate incorrect logic.

**UNUSED FUNCTION SUPPRESSION** — Every `static` helper function defined in the file **MUST** be called at least once. Static functions that are never called **MUST** be deleted — do not define helper functions speculatively.

**CORRECT CAPSTONE ACCESS** — Access instruction fields only via: insn->id, insn->detail->x86.operands[N], insn->detail->x86.op_count, insn->detail->x86.operands[N].type, insn->detail->x86.operands[N].reg, insn->detail->x86.operands[N].imm.

**VERIFIED CAPSTONE CONSTANTS ONLY** — Every `X86_INS_*` constant used in a `switch` or `if` **MUST** exist in the installed Capstone headers. Do **NOT** invent or guess instruction ID names (e.g. `X86_INS_VRCPPD` does not exist — use only constants you are certain are defined). When unsure, use `insn->id` comparisons against the known-good subset or omit the case entirely.

**SIZE ESTIMATE** — get_size_* **MUST** return a value strictly greater than or equal to the maximum number of bytes generate_* can ever write.

**REGISTRATION FUNCTION** — `void register_{base_name}_strategies(void)` **MUST** call `register_strategy(&strategy_struct_name)` for every strategy_t defined in the file.
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
