"""
Technique Proposal Agent
Analyses the existing strategy catalog and proposes a genuinely novel bad-byte
elimination technique that is not yet implemented in BYVALVER.
Uses the AjintK BaseAgent template.
"""
import sys
import json
import re
import secrets
from pathlib import Path
from typing import Dict, List, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / "AjintK"))

from framework import BaseAgent, ToolDefinitions


class TechniqueProposalAgent(BaseAgent):
    """
    Given an existing strategy catalog from StrategyDiscoveryAgent, proposes
    one novel bad-byte elimination strategy by reasoning about uncovered x86/x64
    instruction families and encoding quirks.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="technique_proposal_agent",
            name="Technique Proposal Agent",
            description="Proposes a novel bad-byte elimination strategy not already in BYVALVER",
            capabilities=[
                "Strategy gap analysis",
                "Novel technique ideation",
                "x86/x64 instruction encoding knowledge",
                "Shellcode engineering",
            ],
            config=config,
        )

    def get_tools(self) -> List[Dict[str, Any]]:
        return [
            ToolDefinitions.file_read(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        print("[TechniqueProposalAgent] Proposing novel technique...")

        # Extract catalog from context (supports both direct and pipeline context shapes)
        catalog: Dict[str, Any] = {}
        covered_summary: str = ""

        if context:
            catalog = context.get("catalog", {})
            covered_summary = context.get("findings", "")
            if not catalog and "previous_stage" in context:
                prev = context["previous_stage"]
                catalog = prev.get("catalog", {})
                covered_summary = prev.get("findings", "")

        categories = catalog.get("strategy_categories", [])
        active_categories = catalog.get("active_categories", [])
        strategy_names = catalog.get("strategy_names", [])
        llm_summary = catalog.get("llm_summary", "")
        arch_hint = (context or {}).get("arch", "both")

        # Narrow down categories to include in the prompt (avoid token overflow)
        all_cats = sorted(set(categories + active_categories))

        # Cache-busting nonce — ensures each run produces a unique prompt hash
        nonce = secrets.token_hex(8)

        # Format the explicit strategy name blacklist (capped to avoid token overflow)
        blacklist_lines = "\n".join(f"  {n}" for n in sorted(strategy_names)[:200])

        # Pull notable_gaps from LLM summary if available
        notable_gaps_text = ""
        if llm_summary:
            try:
                cleaned_summary = re.sub(r"```json|```", "", llm_summary).strip()
                s = cleaned_summary.index("{")
                e = cleaned_summary.rindex("}") + 1
                summary_obj = json.loads(cleaned_summary[s:e])
                gaps = summary_obj.get("notable_gaps", [])
                if gaps:
                    notable_gaps_text = "\n".join(f"  - {g}" for g in gaps[:15])
            except (ValueError, json.JSONDecodeError):
                pass

        prompt = f"""<role>
You are an expert x86/x64 shellcode engineer. Your specialisation is **bad-byte and null-byte elimination** at the machine-code level. You have deep knowledge of x86/x64 instruction encoding: opcodes, prefixes, ModR/M, SIB, REX, VEX, EVEX, displacement fields, and immediate fields.
</role>

<system_context>
BYVALVER rewrites shellcode one instruction at a time. Each transformation strategy implements three functions:
  can_handle(cs_insn*)  — returns 1 if the strategy applies to this instruction
  get_size(cs_insn*)    — returns the upper-bound byte count of the replacement
  generate(buffer*, cs_insn*) — writes the null-byte-free replacement bytes
</system_context>

<existing_coverage>
<categories total="{len(all_cats)}">
{chr(10).join(f'  {c}' for c in all_cats[:90])}
</categories>
<implemented_strategy_names total="{len(strategy_names)}">
**Every name listed below is ALREADY IMPLEMENTED. The `strategy_name` you propose MUST NOT match any of these.**
{blacklist_lines}
</implemented_strategy_names>
{f'<notable_gaps>{chr(10)}{notable_gaps_text}{chr(10)}</notable_gaps>' if notable_gaps_text else ''}
<target_arch>{arch_hint}</target_arch>
</existing_coverage>

<constraints>
**UNIQUENESS** — The `strategy_name` field **MUST NOT** match any name in `<implemented_strategy_names>` above.
**IMPLEMENTABILITY** — The proposed strategy **MUST** be implementable as a `can_handle` / `get_size` / `generate` triplet.
**NULL-FREE OUTPUT** — The `generate` output **MUST** contain **ZERO null bytes (0x00)** and zero bad bytes.
**ARCHITECTURE** — The `architecture` field **MUST** be exactly one of: `x86`, `x64`, or `both`.
**NOVELTY** — The strategy **MUST NOT** duplicate any category or technique family already listed above.
</constraints>

<ideation_axes>
CONSIDER these dimensions — but **ONLY if not already covered above**:
- Instruction fields that carry bad bytes in unusual positions (prefix bytes, escape bytes, secondary opcode maps)
- REX prefix bit manipulation to rearrange ModR/M register encoding and avoid bad byte values
- Operand-size or address-size prefix (0x66 / 0x67) used to shift the byte layout of an instruction
- Two-instruction carry/borrow propagation sequences as arithmetic alternatives
- EFLAGS manipulation idioms (LAHF/SAHF, PUSHF/POPF combinations) not yet covered
- BOUND / ENTER / LEAVE alternative encodings with non-null operands
- String-instruction prefix overloading (REPNE on non-string opcodes)
- FPU control-word manipulation (FSTCW/FLDCW) as an integer-value carrier
- BMI1/BMI2 instructions (ANDN, BLSI, BLSR, BEXTR, PEXT, PDEP) for bitmask construction
- XCHG-based register rotation to avoid bad-byte register encodings
- TEST/BT instruction variants where the immediate field carries bad bytes
- LOOP / LOOPcc as alternative branching encodings
- IMUL 3-operand form for constant multiplication without MOV + MUL
- IN/OUT port I/O instructions for value construction in ring-3-accessible contexts
</ideation_axes>

<task>
PROPOSE **EXACTLY ONE** novel bad-byte elimination strategy not covered by the existing categories or strategy names.
SELECT a technique that is maximally different from all listed implemented strategies.
</task>
<!-- run-nonce: {nonce} -->

<output_format>
RESPOND with a **single raw JSON object** — no markdown fences, no prose outside the object:
{{
  "strategy_name": "descriptive_snake_case_strategies",
  "display_name": "Human-Readable Strategy Name",
  "description": "One to two sentences stating exactly what this strategy does.",
  "target_instruction": "x86 mnemonic(s) targeted, e.g. MOV, PUSH, ADD",
  "approach": "Precise technical description of the byte-level substitution, including which fields are affected and how.",
  "architecture": "x86 | x64 | both",
  "priority": <integer 70-95>,
  "rationale": "Specific explanation of why this is novel and not covered by the listed categories.",
  "example_transformation": "Before: <hex bytes> <mnemonic>. After: <hex bytes> <equivalent sequence>."
}}
</output_format>"""

        try:
            response = await self.call_llm(
                prompt=prompt,
                max_tokens=2000,
                temperature=0.85,
            )

            # Extract JSON from the response
            proposal: Dict[str, Any] = {}
            try:
                # Strip markdown fences if present
                cleaned = re.sub(r"```json|```", "", response).strip()
                # Find first { ... }
                start = cleaned.index("{")
                end = cleaned.rindex("}") + 1
                proposal = json.loads(cleaned[start:end])
            except (ValueError, json.JSONDecodeError) as parse_err:
                print(f"[TechniqueProposalAgent] JSON parse warning: {parse_err}; storing raw response")
                proposal = {"raw_proposal": response}

            self.save_artifact(proposal, "technique_proposal")
            print(f"[TechniqueProposalAgent] Proposed: {proposal.get('display_name', 'Unknown')}")
            print(f"[TechniqueProposalAgent] Description: {proposal.get('description', '')}")

            return {
                "status": "success",
                "findings": response,
                "proposal": proposal,
                "artifacts": self.artifacts,
                "metadata": {
                    "task": task,
                    "strategy_name": proposal.get("strategy_name", "unknown"),
                    "model": self.config.get("model"),
                    "provider": self.config.get("provider", "anthropic"),
                },
            }

        except Exception as e:
            print(f"[TechniqueProposalAgent] Error: {e}")
            return {
                "status": "error",
                "error": str(e),
                "findings": None,
                "artifacts": [],
            }
