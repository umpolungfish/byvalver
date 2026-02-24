"""
Strategy Discovery Agent
Scans the BYVALVER src/ directory to catalog all existing implemented strategies.
Uses the AjintK BaseAgent template.
"""
import sys
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / "AjintK"))

from framework import BaseAgent, ToolDefinitions


class StrategyDiscoveryAgent(BaseAgent):
    """
    Catalogs all existing BYVALVER bad-byte elimination strategies by scanning src/.
    Reads the strategy registry to extract category names, strategy counts, and
    interface details needed by downstream agents.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="strategy_discovery_agent",
            name="Strategy Discovery Agent",
            description="Catalogs all existing BYVALVER bad-byte elimination strategies by scanning src/",
            capabilities=[
                "File system scanning",
                "Strategy name extraction",
                "Category analysis",
                "Registry parsing",
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
        print(f"[StrategyDiscoveryAgent] Scanning {self.src_dir} for existing strategies...")

        try:
            # 1. List all strategy .c source files
            ls_result = await self.tool_executor.execute_tool("run_command", {
                "command": f"ls {self.src_dir}/*.c 2>/dev/null | sort"
            })
            source_files = [f.strip() for f in ls_result.split("\n") if f.strip().endswith(".c")]

            # 2. Read strategy_registry.c to extract categories
            registry_path = str(self.src_dir / "strategy_registry.c")
            registry_content = await self.tool_executor.execute_tool("file_read", {
                "path": registry_path
            })

            # Parse #include lines for strategy headers
            includes = re.findall(r'#include "([^"]+_strategies\.h)"', registry_content)

            # Parse all register_* forward declarations (these are the strategy categories)
            forward_decls = list(dict.fromkeys(
                re.findall(r'void register_(\w+)\(\)', registry_content)
            ))

            # Parse active (non-commented) registration calls inside init_strategies
            active_calls = re.findall(r'^\s+register_(\w+)\(\)', registry_content, re.MULTILINE)

            # 3. Extract all individual strategy names from .name = "..." in C files
            grep_result = await self.tool_executor.execute_tool("run_command", {
                "command": (
                    f'grep -rh \'.name = "\' {self.src_dir}/ --include="*.c" '
                    '| grep -o \'"[^"]*"\' | tr -d \'"\' | sort | uniq'
                )
            })
            strategy_names = [n.strip() for n in grep_result.split("\n") if n.strip()]

            # 4. Read the strategy interface for downstream reference
            strategy_h = await self.tool_executor.execute_tool("file_read", {
                "path": str(self.src_dir / "strategy.h")
            })

            # 5. Read utils.h header section for available helpers
            utils_h = await self.tool_executor.execute_tool("file_read", {
                "path": str(self.src_dir / "utils.h")
            })

            # 6. Read a canonical example implementation for code gen reference
            example_c = await self.tool_executor.execute_tool("file_read", {
                "path": str(self.src_dir / "mov_strategies.c")
            })

            catalog = {
                "source_files": source_files,
                "strategy_categories": forward_decls,
                "active_categories": active_calls,
                "strategy_names": strategy_names,
                "strategy_interface": strategy_h,
                "utils_header": utils_h,
                "example_implementation": example_c,
                "registry_includes": includes,
                "total_strategies": len(strategy_names),
                "total_categories": len(forward_decls),
            }

            # 7. Summarise with LLM for the proposal agent
            summary_prompt = f"""<role>
You are a BYVALVER strategy corpus analyst. BYVALVER is a shellcode bad-byte (null/restricted byte) elimination tool that rewrites x86/x64 instructions using a ranked registry of transformation strategies.
</role>

<corpus>
<strategy_categories total="{len(forward_decls)}">
{chr(10).join(f'  {c}' for c in forward_decls[:80])}
</strategy_categories>
<counts>
  <individual_strategies>{len(strategy_names)}</individual_strategies>
  <source_files>{len(source_files)}</source_files>
</counts>
</corpus>

<task>
PRODUCE a concise structured JSON summary of the technique families already covered.
ORGANIZE by approach type: MOV variants, arithmetic transforms, PEB/API resolution, stack construction, flag manipulation, SIMD/FPU, bit operations, encoding tricks, etc.
</task>

<output_format>
RESPOND with a **JSON object only** — no prose, no markdown fences — with exactly these keys:
- "covered_families": array of technique family name strings
- "approach_summary": 2–3 sentence description of overall coverage breadth
- "notable_gaps": array of x86/x64 technique areas **NOT YET COVERED**
</output_format>"""

            llm_summary = await self.call_llm(
                prompt=summary_prompt,
                max_tokens=1500,
                temperature=0.3,
            )
            catalog["llm_summary"] = llm_summary

            self.save_artifact(catalog, "strategy_catalog")
            print(
                f"[StrategyDiscoveryAgent] Cataloged {len(strategy_names)} strategies "
                f"across {len(forward_decls)} categories in {len(source_files)} files"
            )

            return {
                "status": "success",
                "findings": llm_summary,
                "catalog": catalog,
                "artifacts": self.artifacts,
                "metadata": {
                    "task": task,
                    "strategy_count": len(strategy_names),
                    "file_count": len(source_files),
                    "category_count": len(forward_decls),
                    "model": self.config.get("model"),
                    "provider": self.config.get("provider", "anthropic"),
                },
            }

        except Exception as e:
            print(f"[StrategyDiscoveryAgent] Error: {e}")
            return {
                "status": "error",
                "error": str(e),
                "findings": None,
                "artifacts": [],
            }
