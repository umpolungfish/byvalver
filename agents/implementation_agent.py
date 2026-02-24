"""
Implementation Agent
Writes generated C strategy files to src/, patches strategy_registry.c with
the include/forward-declaration/registration-call triple, then verifies the build.
Uses the AjintK BaseAgent template.
"""
import sys
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / "AjintK"))

from framework import BaseAgent, ToolDefinitions

# Patch anchors — must match exactly what is in strategy_registry.c
_INCLUDE_ANCHOR = '#include <stdlib.h>'
_FORWARD_DECL_ANCHOR = 'void init_strategies(int use_ml, byval_arch_t arch)'
_REGISTER_ANCHOR = '    register_remaining_null_elimination_strategies();'


class ImplementationAgent(BaseAgent):
    """
    Writes the generated .h and .c files into src/, then performs three targeted
    patches to strategy_registry.c:
      1. Adds a #include for the new header (before <stdlib.h>)
      2. Adds a forward declaration (before init_strategies())
      3. Adds the register_*() call (before register_remaining_null_elimination_strategies())
    Finally runs `make` and reports the result.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="implementation_agent",
            name="Implementation Agent",
            description="Writes strategy files, patches the registry, and verifies compilation",
            capabilities=[
                "File writing",
                "Registry patching",
                "Build verification",
                "Error analysis",
            ],
            config=config,
        )
        self.src_dir = Path(__file__).parent.parent / "src"
        self.project_root = Path(__file__).parent.parent

    def get_tools(self) -> List[Dict[str, Any]]:
        return [
            ToolDefinitions.file_read(),
            ToolDefinitions.file_write(),
            ToolDefinitions.run_command(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        print("[ImplementationAgent] Writing and registering new strategy...")

        # Unpack context
        generated: Dict[str, Any] = {}
        proposal: Dict[str, Any] = {}

        if context:
            generated = context.get("generated", {})
            proposal = context.get("proposal", {})
            if not generated and "previous_stage" in context:
                prev = context["previous_stage"]
                generated = prev.get("generated", {})
                proposal = prev.get("proposal", {})

        # Validate we have the minimum required fields
        base_name = generated.get("base_name", "")
        header_content = generated.get("header_content", "")
        source_content = generated.get("source_content", "")

        if not base_name:
            return _error("No base_name in generated context")
        if not header_content:
            return _error("No header_content in generated context")
        if not source_content:
            return _error("No source_content in generated context")

        header_path = str(self.src_dir / f"{base_name}_strategies.h")
        source_path = str(self.src_dir / f"{base_name}_strategies.c")

        try:
            # --- Step 1: Write header file ---
            await self.tool_executor.execute_tool("file_write", {
                "path": header_path,
                "content": header_content,
            })
            print(f"[ImplementationAgent] Wrote {header_path}")

            # --- Step 2: Write source file ---
            await self.tool_executor.execute_tool("file_write", {
                "path": source_path,
                "content": source_content,
            })
            print(f"[ImplementationAgent] Wrote {source_path}")

            # --- Step 3: Patch strategy_registry.c ---
            registry_path = str(self.src_dir / "strategy_registry.c")
            registry_content: str = await self.tool_executor.execute_tool("file_read", {
                "path": registry_path,
            })

            registry_content, patched_include = _patch_include(registry_content, base_name)
            registry_content, patched_decl = _patch_forward_decl(registry_content, base_name, generated)
            registry_content, patched_call = _patch_register_call(registry_content, base_name, generated)

            await self.tool_executor.execute_tool("file_write", {
                "path": registry_path,
                "content": registry_content,
            })

            patch_summary = (
                f"include={'added' if patched_include else 'already present'}, "
                f"forward_decl={'added' if patched_decl else 'already present'}, "
                f"register_call={'added' if patched_call else 'already present'}"
            )
            print(f"[ImplementationAgent] Patched strategy_registry.c ({patch_summary})")

            # --- Step 4: Build ---
            print("[ImplementationAgent] Running make...")
            build_output: str = await self.tool_executor.execute_tool("run_command", {
                "command": f"cd {self.project_root} && make 2>&1 | tail -40",
                "timeout": 120,
            })

            # Determine build success by checking for real C compilation errors,
            # filtering out the known pre-existing permission error on the root-owned
            # bin/tui/ directory which is unrelated to any strategy we generated.
            real_errors = [
                line for line in build_output.splitlines()
                if re.search(r"error:", line, re.IGNORECASE)
                and not re.search(r"bin/tui/|src/tui/|tui_\w+\.(c|o)", line)
                and "Permission denied" not in line
            ]
            build_success = len(real_errors) == 0

            if build_success:
                print("[ImplementationAgent] Build succeeded!")
            else:
                print(f"[ImplementationAgent] Build failed.\n{build_output}")

            self.save_artifact(
                {
                    "files_written": [header_path, source_path],
                    "patch_summary": patch_summary,
                    "build_output": build_output,
                    "build_success": build_success,
                },
                "implementation_result",
            )

            return {
                "status": "success" if build_success else "build_failed",
                "findings": (
                    f"Strategy '{base_name}' "
                    + ("successfully implemented and compiled." if build_success else "written but build failed.")
                    + f"\n\nPatch: {patch_summary}\n\nBuild output:\n{build_output}"
                ),
                "build_output": build_output,
                "build_success": build_success,
                "files_written": [header_path, source_path],
                "patch_summary": patch_summary,
                "artifacts": self.artifacts,
                "metadata": {
                    "task": task,
                    "base_name": base_name,
                    "model": self.config.get("model"),
                    "provider": self.config.get("provider", "anthropic"),
                },
            }

        except Exception as e:
            print(f"[ImplementationAgent] Error: {e}")
            return {
                "status": "error",
                "error": str(e),
                "findings": None,
                "artifacts": [],
            }


# ---------------------------------------------------------------------------
# Registry patching helpers
# ---------------------------------------------------------------------------

def _patch_include(content: str, base_name: str) -> tuple[str, bool]:
    """Insert #include "base_name_strategies.h" before #include <stdlib.h>."""
    line = f'#include "{base_name}_strategies.h"'
    if line in content:
        return content, False
    return content.replace(
        _INCLUDE_ANCHOR,
        f"{line}\n{_INCLUDE_ANCHOR}",
    ), True


def _patch_forward_decl(content: str, base_name: str, generated: Dict[str, Any]) -> tuple[str, bool]:
    """Insert a forward declaration before void init_strategies(...)."""
    signature = f"void register_{base_name}_strategies()"
    if signature in content:
        return content, False
    display = generated.get("strategy_name", base_name)
    decl = f"void register_{base_name}_strategies(); // Forward declaration - {display}"
    return content.replace(
        _FORWARD_DECL_ANCHOR,
        f"{decl}\n{_FORWARD_DECL_ANCHOR}",
    ), True


def _patch_register_call(content: str, base_name: str, generated: Dict[str, Any]) -> tuple[str, bool]:
    """Insert register_*() call before register_remaining_null_elimination_strategies()."""
    call_pattern = f"register_{base_name}_strategies()"
    if call_pattern in content:
        return content, False
    priority = generated.get("priority", 80)
    display = generated.get("strategy_name", base_name)
    call = f"    register_{base_name}_strategies();  // {display} (priority {priority})"
    return content.replace(
        _REGISTER_ANCHOR,
        f"{call}\n{_REGISTER_ANCHOR}",
    ), True


def _error(msg: str) -> Dict[str, Any]:
    return {"status": "error", "error": msg, "findings": None, "artifacts": []}
