#!/usr/bin/env python3
"""
BYVALVER Auto-Technique Generator
===================================
Runs a four-stage agent pipeline that:
  1. Discovers every existing bad-byte elimination strategy in src/
  2. Proposes a genuinely novel technique not yet implemented
  3. Generates complete C implementation (.h + .c)
  4. Writes files, patches strategy_registry.c, and verifies the build

Usage:
    python run_technique_generator.py [options]

Options:
    --dry-run       Stop after Stage 2 — print proposal without writing any files
    --arch          Target architecture hint: x86 | x64 | both  (default: both)
    --model         Claude model ID (default: claude-sonnet-4-6)
    --verbose       Print full LLM responses at each stage

Requires:
    ANTHROPIC_API_KEY environment variable
    pip install anthropic tenacity httpx pyyaml
"""
import asyncio
import argparse
import json
import os
import sys
from pathlib import Path

# Ensure project root and AjintK framework are importable
_ROOT = Path(__file__).parent
sys.path.insert(0, str(_ROOT / "AjintK"))
sys.path.insert(0, str(_ROOT))  # must be first so byvalver/agents/ wins over AjintK/agents/

from agents.strategy_discovery_agent import StrategyDiscoveryAgent
from agents.technique_proposal_agent import TechniqueProposalAgent
from agents.code_generation_agent import CodeGenerationAgent
from agents.implementation_agent import ImplementationAgent


def _banner(text: str) -> None:
    width = 60
    print("\n" + "=" * width)
    print(f"  {text}")
    print("=" * width)


def _section(stage: int, total: int, label: str) -> None:
    print(f"\n[{stage}/{total}] {label}...")


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="BYVALVER Auto-Technique Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Propose but do not generate or write any code")
    parser.add_argument("--arch", choices=["x86", "x64", "both"], default="both",
                        help="Target architecture hint passed to the proposal agent")
    parser.add_argument("--provider", default="anthropic",
                        choices=["anthropic", "deepseek", "qwen", "mistral", "google"],
                        help="LLM provider to use (default: anthropic)")
    parser.add_argument("--model", default=None,
                        help="Model ID (defaults per provider: anthropic=claude-sonnet-4-6, deepseek=deepseek-chat)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print full LLM responses at each stage")
    args = parser.parse_args()

    # Default models per provider
    _default_models = {
        "anthropic": "claude-sonnet-4-6",
        "deepseek":  "deepseek-chat",
        "qwen":      "qwen3-max",
        "mistral":   "codestral-2508",
        "google":    "gemini-pro",
    }
    model = args.model or _default_models.get(args.provider, "deepseek-chat")

    # Validate API key for chosen provider
    key_var = f"{args.provider.upper()}_API_KEY"
    if not os.environ.get(key_var):
        print(f"ERROR: {key_var} environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    config = {
        "provider": args.provider,
        "model": model,
        "max_tokens": 8000,
    }

    TOTAL_STAGES = 2 if args.dry_run else 4

    _banner("BYVALVER Auto-Technique Generator")
    print(f"  Provider: {args.provider}")
    print(f"  Model   : {model}")
    print(f"  Arch    : {args.arch}")
    print(f"  Dry run : {args.dry_run}")

    # -----------------------------------------------------------------------
    # Stage 1 — Discovery
    # -----------------------------------------------------------------------
    _section(1, TOTAL_STAGES, "Discovering existing strategies")
    discovery_agent = StrategyDiscoveryAgent(config)
    discovery_result = await discovery_agent.run(
        task="Catalog all existing BYVALVER bad-byte elimination strategies",
        context={"arch": args.arch},
    )

    if discovery_result["status"] != "success":
        print(f"\nERROR: Discovery failed — {discovery_result.get('error')}", file=sys.stderr)
        sys.exit(1)

    meta = discovery_result["metadata"]
    print(f"  Found {meta['strategy_count']} strategies in "
          f"{meta['file_count']} files across {meta['category_count']} categories")

    if args.verbose:
        print("\n--- Discovery findings ---")
        print(discovery_result.get("findings", ""))

    # -----------------------------------------------------------------------
    # Stage 2 — Proposal
    # -----------------------------------------------------------------------
    _section(2, TOTAL_STAGES, "Proposing novel technique")
    proposal_agent = TechniqueProposalAgent(config)
    proposal_result = await proposal_agent.run(
        task=(
            f"Propose a novel bad-byte elimination strategy for {args.arch} "
            "targeting gaps in existing coverage"
        ),
        context={
            "catalog": discovery_result.get("catalog", {}),
            "findings": discovery_result.get("findings", ""),
            "arch": args.arch,
        },
    )

    if proposal_result["status"] != "success":
        print(f"\nERROR: Proposal failed — {proposal_result.get('error')}", file=sys.stderr)
        sys.exit(1)

    proposal = proposal_result.get("proposal", {})
    print(f"  Strategy : {proposal.get('strategy_name', '?')}")
    print(f"  Name     : {proposal.get('display_name', '?')}")
    print(f"  Targets  : {proposal.get('target_instruction', '?')}")
    print(f"  Arch     : {proposal.get('architecture', '?')}")
    print(f"  Priority : {proposal.get('priority', '?')}")
    print(f"  Approach : {proposal.get('approach', '')[:120]}...")

    if args.verbose:
        print("\n--- Full proposal ---")
        print(json.dumps(proposal, indent=2))

    if args.dry_run:
        _banner("Dry-run complete — no files written")
        print(json.dumps(proposal, indent=2))
        return

    # -----------------------------------------------------------------------
    # Stage 3 — Code Generation
    # -----------------------------------------------------------------------
    _section(3, TOTAL_STAGES, "Generating C implementation")
    codegen_agent = CodeGenerationAgent(config)
    codegen_result = await codegen_agent.run(
        task="Generate complete C implementation for the proposed strategy",
        context={
            "proposal": proposal,
            "catalog": discovery_result.get("catalog", {}),
            "arch": args.arch,
        },
    )

    if codegen_result["status"] != "success":
        print(f"\nERROR: Code generation failed — {codegen_result.get('error')}", file=sys.stderr)
        sys.exit(1)

    generated = codegen_result.get("generated", {})
    print(f"  Header : {generated.get('header_filename')} "
          f"({len(generated.get('header_content', ''))} chars)")
    print(f"  Source : {generated.get('source_filename')} "
          f"({len(generated.get('source_content', ''))} chars)")

    if args.verbose:
        print("\n--- Generated header ---")
        print(generated.get("header_content", ""))
        print("\n--- Generated source ---")
        print(generated.get("source_content", ""))

    # -----------------------------------------------------------------------
    # Stage 4 — Implementation
    # -----------------------------------------------------------------------
    _section(4, TOTAL_STAGES, "Writing files and registering strategy")
    impl_agent = ImplementationAgent(config)
    impl_result = await impl_agent.run(
        task="Write strategy files, patch registry, and verify build",
        context={
            "generated": generated,
            "proposal": proposal,
        },
    )

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    _banner("Result")

    if impl_result.get("build_success"):
        print(f"  SUCCESS: '{generated.get('base_name')}' implemented and compiled!")
        for f in impl_result.get("files_written", []):
            print(f"    Wrote: {f}")
        print(f"  Patches: {impl_result.get('patch_summary', '')}")
    elif impl_result.get("status") == "build_failed":
        print(f"  PARTIAL: Files written but build failed (C errors in generated code).")
        print(f"  Patches: {impl_result.get('patch_summary', '')}")
        print("\n  Build errors (tui/ permission errors excluded — pre-existing issue):")
        for line in impl_result.get("build_output", "").splitlines():
            if "error:" in line.lower() and "tui" not in line and "Permission denied" not in line:
                print(f"    {line}")
        sys.exit(2)
    else:
        print(f"  ERROR: {impl_result.get('error', 'Unknown error')}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
