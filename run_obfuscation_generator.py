#!/usr/bin/env python3
"""
BYVALVER Obfuscation Technique Generator
========================================
Runs a four-stage agent pipeline to:
  1. Discover existing obfuscation strategies
  2. Propose a novel obfuscation technique
  3. Generate complete C implementation
  4. Write files, patch registry, and verify build

Usage:
    python run_obfuscation_generator.py [options]
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
sys.path.insert(0, str(_ROOT))

from agents.strategy_discovery_agent import StrategyDiscoveryAgent
from agents.technique_proposal_agent import TechniqueProposalAgent
from agents.code_generation_agent import CodeGenerationAgent
from agents.implementation_agent import ImplementationAgent


def _banner(text: str) -> None:
    width = 60
    print("
" + "=" * width)
    print(f"  {text}")
    print("=" * width)


def _section(stage: int, total: int, label: str) -> None:
    print(f"
[{stage}/{total}] {label}...")


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="BYVALVER Obfuscation Technique Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Propose but do not generate or write any code")
    parser.add_argument("--arch", choices=["x86", "x64", "both"], default="both",
                        help="Target architecture hint")
    parser.add_argument("--provider", default="anthropic",
                        choices=["anthropic", "deepseek", "qwen", "mistral", "google"],
                        help="LLM provider")
    parser.add_argument("--model", default=None,
                        help="Model ID")
    parser.add_argument("--verbose", action="store_true",
                        help="Print full LLM responses")
    args = parser.parse_args()

    # Default models per provider
    _default_models = {
        "anthropic": "claude-sonnet-4-6",
        "deepseek":  "deepseek-chat",
        "qwen":      "qwen3-max",
        "mistral":   "codestral-2508",
        "google":    "gemini-3-flash-preview",
    }
    model = args.model or _default_models.get(args.provider, "deepseek-chat")

    # Validate API key
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

    _banner("BYVALVER Obfuscation Technique Generator")
    print(f"  Provider: {args.provider}")
    print(f"  Model   : {model}")
    print(f"  Arch    : {args.arch}")

    # -----------------------------------------------------------------------
    # Stage 1 — Discovery
    # -----------------------------------------------------------------------
    _section(1, TOTAL_STAGES, "Discovering existing strategies")
    discovery_agent = StrategyDiscoveryAgent(config)
    discovery_result = await discovery_agent.run(
        task="Catalog existing obfuscation strategies",
        context={"mode": "obfuscation", "arch": args.arch},
    )

    if discovery_result["status"] != "success":
        print(f"
ERROR: Discovery failed — {discovery_result.get('error')}", file=sys.stderr)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Stage 2 — Proposal
    # -----------------------------------------------------------------------
    _section(2, TOTAL_STAGES, "Proposing novel obfuscation")
    proposal_agent = TechniqueProposalAgent(config)
    proposal_result = await proposal_agent.run(
        task=f"Propose a novel obfuscation strategy for {args.arch}",
        context={
            "mode": "obfuscation",
            "catalog": discovery_result.get("catalog", {}),
            "findings": discovery_result.get("findings", ""),
            "arch": args.arch,
        },
    )

    if proposal_result["status"] != "success":
        print(f"
ERROR: Proposal failed — {proposal_result.get('error')}", file=sys.stderr)
        sys.exit(1)

    proposal = proposal_result.get("proposal", {})
    print(f"  Strategy : {proposal.get('strategy_name', '?')}")
    print(f"  Name     : {proposal.get('display_name', '?')}")
    print(f"  Approach : {proposal.get('approach', '')[:120]}...")

    if args.dry_run:
        _banner("Dry-run complete")
        return

    # -----------------------------------------------------------------------
    # Stage 3 — Code Generation
    # -----------------------------------------------------------------------
    _section(3, TOTAL_STAGES, "Generating C implementation")
    codegen_agent = CodeGenerationAgent(config)
    codegen_result = await codegen_agent.run(
        task="Generate C implementation for the proposed obfuscation",
        context={
            "mode": "obfuscation",
            "proposal": proposal,
            "catalog": discovery_result.get("catalog", {}),
            "arch": args.arch,
        },
    )

    if codegen_result["status"] != "success":
        print(f"
ERROR: Code generation failed — {codegen_result.get('error')}", file=sys.stderr)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Stage 4 — Implementation
    # -----------------------------------------------------------------------
    _section(4, TOTAL_STAGES, "Writing files and registering strategy")
    impl_agent = ImplementationAgent(config)
    impl_result = await impl_agent.run(
        task="Write files and verify build",
        context={
            "generated": codegen_result.get("generated", {}),
            "proposal": proposal,
        },
    )

    _banner("Result")
    if impl_result.get("build_success"):
        print(f"  SUCCESS: Obfuscation technique implemented!")
    else:
        print(f"  ERROR: {impl_result.get('error', 'Build failed')}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
