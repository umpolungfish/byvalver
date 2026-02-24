"""
Example 3: Sequential Pipeline Execution (Async)

Demonstrates:
- Running agents sequentially using asyncio
- Context passing between stages
- Pipeline orchestration
"""
import sys
import asyncio
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from framework import AgentOrchestrator
from agents.example_agent import ResearchAgent, AnalysisAgent


async def main():
    """Run agents in a sequential pipeline (Async)"""

    # 1. Create configuration
    config = {
        "provider": "anthropic",
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 4000,
        "temperature": 0.7
    }

    orchestrator_config = {
        "max_concurrent_agents": 1,
        "timeout": 300
    }

    # 2. Initialize orchestrator
    print("Initializing Pipeline Orchestrator...")
    orchestrator = AgentOrchestrator(orchestrator_config)

    # 3. Register agents
    print("Registering agents...")
    orchestrator.register_agent("researcher", ResearchAgent(config))
    orchestrator.register_agent("analyzer", AnalysisAgent(config))

    # 4. Define task and initial context
    task = "Investigate best practices for building multi-agent AI systems"
    initial_context = {
        "focus_areas": ["architecture", "coordination", "scalability"]
    }

    # 5. Run pipeline (Awaited)
    print(f"\nRunning pipeline with task: {task}\n")
    print("Stage 1: Research")
    print("Stage 2: Analysis")
    print()

    result = await orchestrator.run_pipeline(
        task=task,
        agent_ids=["researcher", "analyzer"],
        initial_context=initial_context
    )

    # 6. Display pipeline results
    print("\n" + "=" * 60)
    print("PIPELINE RESULTS")
    print("=" * 60)
    print(f"Status: {result['status']}")
    print(f"Stages completed: {result.get('stages_completed', 0)}")

    if result['status'] == 'success':
        print("\nPipeline Execution:")
        print("-" * 60)

        for stage in result['pipeline_results']:
            print(f"\nStage {stage['stage']}: {stage['agent_id']}")
            stage_result = stage['result']
            print(f"  Status: {stage_result['status']}")

            if stage_result['status'] == 'success':
                findings = stage_result['findings'][:300] + "..."
                print(f"  Findings: {findings}")
                print(f"  Artifacts: {len(stage_result.get('artifacts', []))}")
            else:
                print(f"  Error: {stage_result.get('error', 'Unknown')}")

        # Display final context (accumulated data from all stages)
        print("\n" + "=" * 60)
        print("FINAL CONTEXT (Available for next stage)")
        print("=" * 60)
        final_context = result.get('final_context', {})
        print(f"Previous agent: {final_context.get('previous_agent')}")
        print(f"Context keys: {list(final_context.keys())}")

    else:
        print(f"\nPipeline failed at stage {result.get('failed_at_stage', 'unknown')}")


if __name__ == "__main__":
    # Ensure ANTHROPIC_API_KEY is set
    import os
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY environment variable not set")
        sys.exit(1)

    asyncio.run(main())
