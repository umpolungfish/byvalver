"""
Example 2: Multi-Agent Swarm Execution (Async)

Demonstrates:
- Running multiple agents in parallel using asyncio
- Orchestrator usage (Async)
- Result aggregation
"""
import sys
import asyncio
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from framework import AgentOrchestrator
from agents.example_agent import ResearchAgent, AnalysisAgent


async def main():
    """Run multiple agents in parallel (swarm mode - Async)"""

    # 1. Create configuration
    config = {
        "provider": "anthropic",
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 4000,
        "temperature": 0.7
    }

    orchestrator_config = {
        "max_concurrent_agents": 5,
        "timeout": 300
    }

    # 2. Initialize orchestrator
    print("Initializing Agent Orchestrator...")
    orchestrator = AgentOrchestrator(orchestrator_config)

    # 3. Register agents
    print("Registering agents...")
    orchestrator.register_agent("researcher_1", ResearchAgent(config))
    orchestrator.register_agent("researcher_2", ResearchAgent(config))
    orchestrator.register_agent("analyzer", AnalysisAgent(config))

    # 4. Define task
    task = "Analyze the current state of AI agent frameworks and their applications"

    # 5. Run swarm (Awaited)
    print(f"\nRunning swarm with task: {task}\n")
    print("All agents will execute in parallel using asyncio...\n")

    result = await orchestrator.run_swarm(
        task=task,
        agent_ids=["researcher_1", "researcher_2", "analyzer"]
    )

    # 6. Display aggregated results
    print("\n" + "=" * 60)
    print("SWARM RESULTS")
    print("=" * 60)
    print(f"Agents run: {result['agents_run']}")
    print(f"Successful: {result['successful']}")
    print(f"Failed: {result['failed']}")

    print("\nIndividual Agent Results:")
    print("-" * 60)
    for agent_id, agent_result in result['results'].items():
        print(f"\n{agent_id.upper()}:")
        print(f"  Status: {agent_result['status']}")
        if agent_result['status'] == 'success':
            findings_preview = agent_result['findings'][:200] + "..."
            print(f"  Findings: {findings_preview}")
            print(f"  Artifacts: {len(agent_result.get('artifacts', []))}")
        else:
            print(f"  Error: {agent_result.get('error', 'Unknown')}")


if __name__ == "__main__":
    # Ensure ANTHROPIC_API_KEY is set
    import os
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY environment variable not set")
        sys.exit(1)

    asyncio.run(main())
