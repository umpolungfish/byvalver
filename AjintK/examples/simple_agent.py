"""
Example 1: Simple Single Agent Execution (Async)

Demonstrates:
- Basic agent setup
- Running a single agent asynchronously
- Accessing results
"""
import sys
import asyncio
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.example_agent import ResearchAgent


async def main():
    """Run a single agent with a simple task (Async)"""

    # 1. Create agent configuration
    config = {
        "provider": "anthropic",
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 4000,
        "temperature": 0.7
    }

    # 2. Initialize agent
    print("Initializing Research Agent...")
    agent = ResearchAgent(config)

    # 3. Define task
    task = "Research the key features and benefits of multi-agent AI systems"

    # 4. Run agent (Awaited)
    print(f"\nRunning task: {task}\n")
    result = await agent.run(task)

    # 5. Display results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Status: {result['status']}")
    if result['status'] == 'success':
        print(f"\nFindings:\n{result['findings']}")
        print(f"\nArtifacts generated: {len(result['artifacts'])}")
    else:
        print(f"Error: {result.get('error')}")
    print(f"Metadata: {result.get('metadata', {})}")


if __name__ == "__main__":
    # Ensure ANTHROPIC_API_KEY is set in environment
    import os
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY environment variable not set")
        sys.exit(1)

    asyncio.run(main())
