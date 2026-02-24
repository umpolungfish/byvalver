# Quick Start Guide

Get your first high-performance multi-provider agent running in 5 minutes.

## 1. Setup (1 minute)

We recommend using `uv` for lightning-fast dependency management.

```bash
# Create a virtual environment and install dependencies
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt

# Set API keys for desired providers
export ANTHROPIC_API_KEY="your-anthropic-key-here"
export GOOGLE_API_KEY="your-google-key-here"
export QWEN_API_KEY="your-qwen-key-here"
export MISTRAL_API_KEY="your-mistral-key-here"
export DEEPSEEK_API_KEY="your-deepseek-key-here"
```

## 2. Create Your First Async Multi-Provider Agent (2 minutes)

Create `my_agent.py`:

```python
from framework import BaseAgent
from typing import Dict, Any, Optional

class MyFirstAgent(BaseAgent):
    def __init__(self, config):
        super().__init__(
            agent_id="my_first_agent",
            name="My First Multi-Provider Agent",
            description="My first agent with multi-LLM support",
            capabilities=["research", "analysis"],
            config=config
        )

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        # Call LLM with the prompt (Async)
        response_text = await self.call_llm(
            prompt=f"Task: {task}",
            max_tokens=self.config.get("max_tokens", 2000),
            temperature=0.7
        )

        return {
            "status": "success",
            "findings": response_text,
            "metadata": {
                "task": task,
                "provider": self.config.get("provider", "anthropic")
            }
        }
```

## 3. Run It with Different Providers (1 minute)

Create `run.py`:

```python
import asyncio
from my_agent import MyFirstAgent

async def main():
    # Configure agent with Anthropic provider
    anthropic_config = {
        "provider": "anthropic",
        "model": "claude-3-5-sonnet-20241022"
    }

    # Create and run agent
    agent = MyFirstAgent(anthropic_config)
    result = await agent.run("Explain what multi-agent systems are in 3 bullet points")

    print(f"Using provider: {result['metadata']['provider']}")
    print(result['findings'])

if __name__ == "__main__":
    asyncio.run(main())
```

Run it:
```bash
python run.py
```

## 4. Autonomous Tool Use (1 minute)

AjintK now supports an autonomous "Thinking/Acting" loop.

```python
from framework import ToolDefinitions

class ToolAgent(BaseAgent):
    def get_tools(self):
        return [ToolDefinitions.run_command()]

    async def run(self, task: str, context=None):
        # Automatically use tools and iterate until a final answer is reached
        findings = await self.execute_with_tools(task)
        return {"status": "success", "findings": findings}
```

## 5. Parallel Swarms (Async)

```python
import asyncio
from framework import AgentOrchestrator
from my_agent import MyFirstAgent

async def run_swarm():
    orchestrator = AgentOrchestrator({"max_concurrent_agents": 10})
    
    orchestrator.register_agent("researcher", MyFirstAgent({"provider": "anthropic"}))
    orchestrator.register_agent("analyst", MyFirstAgent({"provider": "google", "model": "gemini-pro"}))

    # Run in parallel with asyncio
    result = await orchestrator.run_swarm(task="Research AI safety")
    print(f"Completed: {result['successful']} agents")

if __name__ == "__main__":
    asyncio.run(run_swarm())
```

## What Next?

### Intelligent Provider Routing
```python
from framework import get_adaptive_provider

# Automatically select the best provider for the task type
provider, name = await get_adaptive_provider(task_type="coding")
response = await provider.query("Write a fast sort in Python")
```

### Persistent Async Memory
```python
from framework import AgentMemory

memory = AgentMemory(agent_id="my_agent")
await memory.store("project_goal", "Optimize framework performance")
goal = await memory.retrieve("project_goal")
```

## Tips

1. **Use Async**: Always `await` your LLM calls and tool executions to maximize performance.
2. **Optimized Caching**: The framework automatically caches responses to `.llm_cache.json` with model-aware keys.
3. **Use uv**: For the fastest installation and dependency resolution, use `uv`.