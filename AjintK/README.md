# AjintK: Claude Agent Framework with Multi-Provider LLM Support

A high-performance, asynchronous framework for building autonomous multi-agent systems with support for multiple LLM providers.

## Overview

AjintK is a production-ready framework designed for orchestrating autonomous agents. It leverages **Asynchronous I/O** to achieve high concurrency and features a **standardized autonomous tool-use loop**, allowing agents to "think" and "act" iteratively until a task is completed.

### Key Features

- **Asynchronous Architecture**: Built on `asyncio` for maximum performance and non-blocking agent orchestration.
- **Autonomous Tool-Use Loop**: Standardized Thinking/Acting cycle in `BaseAgent` for complex, multi-step tasks.
- **Multi-Provider Support**: Seamlessly switch between Anthropic (Claude), Google (Gemini), DeepSeek, Qwen, and Mistral.
- **Optimized Caching**: High-efficiency response caching with model-parameter awareness and atomic disk writes.
- **Modern Dependency Management**: Integrated with `uv` for lightning-fast setup and resolution.
- **Intelligent Routing**: Automatically route tasks to the most capable provider based on the task type (coding, analysis, etc.).
- **Persistent Memory**: Asynchronous, thread-safe JSON memory system for agent state and session history.

## Core Components

### 1. BaseAgent (Async)
The foundation for all agents. It provides:
- **`execute_with_tools`**: An autonomous loop that manages tool identification, execution, and response refinement.
- **Async LLM Calls**: Unified interface for multi-provider asynchronous queries.
- **Tool Integration**: Direct access to `ToolExecutor` for executing system and custom tools.

### 2. AgentOrchestrator
Manages concurrent agent execution:
- **Swarm Mode**: Runs multiple agents in parallel using `asyncio.gather`.
- **Pipeline Mode**: Sequential execution where context is passed between stages.

### 3. Tool System
Pre-built asynchronous tools:
- **File Operations**: `file_read`, `file_write`.
- **System Commands**: `run_command` with timeout and subprocess management.
- **Web Interaction**: `web_fetch` using `httpx`.

### 4. Memory System
Asynchronous persistent storage:
- **Atomic Writes**: Prevents data corruption during concurrent operations.
- **Session Tracking**: Organize agent interactions into logical sessions and events.

## Installation

We recommend using `uv` for the best performance.

```bash
# 1. Clone the repository
git clone https://github.com/mrnob0dy666/AjintK
cd AjintK

# 2. Setup environment and dependencies
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt

# 3. Set up API keys
export ANTHROPIC_API_KEY="your-key"
export GOOGLE_API_KEY="your-key"
# etc...
```

## Quick Start

### Create an Autonomous Agent

```python
import asyncio
from framework import BaseAgent, ToolDefinitions

class DevAgent(BaseAgent):
    def get_tools(self):
        # Enable shell and file tools
        return [ToolDefinitions.run_command(), ToolDefinitions.file_write()]

    async def run(self, task: str, context=None):
        # Use the autonomous loop to execute the task
        findings = await self.execute_with_tools(task)
        return {"status": "success", "findings": findings}

async def main():
    config = {"provider": "anthropic", "model": "claude-3-5-sonnet-20241022"}
    agent = DevAgent("dev_agent", "Developer", "Writes and tests code", ["coding"], config)
    
    result = await agent.run("Create a hello.py and run it to verify it works.")
    print(result['findings'])

if __name__ == "__main__":
    asyncio.run(main())
```

## Advanced Usage

### Parallel Swarms
```python
orchestrator = AgentOrchestrator({"max_concurrent_agents": 10})
orchestrator.register_agent("researcher", ResearchAgent(config))
orchestrator.register_agent("analyst", AnalysisAgent(config))

# Executes all agents in parallel
results = await orchestrator.run_swarm(task="Scan for vulnerabilities")
```

### Intelligent Routing
```python
from framework import get_adaptive_provider

# Automatically selects the best model for 'coding' (e.g., DeepSeek or Qwen)
provider, name = await get_adaptive_provider(task_type="coding")
code = await provider.query("Optimize this SQL query...")
```

## Performance & Reliability

- **Caching**: Responses are cached to `.llm_cache.json` based on a SHA-256 hash of the prompt, model, and temperature.
- **Async Safety**: Every component uses `asyncio.Lock` where necessary to ensure data integrity in high-concurrency scenarios.
- **Error Handling**: Standardized error reporting across all agent modes.

## Contributing

AjintK is designed to be extensible. To add a new provider, inherit from `LLMProvider` in `framework/llm_provider_abc.py` and implement the `async query` method.

---
**Build powerful, autonomous, and lightning-fast AI systems with AjintK.**