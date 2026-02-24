# Framework Methodology & Design Philosophy

This document explains the core methodology and design decisions behind the Claude Agent Framework with Multi-Provider LLM Support.

## Core Design Principles

### 1. Separation of Concerns

The framework separates distinct responsibilities into isolated modules:

- **BaseAgent**: Agent logic and multi-LLM provider interaction
- **Orchestrator**: Multi-agent coordination
- **Enhanced LLM Provider System**: Multi-provider LLM integration
- **Tools**: External capabilities (file, web, commands)
- **Memory**: State persistence
- **Communication**: Inter-agent messaging

**Why**: This modularity enables agents to be developed independently while maintaining consistent interfaces for integration.

### 2. Inheritance-Based Extensibility

All agents inherit from `BaseAgent`, which provides:
- Multi-LLM provider client setup
- Lifecycle management (start → run → complete/fail)
- State tracking
- Artifact generation
- Memory/communication hooks
- Intelligent provider selection and routing

**Pattern**:
```python
class CustomAgent(BaseAgent):
    def __init__(self, config):
        super().__init__(agent_id, name, description, capabilities, config)

    def run(self, task, context):
        # Agent-specific logic
        response = self.call_llm(prompt=task)
        return result
```

**Why**: New agents get all base functionality for free. Developers only implement the unique `run()` logic.

### 3. Multi-Provider Architecture

Agents can utilize multiple LLM providers:
- Provider selection via configuration
- Intelligent routing based on task type
- Automatic fallback mechanisms
- Response caching for efficiency

**Pattern**:
```python
def run(self, task, context):
    # Use configured provider
    response = self.call_llm(
        prompt=task,
        max_tokens=self.config.get("max_tokens", 4000),
        temperature=0.7
    )

    # Or use adaptive provider selection
    provider, provider_name = get_adaptive_provider(
        task_type="analysis",
        context=context
    )
    response = provider.query(task)
```

**Why**: Flexibility to match provider capabilities to task requirements, optimize costs, and provide redundancy.

### 4. Tool-Driven Architecture

Agents interact with external systems via Claude API tools:
- Tools are defined as JSON schemas
- Claude decides when to use tools
- Framework executes tool calls

**Pattern**:
```python
def get_tools(self):
    return [
        ToolDefinitions.file_read(),
        ToolDefinitions.web_fetch(),
    ]

# Note: Tool usage may vary by provider
prompt = f"Task: {task}. Use tools if needed."
response = self.call_llm(prompt=prompt)
```

**Why**: Claude's native tool use enables agents to perform actions while maintaining natural language reasoning.

### 5. Context-Driven Coordination

Agents receive context from previous stages:

**Pattern**:
```python
# Stage 1: Research
result1 = agent1.run(task, context={})

# Stage 2: Analysis (receives research findings)
context = {"previous_stage": result1}
result2 = agent2.run(task, context)

# Stage 3: Synthesis (receives analysis)
context = {"previous_stage": result2}
result3 = agent3.run(task, context)
```

**Why**: Sequential agents build on previous work without tight coupling. Each agent processes context independently.

### 6. Three Coordination Patterns

#### Pattern A: Single Agent
```python
result = orchestrator.run_agent("researcher", task)
```
**Use**: Simple, focused tasks requiring single capability

#### Pattern B: Parallel Swarm
```python
result = orchestrator.run_swarm(task, ["agent1", "agent2", "agent3"])
```
**Use**: Multiple perspectives on same problem, executed concurrently

#### Pattern C: Sequential Pipeline
```python
result = orchestrator.run_pipeline(task, ["research", "analyze", "synthesize"])
```
**Use**: Multi-stage workflows where later stages depend on earlier outputs

### 7. State Machine Lifecycle

Every agent follows this lifecycle:

```
IDLE → start() → RUNNING → run() → complete()/fail() → COMPLETED/FAILED
```

**Why**: Consistent state management enables monitoring, debugging, and recovery.

## Key Architectural Decisions

### Decision 1: JSON-Based Persistence

**Choice**: Store memory and messages as JSON files
**Alternative**: Database (PostgreSQL, MongoDB)
**Rationale**:
- Zero external dependencies
- Human-readable for debugging
- Easy to version control
- Sufficient for most use cases
- Can upgrade to DB later without changing interfaces

### Decision 2: Thread-Based Concurrency

**Choice**: `ThreadPoolExecutor` for parallel agents
**Alternative**: Async/await or multiprocessing
**Rationale**:
- Simple, well-understood model
- Sufficient for I/O-bound LLM API calls
- Easy to reason about for developers
- Works well with synchronous LLM SDKs

### Decision 3: Tool Definitions in Agent Classes

**Choice**: Agents define their own `get_tools()` method
**Alternative**: Global tool registry
**Rationale**:
- Agents explicitly declare capabilities
- Easy to see what each agent can do
- Supports agent-specific custom tools
- No hidden dependencies

### Decision 4: Result Dictionary Pattern

**Choice**: Agents return structured dicts:
```python
{
    "status": "success|error",
    "findings": "...",
    "artifacts": [...],
    "metadata": {
        "task": "...",
        "model": "...",
        "provider": "..."
    }
}
```
**Alternative**: Custom result classes
**Rationale**:
- Simple, flexible structure
- Easy to serialize/deserialize
- Compatible with JSON storage
- Extensible via metadata

### Decision 5: Configuration-Driven Behavior

**Choice**: YAML config files for settings
**Alternative**: Environment variables or code-based config
**Rationale**:
- Centralized configuration
- Easy to modify without code changes
- Supports per-agent customization
- Human-readable format

### Decision 6: Multi-Provider Abstraction

**Choice**: Abstract base class for LLM providers with factory pattern
**Alternative**: Direct API integrations in agents
**Rationale**:
- Consistent interface across providers
- Easy to swap or add new providers
- Enables intelligent routing
- Reduces coupling between agents and specific APIs

## Implementation Patterns

### Pattern: Multi-Provider Usage

```python
def run(self, task, context):
    # Use configured provider
    prompt = f"Task: {task}"

    response_text = self.call_llm(
        prompt=prompt,
        max_tokens=self.config.get("max_tokens", 4000),
        temperature=0.7
    )

    # Save artifacts
    self.save_artifact(response_text, "output")

    return {
        "status": "success",
        "findings": response_text,
        "artifacts": self.artifacts,
        "metadata": {
            "task": task,
            "model": self.config.get("model"),
            "provider": self.config.get("provider", "anthropic")
        }
    }
```

### Pattern: Adaptive Provider Selection

```python
def run(self, task, context):
    # Automatically select best provider for task type
    provider, provider_name = get_adaptive_provider(
        task_type="coding",  # Options: 'coding', 'reasoning', 'creative', 'analysis', 'general'
        context={"domain": "software", "complexity": "high"}
    )

    response = provider.query(task)

    return {
        "status": "success",
        "findings": response,
        "metadata": {"provider_used": provider_name}
    }
```

### Pattern: Progressive Context Accumulation

```python
context = {"initial": "data"}

for agent_id in pipeline:
    result = agent.run(task, context)

    # Accumulate context for next stage
    context.update({
        "previous_stage": result,
        "previous_agent": agent_id
    })

# Final context contains full execution history
return {"final_context": context}
```

### Pattern: Collaborative Messaging

```python
# Agent A needs help from Agent B
comm.send_collaboration_request(
    from_agent="agent_a",
    to_agent="agent_b",
    task="Analyze this data",
    context={"data": results}
)

# Agent B processes request
messages = comm.receive_messages("agent_b")
for msg in messages:
    if msg['message_type'] == 'collaboration_request':
        result = process_request(msg['metadata']['task'])
        comm.send_response(
            from_agent="agent_b",
            to_agent="agent_a",
            original_message_id=msg['message_id'],
            response_content="Complete",
            response_data={"result": result}
        )
```

## Scalability Considerations

### Horizontal Scaling
- **Current**: Thread-based concurrency on single machine
- **Upgrade Path**: Replace orchestrator with distributed task queue (Celery, RabbitMQ)
- **Agent Interface**: Unchanged! Agents don't know about orchestration

### Storage Scaling
- **Current**: JSON files stored locally
- **Upgrade Path**: Replace with database (PostgreSQL, MongoDB) in AgentMemory implementation
- **Agent Interface**: Unchanged! Agents use same memory API regardless of storage backend

### Provider Scaling
- **Current**: Individual API calls to each provider
- **Upgrade Path**: Add rate limiting, caching, and load balancing at the provider level
- **Agent Interface**: Unchanged! Scaling handled transparently in provider implementations

## Performance Optimization

### Caching Strategy
The enhanced LLM provider system includes built-in response caching:
- Cache responses based on prompt content
- Configurable cache expiration
- Reduces API costs and latency for repeated queries

### Provider Selection
- Use appropriate provider for task type (coding, reasoning, creative, etc.)
- Consider cost implications of different providers
- Leverage intelligent routing for automatic optimization

### Resource Management
- Monitor token usage across providers
- Implement timeouts for long-running requests
- Use appropriate models for task complexity

### Cost Optimization
- **Pattern**: Use cheaper models for simple agents
- **Implementation**: Per-agent model configuration
```yaml
agents:
  researcher:
    model: "claude-sonnet-4-5-20250929"  # Complex reasoning
  formatter:
    model: "claude-haiku-4-5-20250929"   # Simple formatting
```

## Testing Strategy

### Unit Testing Agents
```python
def test_research_agent():
    config = {"model": "claude-haiku-4-5-20250929"}
    agent = ResearchAgent(config)

    result = agent.run("Simple test task")

    assert result['status'] == 'success'
    assert len(result['findings']) > 0
```

### Integration Testing Pipelines
```python
def test_pipeline():
    orchestrator = AgentOrchestrator()
    orchestrator.register_agent("a", AgentA(config))
    orchestrator.register_agent("b", AgentB(config))

    result = orchestrator.run_pipeline("task", ["a", "b"])

    assert result['status'] == 'success'
    assert result['stages_completed'] == 2
```

### Mocking for Speed
```python
class MockClaudeClient:
    def messages_create(self, **kwargs):
        return MockResponse(content=[{"text": "Mock response"}])

agent.client = MockClaudeClient()  # Fast tests without API calls
```

## Common Extension Points

### 1. Adding Domain-Specific Agents
- Inherit from `BaseAgent`
- Implement specialized `run()` logic
- Define domain-specific tools

### 2. Custom Orchestration Logic
- Extend `AgentOrchestrator`
- Override `run_swarm()` or `run_pipeline()`
- Implement conditional execution, retries, etc.

### 3. Enhanced Memory Systems
- Implement `AgentMemory` interface
- Add vector storage for semantic search
- Integrate with Redis, MongoDB, etc.

### 4. Advanced Communication
- Add message routing logic
- Implement pub/sub patterns
- Add message prioritization/filtering

### 5. Observability
- Add logging throughout agent lifecycle
- Implement metrics collection (token usage, latency)
- Add tracing for pipeline execution

## Lessons from Production

### Lesson 1: Keep Agents Focused
**Problem**: "Swiss army knife" agents become hard to debug
**Solution**: Many specialized agents > few general agents

### Lesson 2: Explicit Tool Definitions
**Problem**: Agents calling wrong tools or missing capabilities
**Solution**: Each agent explicitly declares tools in `get_tools()`

### Lesson 3: Context Management
**Problem**: Context growing unbounded in long pipelines
**Solution**: Only pass forward what's needed, clean up per stage

### Lesson 4: Error Handling
**Problem**: One failed agent breaks entire pipeline
**Solution**: Agents return structured errors, orchestrator handles gracefully

### Lesson 5: Token Optimization
**Problem**: Expensive API calls for simple tasks
**Solution**: Per-agent model selection, appropriate max_tokens

## Framework Evolution

This framework can evolve along several axes:

1. **Persistence**: JSON → Database
2. **Concurrency**: Threads → Async → Distributed
3. **Communication**: Files → Message Queue
4. **Observability**: Logs → Metrics → Tracing
5. **Orchestration**: Simple → Conditional → ML-Driven

**Key Principle**: Evolution should be incremental and backward-compatible. Agent code remains stable while infrastructure scales.

## Applying to New Projects

When starting a new project with this framework:

1. **Identify Agent Types**: What specialized capabilities do you need?
2. **Design Information Flow**: Single agents? Swarm? Pipeline?
3. **Define Tools**: What external actions will agents take?
4. **Configure Resources**: Model selection, concurrency limits
5. **Implement Agents**: Start with one, test thoroughly, then expand
6. **Iterate**: Add complexity only as needed

The framework provides the foundation. Your domain expertise determines the agents and their orchestration.

---

**Remember**: The goal is productive agent development, not perfect abstraction. Use what you need, extend when necessary, keep agents simple.
