"""
Claude Agent Framework with Multi-Provider LLM Support
A reusable framework for building multi-agent systems with multiple LLM providers.
"""

from .base_agent import BaseAgent, AgentStatus
from .orchestrator import AgentOrchestrator
from .tools import ToolDefinitions, ToolExecutor
from .memory import AgentMemory
from .communication import AgentCommunication, Message, MessageType
from .enhanced_llm_provider import (
    get_llm_provider,
    get_adaptive_provider,
    AnthropicProvider,
    GoogleProvider,
    DeepSeekProvider,
    QwenProvider,
    MistralProvider,
    ModelRouter
)

__version__ = "2.0.0"

__all__ = [
    "BaseAgent",
    "AgentStatus",
    "AgentOrchestrator",
    "ToolDefinitions",
    "ToolExecutor",
    "AgentMemory",
    "AgentCommunication",
    "Message",
    "MessageType",
    "get_llm_provider",
    "get_adaptive_provider",
    "AnthropicProvider",
    "GoogleProvider",
    "DeepSeekProvider",
    "QwenProvider",
    "MistralProvider",
    "ModelRouter",
]
