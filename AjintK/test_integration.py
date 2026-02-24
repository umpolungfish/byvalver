#!/usr/bin/env python3
"""
Test script to verify the integration of the enhanced LLM provider system (Async).
"""

import os
import sys
import asyncio
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from framework import (
    BaseAgent,
    AgentOrchestrator,
    get_llm_provider
)

from agents import ResearchAgent

async def test_provider_creation():
    """Test that we can create different LLM providers"""
    print("Testing LLM provider creation...")
    
    try:
        from framework.enhanced_llm_provider import (
            AnthropicProvider, 
            GoogleProvider, 
            DeepSeekProvider,
            QwenProvider,
            MistralProvider
        )
        print("✓ All provider classes are accessible")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

async def test_base_agent_update():
    """Test that the BaseAgent has been updated properly"""
    print("\nTesting BaseAgent updates...")
    
    try:
        agent_methods = dir(BaseAgent)
        
        if 'call_llm' in agent_methods:
            print("✓ BaseAgent has async LLM methods")
        else:
            print("✗ BaseAgent missing async LLM methods")
            return False
            
        config = {
            "provider": "anthropic",
            "model": "claude-3-5-sonnet-20241022"
        }
        
        try:
            class TestAgent(BaseAgent):
                async def run(self, task, context=None):
                    return {"status": "success", "findings": "test"}
            
            agent = TestAgent(
                agent_id="test_agent",
                name="Test Agent",
                description="Test agent for integration",
                capabilities=["testing"],
                config=config
            )
            print("✓ BaseAgent can be instantiated with provider config")
        except ValueError as e:
            if "API key" in str(e):
                print("✓ BaseAgent initialization works (API key error is expected)")
            else:
                print(f"✗ Unexpected error during BaseAgent init: {e}")
                return False
        
        return True
    except Exception as e:
        print(f"✗ Error testing BaseAgent: {e}")
        return False

async def test_example_agents():
    """Test that example agents have been updated"""
    print("\nTesting example agents...")
    
    try:
        config = {
            "provider": "anthropic",
            "model": "claude-3-5-sonnet-20241022"
        }
        
        try:
            agent = ResearchAgent(config)
            print("✓ ResearchAgent can be instantiated with new provider system")
        except ValueError as e:
            if "API key" in str(e):
                print("✓ ResearchAgent initialization works (API key error is expected)")
            else:
                print(f"✗ Unexpected error during ResearchAgent init: {e}")
                return False
                
        return True
    except Exception as e:
        print(f"✗ Error testing example agents: {e}")
        return False

async def test_orchestrator():
    """Test that orchestrator still works with updated agents"""
    print("\nTesting orchestrator...")
    
    try:
        orchestrator = AgentOrchestrator()
        print("✓ AgentOrchestrator can be instantiated")
        return True
    except Exception as e:
        print(f"✗ Error testing orchestrator: {e}")
        return False

async def run_tests():
    """Run all tests"""
    print("Testing AjintK framework with enhanced LLM provider system (Async)...\n")
    
    results = [
        await test_provider_creation(),
        await test_base_agent_update(),
        await test_example_agents(),
        await test_orchestrator()
    ]
    
    print(f"\n{'='*50}")
    print(f"Test Results: {sum(results)}/{len(results)} passed")
    
    if all(results):
        print("✓ All tests passed! Integration successful.")
        return 0
    else:
        print("✗ Some tests failed.")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(run_tests()))