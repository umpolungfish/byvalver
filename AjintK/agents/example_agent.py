"""
Example Agent Implementations (Async)
Demonstrates how to create custom agents using the framework.
"""
from typing import Dict, List, Any, Optional
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from framework import BaseAgent, ToolDefinitions


class ResearchAgent(BaseAgent):
    """
    Example: Research agent that gathers and analyzes information (Async).
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="research_agent",
            name="Research Agent",
            description="Gathers and analyzes information on given topics",
            capabilities=[
                "Web research",
                "Information synthesis",
                "Source analysis",
                "Report generation"
            ],
            config=config
        )

    def get_tools(self) -> List[Dict[str, Any]]:
        """Define tools this agent can use"""
        return [
            ToolDefinitions.web_fetch(),
            ToolDefinitions.file_read(),
            ToolDefinitions.file_write(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute research task (Async)."""
        print(f"[ResearchAgent] Starting research on: {task}")

        system_prompt = f"""You are a research agent specialized in gathering and analyzing information.
Your capabilities: {', '.join(self.capabilities)}

Task: {task}
"""

        if context:
            system_prompt += f"\nContext from previous agents:\n{context}"

        prompt = f"""{system_prompt}

Research the following topic and provide:
1. Key findings
2. Important sources
3. Summary analysis

Topic: {task}

Provide structured output with clear sections."""

        try:
            # Call LLM with the prompt (Awaited)
            response_text = await self.call_llm(
                prompt=prompt,
                max_tokens=self.config.get("max_tokens", 4000),
                temperature=0.7
            )

            # Save as artifact
            self.save_artifact(response_text, "research_report")

            print(f"[ResearchAgent] Research completed successfully")

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

        except Exception as e:
            print(f"[ResearchAgent] Error: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "findings": None,
                "artifacts": []
            }


class AnalysisAgent(BaseAgent):
    """
    Example: Analysis agent that processes and interprets data (Async).
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="analysis_agent",
            name="Analysis Agent",
            description="Analyzes data and generates insights",
            capabilities=[
                "Data analysis",
                "Pattern recognition",
                "Insight generation",
                "Recommendation synthesis"
            ],
            config=config
        )

    def get_tools(self) -> List[Dict[str, Any]]:
        """Define tools this agent can use"""
        return [
            ToolDefinitions.file_read(),
            ToolDefinitions.file_write(),
            ToolDefinitions.json_load(),
            ToolDefinitions.json_save(),
        ]

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute analysis task (Async)."""
        print(f"[AnalysisAgent] Starting analysis: {task}")

        # Extract previous findings if available
        previous_findings = ""
        if context and "previous_stage" in context:
            prev = context["previous_stage"]
            previous_findings = prev.get("findings", "")

        prompt = f"""You are an analysis agent specialized in processing and interpreting data.
Your capabilities: {', '.join(self.capabilities)}

Analysis objective: {task}

Data to analyze:
{previous_findings if previous_findings else "No previous data provided"}

Analyze the following information and provide:
1. Key insights
2. Patterns identified
3. Actionable recommendations

Provide structured, detailed analysis."""

        try:
            # Call LLM with the prompt (Awaited)
            response_text = await self.call_llm(
                prompt=prompt,
                max_tokens=self.config.get("max_tokens", 4000),
                temperature=0.7
            )

            # Save as artifact
            self.save_artifact(response_text, "analysis_report")

            print(f"[AnalysisAgent] Analysis completed successfully")

            return {
                "status": "success",
                "findings": response_text,
                "artifacts": self.artifacts,
                "metadata": {
                    "task": task,
                    "used_previous_context": bool(previous_findings),
                    "model": self.config.get("model"),
                    "provider": self.config.get("provider", "anthropic")
                }
            }

        except Exception as e:
            print(f"[AnalysisAgent] Error: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "findings": None,
                "artifacts": []
            }


# Template for creating new agents
class CustomAgentTemplate(BaseAgent):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id="custom_agent",
            name="Custom Agent",
            description="Description of what this agent does",
            capabilities=["Capability 1"],
            config=config
        )

    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        print(f"[CustomAgent] Starting: {task}")
        prompt = f"You are a custom agent. Task: {task}"

        try:
            response_text = await self.call_llm(prompt=prompt)

            return {
                "status": "success",
                "findings": response_text,
                "artifacts": self.artifacts,
                "metadata": {}
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "findings": None,
                "artifacts": []
            }
