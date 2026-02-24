"""
Agent Orchestrator (Async)
Coordinates execution of single or multiple agents in parallel using asyncio.
"""
from typing import Dict, List, Optional, Any
import asyncio
import logging

from .base_agent import BaseAgent, AgentStatus


logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """
    Orchestrates agent execution in single or multi-agent (swarm) modes using asyncio.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.agents: Dict[str, BaseAgent] = {}
        self.max_concurrent = self.config.get("max_concurrent_agents", 10)

    def register_agent(self, agent_id: str, agent: BaseAgent) -> None:
        """Register an agent with the orchestrator."""
        self.agents[agent_id] = agent
        logger.info(f"Registered agent: {agent_id} ({agent.name})")

    async def run_agent(
        self,
        agent_id: str,
        task: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a single agent (Async)."""
        if agent_id not in self.agents:
            raise ValueError(f"Agent not found: {agent_id}")

        agent = self.agents[agent_id]
        logger.info(f"Running agent: {agent_id}")

        try:
            agent.start()
            result = await agent.run(task, context)
            agent.complete(result)
            logger.info(f"Agent {agent_id} completed successfully")
            return result
        except Exception as e:
            logger.error(f"Agent {agent_id} failed: {str(e)}")
            agent.fail(str(e))
            return {
                "status": "error",
                "error": str(e),
                "agent_id": agent_id
            }

    async def run_swarm(
        self,
        task: str,
        agent_ids: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute multiple agents in parallel (Async)."""
        if agent_ids is None:
            agent_ids = list(self.agents.keys())

        logger.info(f"Running swarm with {len(agent_ids)} agents")

        # Use a semaphore to limit concurrency if needed
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def _run_with_semaphore(aid):
            async with semaphore:
                return await self.run_agent(aid, task, context)

        tasks = [_run_with_semaphore(aid) for aid in agent_ids]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        results = {}
        successful = 0
        failed = 0

        for agent_id, result in zip(agent_ids, results_list):
            if isinstance(result, Exception):
                logger.error(f"Agent {agent_id} raised an exception: {result}")
                results[agent_id] = {"status": "error", "error": str(result)}
                failed += 1
            else:
                results[agent_id] = result
                if result.get("status") == "success":
                    successful += 1
                else:
                    failed += 1

        logger.info(f"Swarm complete: {successful} successful, {failed} failed")

        return {
            "agents_run": len(agent_ids),
            "successful": successful,
            "failed": failed,
            "results": results
        }

    async def run_pipeline(
        self,
        task: str,
        agent_ids: List[str],
        initial_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute agents sequentially (Async)."""
        logger.info(f"Running pipeline with {len(agent_ids)} stages")

        context = initial_context or {}
        pipeline_results = []

        for i, agent_id in enumerate(agent_ids):
            stage_num = i + 1
            logger.info(f"Pipeline stage {stage_num}/{len(agent_ids)}: {agent_id}")

            result = await self.run_agent(agent_id, task, context)

            pipeline_results.append({
                "stage": stage_num,
                "agent_id": agent_id,
                "result": result
            })

            if result.get("status") != "success":
                logger.warning(f"Pipeline failed at stage {stage_num}")
                return {
                    "status": "failed",
                    "failed_at_stage": stage_num,
                    "pipeline_results": pipeline_results
                }

            context.update({
                "previous_stage": result,
                "previous_agent": agent_id
            })

        logger.info("Pipeline completed successfully")

        return {
            "status": "success",
            "stages_completed": len(agent_ids),
            "pipeline_results": pipeline_results,
            "final_context": context
        }

    def get_agent_status(self, agent_id: str) -> AgentStatus:
        """Get current status of an agent"""
        if agent_id not in self.agents:
            raise ValueError(f"Agent not found: {agent_id}")
        return self.agents[agent_id].status

    def get_all_agents(self) -> Dict[str, Dict[str, Any]]:
        """Get info about all registered agents"""
        return {
            agent_id: {
                "name": agent.name,
                "description": agent.description,
                "capabilities": agent.capabilities,
                "status": agent.status.value
            }
            for agent_id, agent in self.agents.items()
        }
