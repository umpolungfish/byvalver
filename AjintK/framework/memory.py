"""
Agent Memory System (Async)
Provides persistent storage for agent state and data with non-blocking I/O.
"""
from typing import Dict, Any, Optional
import json
import os
import asyncio
from pathlib import Path
from datetime import datetime


class AgentMemory:
    """
    Persistent memory system for agents with async support.
    """

    def __init__(self, agent_id: str, storage_dir: str = ".agent_memory"):
        self.agent_id = agent_id
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.memory_file = self.storage_dir / f"{agent_id}_memory.json"
        self.memory = self._load_memory_sync()
        self._lock = asyncio.Lock()

    def _load_memory_sync(self) -> Dict[str, Any]:
        """Load memory from disk (Sync for init)"""
        if self.memory_file.exists():
            try:
                with open(self.memory_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading memory: {e}")
                return self._init_memory_structure()
        return self._init_memory_structure()

    def _init_memory_structure(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "created_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "categories": {
                "general": {},
                "updates": [],
                "sessions": []
            }
        }

    async def _save_memory(self) -> None:
        """Save memory to disk asynchronously."""
        async with self._lock:
            self.memory["last_updated"] = datetime.now().isoformat()
            try:
                # Use a temp file for atomic write
                temp_file = f"{self.memory_file}.tmp"
                def sync_write():
                    with open(temp_file, 'w') as f:
                        json.dump(self.memory, f, indent=2)
                    os.replace(temp_file, self.memory_file)
                
                await asyncio.to_thread(sync_write)
            except Exception as e:
                print(f"Error saving memory: {e}")

    async def store(self, key: str, value: Any, category: str = "general") -> None:
        if category not in self.memory["categories"]:
            self.memory["categories"][category] = {}

        self.memory["categories"][category][key] = value
        await self._save_memory()

    async def retrieve(self, key: str, category: str = "general") -> Optional[Any]:
        return self.memory["categories"].get(category, {}).get(key)

    async def delete(self, key: str, category: str = "general") -> bool:
        if category in self.memory["categories"]:
            if key in self.memory["categories"][category]:
                del self.memory["categories"][category][key]
                await self._save_memory()
                return True
        return False

    async def add_update(self, update: str) -> None:
        self.memory["categories"]["updates"].append({
            "timestamp": datetime.now().isoformat(),
            "update": update
        })
        await self._save_memory()

    async def start_session(self) -> str:
        session_id = f"session_{len(self.memory['categories']['sessions']) + 1}"
        session = {
            "session_id": session_id,
            "start_time": datetime.now().isoformat(),
            "events": []
        }
        self.memory["categories"]["sessions"].append(session)
        await self._save_memory()
        return session_id

    async def log_event(self, session_id: str, event: str, data: Any = None) -> None:
        for session in self.memory["categories"]["sessions"]:
            if session["session_id"] == session_id:
                session["events"].append({
                    "timestamp": datetime.now().isoformat(),
                    "event": event,
                    "data": data
                })
                await self._save_memory()
                return

    async def end_session(self, session_id: str) -> None:
        for session in self.memory["categories"]["sessions"]:
            if session["session_id"] == session_id:
                session["end_time"] = datetime.now().isoformat()
                await self._save_memory()
                return

    async def get_all_sessions(self) -> list:
        return self.memory["categories"]["sessions"]

    async def clear_category(self, category: str) -> None:
        if category in self.memory["categories"]:
            if isinstance(self.memory["categories"][category], dict):
                self.memory["categories"][category] = {}
            elif isinstance(self.memory["categories"][category], list):
                self.memory["categories"][category] = []
            await self._save_memory()

    async def clear_all(self) -> None:
        self.memory = self._init_memory_structure()
        await self._save_memory()
