"""
Inter-Agent Communication System (Async)
Enables agents to send messages and collaborate with non-blocking I/O.
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import json
import asyncio
import os
from enum import Enum


class MessageType(Enum):
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    COLLABORATION = "collaboration_request"


@dataclass
class Message:
    message_id: str
    from_agent: str
    to_agent: str
    message_type: MessageType
    content: str
    priority: int = 5
    timestamp: str = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self):
        d = asdict(self)
        d["message_type"] = self.message_type.value
        return d


class AgentCommunication:
    """
    Manages asynchronous message passing between agents.
    """

    def __init__(self, storage_dir: str = ".agent_messages"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.message_counter = 0
        self._lock = asyncio.Lock()

    def _get_inbox_path(self, agent_id: str) -> Path:
        return self.storage_dir / f"{agent_id}_inbox.json"

    def _get_outbox_path(self, agent_id: str) -> Path:
        return self.storage_dir / f"{agent_id}_outbox.json"

    async def _load_messages(self, file_path: Path) -> List[Dict[str, Any]]:
        if file_path.exists():
            try:
                def sync_read():
                    with open(file_path, 'r') as f:
                        return json.load(f)
                return await asyncio.to_thread(sync_read)
            except Exception:
                return []
        return []

    async def _save_messages(self, file_path: Path, messages: List[Dict[str, Any]]) -> None:
        async with self._lock:
            try:
                temp_file = f"{file_path}.tmp"
                def sync_write():
                    with open(temp_file, 'w') as f:
                        json.dump(messages, f, indent=2)
                    os.replace(temp_file, file_path)
                await asyncio.to_thread(sync_write)
            except Exception as e:
                print(f"Error saving messages: {e}")

    async def send_message(
        self,
        from_agent: str,
        to_agent: str,
        content: str,
        message_type: MessageType = MessageType.NOTIFICATION,
        priority: int = 5,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        self.message_counter += 1
        message_id = f"msg_{self.message_counter}_{datetime.now().timestamp()}"

        message = Message(
            message_id=message_id,
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=message_type,
            content=content,
            priority=priority,
            metadata=metadata
        )

        # Outbox update
        outbox_path = self._get_outbox_path(from_agent)
        outbox = await self._load_messages(outbox_path)
        outbox.append(message.to_dict())
        await self._save_messages(outbox_path, outbox)

        # Inbox update
        if to_agent != "broadcast":
            inbox_path = self._get_inbox_path(to_agent)
            inbox = await self._load_messages(inbox_path)
            inbox.append(message.to_dict())
            await self._save_messages(inbox_path, inbox)
        
        return message_id

    async def receive_messages(
        self,
        agent_id: str,
        unread_only: bool = True
    ) -> List[Dict[str, Any]]:
        inbox_path = self._get_inbox_path(agent_id)
        messages = await self._load_messages(inbox_path)

        if unread_only:
            messages = [m for m in messages if not m.get("read", False)]

        messages.sort(key=lambda m: (-m.get("priority", 5), m.get("timestamp", "")))
        return messages

    async def mark_as_read(self, agent_id: str, message_id: str) -> bool:
        inbox_path = self._get_inbox_path(agent_id)
        messages = await self._load_messages(inbox_path)

        for message in messages:
            if message["message_id"] == message_id:
                message["read"] = True
                await self._save_messages(inbox_path, messages)
                return True
        return False

    async def send_collaboration_request(
        self,
        from_agent: str,
        to_agent: str,
        task: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        metadata = {"type": "collaboration_request", "task": task, "context": context or {}}
        return await self.send_message(
            from_agent=from_agent,
            to_agent=to_agent,
            content=f"Collaboration request: {task}",
            message_type=MessageType.COLLABORATION,
            priority=7,
            metadata=metadata
        )

    async def send_response(
        self,
        from_agent: str,
        to_agent: str,
        original_message_id: str,
        response_content: str,
        response_data: Optional[Dict[str, Any]] = None
    ) -> str:
        metadata = {"in_response_to": original_message_id, "response_data": response_data or {}}
        return await self.send_message(
            from_agent=from_agent,
            to_agent=to_agent,
            content=response_content,
            message_type=MessageType.RESPONSE,
            priority=6,
            metadata=metadata
        )
