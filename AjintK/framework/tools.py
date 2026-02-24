"""
Tool System for Claude API Agents (Async)
Provides common tool definitions and an asynchronous executor.
"""
import asyncio
import os
import json
import httpx
import logging
from typing import Dict, List, Any, Callable, Awaitable

logger = logging.getLogger(__name__)

class ToolDefinitions:
    """
    Common tool definitions in Claude API format.
    """

    @staticmethod
    def file_read() -> Dict[str, Any]:
        return {
            "name": "file_read",
            "description": "Read the contents of a file",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the file to read"}
                },
                "required": ["path"]
            }
        }

    @staticmethod
    def file_write() -> Dict[str, Any]:
        return {
            "name": "file_write",
            "description": "Write content to a file",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the file to write"},
                    "content": {"type": "string", "description": "Content to write"}
                },
                "required": ["path", "content"]
            }
        }

    @staticmethod
    def run_command() -> Dict[str, Any]:
        return {
            "name": "run_command",
            "description": "Execute a shell command",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds"}
                },
                "required": ["command"]
            }
        }

    @staticmethod
    def web_fetch() -> Dict[str, Any]:
        return {
            "name": "web_fetch",
            "description": "Fetch content from a URL",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"}
                },
                "required": ["url"]
            }
        }

    @staticmethod
    def get_all_basic_tools() -> List[Dict[str, Any]]:
        return [
            ToolDefinitions.file_read(),
            ToolDefinitions.file_write(),
            ToolDefinitions.run_command(),
            ToolDefinitions.web_fetch(),
        ]


class ToolExecutor:
    """
    Asynchronously executes tool calls.
    """

    def __init__(self):
        self.handlers: Dict[str, Callable[[Dict[str, Any]], Awaitable[Any]]] = {}
        self._register_default_handlers()

    def _register_default_handlers(self):
        self.handlers["file_read"] = self._handle_file_read
        self.handlers["file_write"] = self._handle_file_write
        self.handlers["run_command"] = self._handle_run_command
        self.handlers["web_fetch"] = self._handle_web_fetch

    def register_handler(self, tool_name: str, handler_func: Callable[[Dict[str, Any]], Awaitable[Any]]):
        self.handlers[tool_name] = handler_func

    async def execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> Any:
        if tool_name not in self.handlers:
            return f"Error: No handler registered for tool: {tool_name}"

        handler = self.handlers[tool_name]
        try:
            return await handler(tool_input)
        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {e}")
            return f"Error executing {tool_name}: {str(e)}"

    async def _handle_file_read(self, tool_input: Dict[str, Any]) -> str:
        path = tool_input["path"]
        # Use run_in_executor for blocking I/O
        def sync_read():
            with open(path, 'r') as f:
                return f.read()
        return await asyncio.to_thread(sync_read)

    async def _handle_file_write(self, tool_input: Dict[str, Any]) -> str:
        path = tool_input["path"]
        content = tool_input["content"]
        def sync_write():
            with open(path, 'w') as f:
                f.write(content)
            return f"Successfully wrote to {path}"
        return await asyncio.to_thread(sync_write)

    async def _handle_run_command(self, tool_input: Dict[str, Any]) -> str:
        command = tool_input["command"]
        timeout = tool_input.get("timeout", 30)
        
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            result = stdout.decode().strip()
            error = stderr.decode().strip()
            return f"STDOUT: {result}\nSTDERR: {error}" if error else result
        except asyncio.TimeoutError:
            process.kill()
            return "Error: Command timed out"

    async def _handle_web_fetch(self, tool_input: Dict[str, Any]) -> str:
        url = tool_input["url"]
        async with httpx.AsyncClient() as client:
            response = await client.get(url, follow_redirects=True)
            response.raise_for_status()
            return response.text
