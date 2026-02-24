# llm_provider_abc.py
from abc import ABC, abstractmethod
import hashlib
import logging
import json
import os
import asyncio
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

CACHE_FILE = ".llm_cache.json"

class LLMProvider(ABC):
    """Abstract Base Class for all LLM providers with async support and optimized caching."""
    def __init__(self):
        self._cache = self._load_cache()
        self._cache_lock = asyncio.Lock()
        self._dirty = False

    def _load_cache(self) -> dict:
        """Load cache from file if it exists."""
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r') as f:
                    logger.info("Loading LLM cache from file.")
                    return json.load(f)
            except (IOError, json.JSONDecodeError) as e:
                logger.warning(f"Could not load LLM cache file: {e}")
        return {}

    async def _save_cache_if_dirty(self):
        """Save the current cache to file if it has changed."""
        if not self._dirty:
            return
        
        async with self._cache_lock:
            try:
                # Use a temporary file for atomic write
                temp_file = f"{CACHE_FILE}.tmp"
                with open(temp_file, 'w') as f:
                    json.dump(self._cache, f, indent=2)
                os.replace(temp_file, CACHE_FILE)
                self._dirty = False
                logger.info("LLM cache saved to disk.")
            except IOError as e:
                logger.warning(f"Could not save LLM cache file: {e}")

    def _get_cache_key(self, prompt: str, **kwargs) -> str:
        """Generate a cache key including model parameters."""
        # Include relevant parameters in the key
        cache_data = {
            "prompt": prompt,
            "model": kwargs.get("model"),
            "temperature": kwargs.get("temperature"),
            "max_tokens": kwargs.get("max_tokens")
        }
        key_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()

    async def get_cached_response(self, prompt: str, **kwargs) -> Optional[str]:
        """Get cached response if available."""
        cache_key = self._get_cache_key(prompt, **kwargs)
        async with self._cache_lock:
            if cache_key in self._cache:
                logger.info("Cache hit for prompt")
                return self._cache[cache_key]
        return None

    async def cache_response(self, prompt: str, response: str, **kwargs):
        """Cache the response for the given prompt."""
        cache_key = self._get_cache_key(prompt, **kwargs)
        async with self._cache_lock:
            self._cache[cache_key] = response
            self._dirty = True
            logger.info("Response cached for prompt")
        
        # In a real high-performance system, we might flush periodically 
        # instead of after every write, but let's ensure persistence for now.
        await self._save_cache_if_dirty()

    @abstractmethod
    async def query(self, prompt: str, **kwargs) -> str:
        """Asynchronously query the LLM provider."""
        pass