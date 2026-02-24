"""
Enhanced LLM Provider Factory with Multi-Provider Support for AjintK (Async Version)
"""
import os
import json
import logging
import httpx
import asyncio
from typing import Dict, Any, Optional, List, Tuple
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .llm_provider_abc import LLMProvider

logger = logging.getLogger(__name__)

# Common retry configuration for all providers
llm_retry = retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=4, max=60),
    retry=(
        retry_if_exception_type(httpx.HTTPStatusError) | 
        retry_if_exception_type(httpx.RequestError) |
        retry_if_exception_type(asyncio.TimeoutError)
    ),
    reraise=True
)

class AnthropicProvider(LLMProvider):
    """LLM Provider for Anthropic's Claude models (Async)."""

    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        super().__init__()
        self.api_key = api_key
        self.model = model
        self.client = None

        if not self.api_key or self.api_key == "YOUR_ANTHROPIC_API_KEY_HERE":
            raise ValueError("Anthropic API key is not configured properly.")

    @llm_retry
    async def query(self, prompt: str, **kwargs) -> str:
        temp = kwargs.get("temperature", 0.7)
        max_tokens = kwargs.get("max_tokens", 4096)
        
        cached_response = await self.get_cached_response(prompt, model=self.model, temperature=temp, max_tokens=max_tokens)
        if cached_response:
            return cached_response

        from anthropic import AsyncAnthropic

        if self.client is None:
            self.client = AsyncAnthropic(api_key=self.api_key)

        try:
            message = await self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temp,
                system="You are a helpful assistant.",
                messages=[{"role": "user", "content": prompt}]
            )

            content = message.content[0].text if message.content else ""
            await self.cache_response(prompt, content, model=self.model, temperature=temp, max_tokens=max_tokens)
            return content
        except Exception as e:
            logger.error(f"Error during Anthropic API call: {e}")
            raise


class GoogleProvider(LLMProvider):
    """LLM Provider for Google's Gemini models (Async)."""

    def __init__(self, api_key: str, model: str = "gemini-pro"):
        super().__init__()
        self.api_key = api_key
        self.model_name = model

        if not self.api_key or self.api_key == "YOUR_GOOGLE_API_KEY_HERE":
            raise ValueError("Google API key is not configured properly.")

    @llm_retry
    async def query(self, prompt: str, **kwargs) -> str:
        cached_response = await self.get_cached_response(prompt, model=self.model_name)
        if cached_response:
            return cached_response

        import google.generativeai as genai

        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(self.model_name)

        try:
            response = await model.generate_content_async(prompt)
            content = response.text if response.text else ""

            await self.cache_response(prompt, content, model=self.model_name)
            return content
        except Exception as e:
            logger.error(f"Error during Google API call: {e}")
            raise


class HttpProvider(LLMProvider):
    """Base class for HTTP-based providers like DeepSeek and Qwen (Async)."""
    
    def __init__(self, api_key: str, model: str, base_url: str):
        super().__init__()
        self.api_key = api_key
        self.model = model
        self.base_url = base_url

    @llm_retry
    async def query(self, prompt: str, **kwargs) -> str:
        temp = kwargs.get("temperature", 0.7)
        max_tokens = kwargs.get("max_tokens", 4096)
        
        cached_response = await self.get_cached_response(prompt, model=self.model, temperature=temp, max_tokens=max_tokens)
        if cached_response:
            return cached_response

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temp,
            "max_tokens": max_tokens
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(self.base_url, headers=headers, json=data)
                response.raise_for_status()

                full_response = response.json()
                content = full_response["choices"][0]["message"]["content"]

                await self.cache_response(prompt, content, model=self.model, temperature=temp, max_tokens=max_tokens)
                return content
        except Exception as e:
            logger.error(f"Error during API call to {self.base_url}: {e}")
            raise


class DeepSeekProvider(HttpProvider):
    def __init__(self, api_key: str, model: str = "deepseek-chat"):
        super().__init__(api_key, model, "https://api.deepseek.com/chat/completions")


class QwenProvider(HttpProvider):
    def __init__(self, api_key: str, model: str = "qwen3-max"):
        super().__init__(api_key, model, "https://api.mulerouter.ai/vendors/openai/v1/chat/completions")


class MistralProvider(LLMProvider):
    """LLM Provider for Mistral (Async)."""
    def __init__(self, api_key: str, model: str = "codestral-2508"):
        super().__init__()
        self.api_key = api_key
        self.model = model
        self.client = None

    @llm_retry
    async def query(self, prompt: str, **kwargs) -> str:
        cached_response = await self.get_cached_response(prompt, model=self.model)
        if cached_response:
            return cached_response

        from mistralai import Mistral

        if self.client is None:
            self.client = Mistral(api_key=self.api_key)

        try:
            chat_response = await self.client.chat.complete_async(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
            )

            if chat_response.choices:
                content = chat_response.choices[0].message.content
                await self.cache_response(prompt, content, model=self.model)
                return content
            return "Error: No response choices from API."
        except Exception as e:
            logger.error(f"Error during Mistral API call: {e}")
            raise


class ModelRouter:
    """Intelligent router that selects the best model based on task requirements."""

    def __init__(self):
        self.task_model_mapping = {
            'coding': ['qwen', 'mistral', 'deepseek'],
            'reasoning': ['anthropic', 'qwen', 'deepseek'],
            'creative': ['anthropic', 'qwen', 'deepseek'],
            'analysis': ['anthropic', 'qwen', 'deepseek'],
            'general': ['qwen', 'anthropic', 'mistral', 'deepseek']
        }

    def select_best_provider(self, task_type: str) -> str:
        candidates = self.task_model_mapping.get(task_type, ['qwen', 'anthropic', 'mistral'])
        return candidates[0]


def get_llm_provider(provider_name: str, **kwargs) -> LLMProvider:
    provider_name = provider_name.lower()
    api_key_env = f"{provider_name.upper()}_API_KEY"
    api_key = os.getenv(api_key_env)
    
    if not api_key and provider_name != 'google': # Google has its own check
         raise ValueError(f"{api_key_env} environment variable not set.")

    if provider_name == 'qwen':
        return QwenProvider(api_key=api_key, **kwargs)
    elif provider_name == 'mistral':
        return MistralProvider(api_key=api_key, **kwargs)
    elif provider_name == 'anthropic':
        return AnthropicProvider(api_key=api_key, **kwargs)
    elif provider_name == 'google':
        api_key = os.getenv("GOOGLE_API_KEY")
        return GoogleProvider(api_key=api_key, **kwargs)
    elif provider_name == 'deepseek':
        return DeepSeekProvider(api_key=api_key, **kwargs)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider_name}")


async def get_adaptive_provider(task_type: str = "general", **kwargs) -> Tuple[LLMProvider, str]:
    router = ModelRouter()
    best_provider_name = router.select_best_provider(task_type)
    provider = get_llm_provider(best_provider_name, **kwargs)
    return provider, best_provider_name