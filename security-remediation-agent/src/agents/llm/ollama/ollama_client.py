"""Shared async Ollama transport; callers own prompts and response validation."""
import asyncio
import logging
import os
import time
from typing import Any

from httpx import TimeoutException

from .ollama_context_config import OllamaContextConfig

logger = logging.getLogger(__name__)


class OllamaClient:
    def __init__(self, contextConfig: OllamaContextConfig, host: str | None = None,
                 client: Any = None):
        self.contextConfig = contextConfig
        if client is None:
            try:
                from ollama import AsyncClient
            except ImportError as exc:
                raise RuntimeError('Install Ollama support with pip install -e ".[ai]"') from exc
            client = AsyncClient(host=host or os.getenv("OLLAMA_HOST", "http://localhost:11434"),
                                 timeout=contextConfig.timeout)
        self.client = client

    async def is_available(self) -> bool:
        """Require a reachable server with the configured model installed."""
        try:
            response = await asyncio.wait_for(self.client.list(), timeout=10)
            expected = self.contextConfig.model
            return any(model.get("model") == expected for model in response["models"])
        except Exception as exc:
            logger.warning("Ollama availability check failed: %s", exc)
            return False

    async def run(self, payload: str, messages: list[dict[str, Any]], *,
                  format: str | dict[str, Any] | None = "json", tools: list | None = None) -> Any:
        started = time.monotonic()
        config = self.contextConfig
        logger.info("Ollama input: %s", payload)
        logger.info("Ollama request: model=%s, timeout=%ss, context=%d",
                    config.model, config.timeout, config.context_size)
        try:
            extra = {}
            if format is not None:
                extra["format"] = format
            if tools:
                extra["tools"] = tools
            return await asyncio.wait_for(self.client.chat(
                model=config.model, stream=False, **extra,
                options={"temperature": 0, "num_ctx": config.context_size},
                messages=messages,
            ), timeout=config.timeout)
        except (TimeoutException, asyncio.TimeoutError) as exc:
            raise RuntimeError(
                f"Ollama timed out for model {config.model!r} after "
                f"{time.monotonic() - started:.1f}s (limit={config.timeout:g}s). "
                "Check 'ollama ps' and server logs; adjust OLLAMA_TIMEOUT_SECONDS if needed."
            ) from exc
        except Exception as exc:
            if "context size" in str(exc).lower() or "context length" in str(exc).lower():
                raise RuntimeError(
                    f"Ollama context exceeded for model {config.model!r} "
                    f"(requested context={config.context_size}): {exc}. "
                    "Increase OLLAMA_CONTEXT_LENGTH within available memory or reduce the input."
                ) from exc
            raise RuntimeError(
                f"Ollama request failed for model {config.model!r}: {type(exc).__name__}: {exc}"
            ) from exc
