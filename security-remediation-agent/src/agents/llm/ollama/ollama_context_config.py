import math
import os
from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class OllamaContextConfig:
    model: str | None = None
    
    DEFAULT_TIMEOUT: ClassVar[int] = 600
    DEFAULT_MODEL_NAME: ClassVar[str] = "qwen3:4b-instruct"
    DEFAULT_CONTEXT_LENGTH: ClassVar[int] = 16_384
    MAX_CONTEXT_LENGTH: ClassVar[int] = 32_768

    context_size: int | None = None
    timeout: float | None = None

    def __post_init__(self) -> None:
        size = self.context_size
        if size is None:
            size = int(os.getenv("OLLAMA_CONTEXT_LENGTH", str(self.DEFAULT_CONTEXT_LENGTH)))

        if not 0 < size <= self.MAX_CONTEXT_LENGTH:
            raise ValueError(
                f"context_size must be between 1 and {self.MAX_CONTEXT_LENGTH}"
            )

        object.__setattr__(self, "context_size", size)
        model = self.model or os.getenv("OLLAMA_MODEL", self.DEFAULT_MODEL_NAME)
        if not model.strip():
            raise ValueError("Provide an Ollama model or set OLLAMA_MODEL")
        timeout = float(self.timeout if self.timeout is not None
                        else os.getenv("OLLAMA_TIMEOUT_SECONDS", str(self.DEFAULT_TIMEOUT)))
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        object.__setattr__(self, "model", model)
        object.__setattr__(self, "timeout", timeout)
