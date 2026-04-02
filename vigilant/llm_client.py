"""
vigilant/llm_client.py
────────────────────────
Unified LLM client that routes to Groq, OpenAI, or Anthropic based on
the LLM_PROVIDER setting. Keeps full provider stubs so swapping is one
env-var change.
"""

from __future__ import annotations

import logging
from typing import Any

from vigilant.config import LLMProvider, get_settings

logger = logging.getLogger(__name__)


class LLMClient:
    """
    Thin abstraction over multiple LLM providers.

    Usage:
        client = LLMClient()
        response = client.chat([
            {"role": "system", "content": "You are a C++ security expert."},
            {"role": "user", "content": "Explain this vulnerability..."},
        ])
    """

    def __init__(self, provider: LLMProvider | None = None) -> None:
        settings = get_settings()
        self.provider = provider or settings.llm_provider
        self.settings = settings
        self._client: Any = None
        self._init_client()

    # ── Provider initialization ───────────────────────────────────────────────

    def _init_client(self) -> None:
        if self.provider == LLMProvider.GROQ:
            self._init_groq()
        elif self.provider == LLMProvider.OPENAI:
            self._init_openai()
        elif self.provider == LLMProvider.ANTHROPIC:
            self._init_anthropic()
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def _init_groq(self) -> None:
        try:
            from groq import Groq  # type: ignore[import]
            self._client = Groq(api_key=self.settings.groq_api_key)
            self._model = self.settings.groq_model
            logger.info("LLMClient: Groq initialised (model=%s)", self._model)
        except ImportError as e:
            raise ImportError("groq package not installed. Run: pip install groq") from e

    def _init_openai(self) -> None:
        try:
            from openai import OpenAI  # type: ignore[import]
            self._client = OpenAI(api_key=self.settings.openai_api_key)
            self._model = self.settings.openai_model
            logger.info("LLMClient: OpenAI initialised (model=%s)", self._model)
        except ImportError as e:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            ) from e

    def _init_anthropic(self) -> None:
        try:
            from anthropic import Anthropic  # type: ignore[import]
            self._client = Anthropic(api_key=self.settings.anthropic_api_key)
            self._model = self.settings.anthropic_model
            logger.info("LLMClient: Anthropic initialised (model=%s)", self._model)
        except ImportError as e:
            raise ImportError(
                "anthropic package not installed. Run: pip install anthropic"
            ) from e

    # ── Public interface ──────────────────────────────────────────────────────

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> str:
        try:
            if self.provider == LLMProvider.GROQ:
                return self._chat_groq(messages, temperature, max_tokens)
            elif self.provider == LLMProvider.OPENAI:
                return self._chat_openai(messages, temperature, max_tokens)
            elif self.provider == LLMProvider.ANTHROPIC:
                return self._chat_anthropic(messages, temperature, max_tokens)
        except Exception as e:
            if "rate_limit_exceeded" in str(e).lower() or "429" in str(e):
                logger.warning("LLMClient: Rate limit exceeded for %s. Attempting fallback.", self.provider)
                return self._fallback_chat(messages, temperature, max_tokens)
            raise e
        raise ValueError(f"Unknown provider: {self.provider}")

    def _fallback_chat(self, messages: list[dict[str, str]], temperature: float, max_tokens: int) -> str:
        # Try OpenAI if not already used
        if self.provider != LLMProvider.OPENAI and self.settings.openai_api_key:
            logger.info("LLMClient: Falling back to OpenAI")
            # Use a one-off client to avoid mutating self
            try:
                from openai import OpenAI
                temp_client = OpenAI(api_key=self.settings.openai_api_key)
                response = temp_client.chat.completions.create(
                    model=self.settings.openai_model,
                    messages=messages,  # type: ignore[arg-type]
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                logger.error("LLMClient: OpenAI fallback failed: %s", e)
        
        # Try Anthropic
        if self.provider != LLMProvider.ANTHROPIC and self.settings.anthropic_api_key:
            logger.info("LLMClient: Falling back to Anthropic")
            try:
                from anthropic import Anthropic
                temp_client = Anthropic(api_key=self.settings.anthropic_api_key)
                
                system_content = ""
                user_messages = []
                for msg in messages:
                    if msg["role"] == "system":
                        system_content += msg["content"] + "\n"
                    else:
                        user_messages.append(msg)

                kwargs: dict[str, Any] = {
                    "model": self.settings.anthropic_model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "messages": user_messages,
                }
                if system_content:
                    kwargs["system"] = system_content.strip()

                response = temp_client.messages.create(**kwargs)
                return response.content[0].text if response.content else ""
            except Exception as e:
                logger.error("LLMClient: Anthropic fallback failed: %s", e)
            
        raise RuntimeError("LLMClient: All fallback providers failed or were not configured.")

    # ── Provider implementations ──────────────────────────────────────────────

    def _chat_groq(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=messages,  # type: ignore[arg-type]
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content or ""

    def _chat_openai(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=messages,  # type: ignore[arg-type]
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content or ""

    def _chat_anthropic(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> str:
        # Anthropic separates system prompt from user turns
        system_content = ""
        user_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_content += msg["content"] + "\n"
            else:
                user_messages.append(msg)

        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": user_messages,
        }
        if system_content:
            kwargs["system"] = system_content.strip()

        response = self._client.messages.create(**kwargs)
        return response.content[0].text if response.content else ""

    # ── Convenience helpers ───────────────────────────────────────────────────

    def ask(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        """One-shot convenience wrapper."""
        return self.chat(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            **kwargs,
        )
