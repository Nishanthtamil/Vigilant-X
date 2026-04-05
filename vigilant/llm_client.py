"""
vigilant/llm_client.py
────────────────────────
Unified LLM client that routes to Groq, OpenAI, or Anthropic based on
the LLM_PROVIDER setting. Keeps full provider stubs so swapping is one
env-var change.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception,
)

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

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception(
            lambda e: "rate_limit_exceeded" in str(e).lower() or "429" in str(e)
        ),
        reraise=True,
    )
    def _chat_with_retry(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> str:
        if self.provider == LLMProvider.GROQ:
            return self._chat_groq(messages, temperature, max_tokens, json_mode)
        elif self.provider == LLMProvider.OPENAI:
            return self._chat_openai(messages, temperature, max_tokens, json_mode)
        elif self.provider == LLMProvider.ANTHROPIC:
            return self._chat_anthropic(messages, temperature, max_tokens, json_mode)
        raise ValueError(f"Unknown provider: {self.provider}")

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 4096,
        json_mode: bool = False,
    ) -> str:
        try:
            return self._chat_with_retry(messages, temperature, max_tokens, json_mode)
        except Exception as e:
            if "rate_limit_exceeded" in str(e).lower() or "429" in str(e):
                logger.warning(
                    "LLMClient: %s rate-limited after retries. Falling back to next provider.",
                    self.provider,
                )
                return self._fallback_chat(messages, temperature, max_tokens, json_mode)
            raise

    def _fallback_chat(self, messages: list[dict[str, str]], temperature: float, max_tokens: int, json_mode: bool = False) -> str:
        # Try OpenAI if not already used
        if self.provider != LLMProvider.OPENAI and self.settings.openai_api_key:
            logger.info("LLMClient: Falling back to OpenAI")
            # Use a one-off client to avoid mutating self
            try:
                from openai import OpenAI
                temp_client = OpenAI(api_key=self.settings.openai_api_key)
                kwargs: dict[str, Any] = {
                    "model": self.settings.openai_model,
                    "messages": messages,  # type: ignore[arg-type]
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
                if json_mode:
                    kwargs["response_format"] = {"type": "json_object"}

                response = temp_client.chat.completions.create(**kwargs)
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
                final_user_messages = []
                for msg in messages:
                    if msg["role"] == "system":
                        system_content += msg["content"] + "\n"
                    else:
                        final_user_messages.append(msg.copy())    # FIXED: copy

                if json_mode and final_user_messages:
                    final_user_messages[-1]["content"] += "\n\nReturn ONLY a JSON object. No prose."

                kwargs: dict[str, Any] = {
                    "model": self.settings.anthropic_model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "messages": final_user_messages,
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
        json_mode: bool = False,
    ) -> str:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,  # type: ignore[arg-type]
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
            
        response = self._client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or ""

    def _chat_openai(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        json_mode: bool = False,
    ) -> str:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,  # type: ignore[arg-type]
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
            
        response = self._client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or ""

    def _chat_anthropic(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        json_mode: bool = False,
    ) -> str:
        # Anthropic separates system prompt from user turns
        system_content = ""
        user_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_content += msg["content"] + "\n"
            else:
                user_messages.append(msg.copy())

        if json_mode and user_messages:
            user_messages[-1]["content"] += "\n\nReturn ONLY a JSON object. No prose."

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

    def ask_json(self, system_prompt: str, user_prompt: str, schema_cls: type, **kwargs: Any) -> Any:
        """One-shot convenience wrapper that returns a validated Pydantic model."""
        import json
        raw = self.chat(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            json_mode=True,
            **kwargs,
        )
        try:
            # Strip potential markdown fences even in JSON mode, as some providers are stubborn
            raw_clean = re.sub(r"```(?:json)?", "", raw).strip().strip("`")
            data = json.loads(raw_clean)
            return schema_cls.model_validate(data)
        except Exception as e:
            logger.error("LLMClient: JSON validation failed: %s. Raw response: %s", e, raw)
            raise ValueError(f"LLM produced invalid JSON for schema {schema_cls.__name__}: {e}")
