"""Native Ollama chat/tool-call adapter; no model response is an authorization grant."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from agent_firewall.agent.models import (
    AgentTask,
    ModelTurn,
    ProposedToolCall,
    ToolOutcome,
    ToolSpec,
)
from agent_firewall.agent.provider import ModelSession, ProviderError


class OllamaTransport(Protocol):
    def chat(self, url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]: ...


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise ProviderError("Ollama endpoint redirected")


class HttpOllamaTransport:
    def chat(self, url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        request = Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with build_opener(_RejectRedirects()).open(request, timeout=timeout) as response:
                body = response.read(8_000_001)
                if len(body) > 8_000_000:
                    raise ProviderError("Ollama response exceeded size limit")
                value = json.loads(body)
        except HTTPError as error:
            raise ProviderError(f"Ollama returned HTTP {error.code}") from None
        except (URLError, TimeoutError, OSError, json.JSONDecodeError):
            raise ProviderError("Ollama connection or response failed") from None
        if not isinstance(value, dict):
            raise ProviderError("Ollama returned an invalid response")
        return cast(dict[str, Any], value)


class OllamaProvider:
    def __init__(
        self,
        *,
        model: str = "qwen3:8b",
        base_url: str = "http://127.0.0.1:11434",
        timeout_seconds: float = 120,
        temperature: float = 0,
        seed: int = 42,
        transport: OllamaTransport | None = None,
    ) -> None:
        if not model.strip() or timeout_seconds <= 0:
            raise ValueError("model and positive timeout are required")
        try:
            endpoint = urlsplit(base_url)
            local = (
                endpoint.scheme == "http"
                and endpoint.hostname in {"127.0.0.1", "localhost"}
                and endpoint.port is not None
                and endpoint.username is None
                and endpoint.password is None
                and endpoint.path in {"", "/"}
                and not endpoint.query
                and not endpoint.fragment
            )
        except ValueError:
            local = False
        if not local:
            raise ValueError("Ollama must use a local loopback endpoint")
        self.model = model
        self.url = base_url.rstrip("/") + "/api/chat"
        self.timeout_seconds = timeout_seconds
        self.temperature = temperature
        self.seed = seed
        self.transport = transport or HttpOllamaTransport()
        self.request_count = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.turn_signatures: list[str] = []

    def start_session(
        self, *, task: AgentTask, tools: tuple[ToolSpec, ...], system_instruction: str
    ) -> ModelSession:
        return _OllamaSession(self, task, tools, system_instruction)


class _OllamaSession:
    def __init__(
        self, provider: OllamaProvider, task: AgentTask, tools: tuple[ToolSpec, ...], system: str
    ) -> None:
        self.provider = provider
        self.messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "instruction": task.user_instruction,
                        "external_content": [
                            item.model_dump(mode="json") for item in task.external_content
                        ],
                    },
                    ensure_ascii=False,
                ),
            },
        ]
        self.tools = [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                },
            }
            for tool in tools
        ]
        self.pending_ids: list[str] = []
        self.pending_names: dict[str, str] = {}

    def next_turn(self, outcomes: tuple[ToolOutcome, ...] = ()) -> ModelTurn:
        if [outcome.call_id for outcome in outcomes] != self.pending_ids:
            raise ProviderError("tool outcome IDs do not match pending calls")
        for outcome in outcomes:
            self.messages.append(
                {
                    "role": "tool",
                    "tool_name": self.pending_names[outcome.call_id],
                    "content": outcome.output,
                }
            )
        self.pending_ids = []
        self.pending_names = {}
        response = self.provider.transport.chat(
            self.provider.url,
            {
                "model": self.provider.model,
                "messages": self.messages,
                "tools": self.tools,
                "stream": False,
                "think": False,
                "options": {"temperature": self.provider.temperature, "seed": self.provider.seed},
            },
            self.provider.timeout_seconds,
        )
        self.provider.request_count += 1
        self.provider.prompt_tokens += int(response.get("prompt_eval_count") or 0)
        self.provider.completion_tokens += int(response.get("eval_count") or 0)
        message = response.get("message")
        if not isinstance(message, dict):
            raise ProviderError("Ollama response is missing a message")
        raw_calls = message.get("tool_calls", [])
        if not isinstance(raw_calls, list):
            raise ProviderError("Ollama returned malformed tool calls")
        self.provider.turn_signatures.append(
            hashlib.sha256(json.dumps(raw_calls, sort_keys=True).encode()).hexdigest()
        )
        calls: list[ProposedToolCall] = []
        for raw in raw_calls:
            if not isinstance(raw, dict) or not isinstance(raw.get("function"), dict):
                raise ProviderError("Ollama returned a malformed tool call")
            function = raw["function"]
            arguments = function.get("arguments")
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    raise ProviderError("Ollama returned invalid tool arguments") from None
            if not isinstance(function.get("name"), str) or not isinstance(arguments, dict):
                raise ProviderError("Ollama returned invalid tool arguments")
            calls.append(
                ProposedToolCall(
                    call_id=uuid4().hex,
                    name=function["name"],
                    arguments=arguments,
                )
            )
        content = message.get("content", "")
        if not isinstance(content, str):
            raise ProviderError("Ollama returned invalid message content")
        self.messages.append({"role": "assistant", "content": content, "tool_calls": raw_calls})
        self.pending_ids = [call.call_id for call in calls]
        self.pending_names = {call.call_id: call.name for call in calls}
        return ModelTurn(text=content, tool_calls=tuple(calls))
