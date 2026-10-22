"""Independent regressions for concrete live integration failures."""

from __future__ import annotations

from time import sleep
from typing import Any

import pytest
from conftest import make_context

from agent_firewall.agent import AgentRunStatus, AgentTask, LangGraphFinancialAgent, ModelTurn
from agent_firewall.agent.ollama_provider import OllamaProvider, _RejectRedirects
from agent_firewall.agent.provider import ProviderError


@pytest.mark.parametrize(
    "url",
    (
        "http://127.0.0.1:11434@remote.example",
        "http://localhost:11434@remote.example",
        "http://127.0.0.1:11434/../../api",
    ),
)
def test_ollama_endpoint_cannot_escape_loopback(url: str) -> None:
    with pytest.raises(ValueError, match="loopback"):
        OllamaProvider(base_url=url)


class SlowSession:
    def next_turn(self, outcomes: tuple[Any, ...] = ()) -> ModelTurn:
        del outcomes
        sleep(0.1)
        return ModelTurn(text="Finished after deadline")


class SlowProvider:
    def start_session(self, **kwargs: Any) -> SlowSession:
        del kwargs
        return SlowSession()


def test_late_model_completion_is_reported_as_timeout() -> None:
    agent = LangGraphFinancialAgent(
        provider=SlowProvider(),
        context_provider=make_context,
        timeout_seconds=0.05,
    )
    result = agent.run(AgentTask(trace_id="deadline", user_instruction="Read portfolio"))
    assert result.status is AgentRunStatus.TIMEOUT
    assert agent.gateway.audit_events == ()


def test_ollama_http_redirect_is_rejected() -> None:
    with pytest.raises(ProviderError, match="redirected"):
        _RejectRedirects().redirect_request(None, None, 302, "Found", {}, "https://remote.example")
