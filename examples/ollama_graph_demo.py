"""Run a local native-tool-call graph against the sandbox firewall."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from uuid import uuid4

from agent_firewall.agent import AgentTask, LangGraphFinancialAgent, OllamaProvider
from agent_firewall.domain import AgentIdentity, Capability, CapabilityName, SecurityContext


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("task", nargs="?", default="Get the BTCUSDT price, then show my portfolio.")
    parser.add_argument("--model", default="qwen3:8b")
    args = parser.parse_args()

    def current_context() -> SecurityContext:
        return SecurityContext(
            identity=AgentIdentity(agent_id="local-agent", principal="demo", environment="sandbox"),
            capabilities=(
                Capability(name=CapabilityName.MARKET_READ, agent_id="local-agent"),
                Capability(name=CapabilityName.PORTFOLIO_READ, agent_id="local-agent"),
            ),
            evaluated_at=datetime.now(UTC),
        )

    agent = LangGraphFinancialAgent(
        provider=OllamaProvider(model=args.model),
        context_provider=current_context,
        timeout_seconds=300,
    )
    result = agent.run(AgentTask(trace_id=uuid4().hex, user_instruction=args.task))
    print(
        json.dumps(
            {
                "status": result.status.value,
                "final_text": result.final_text,
                "gateway_statuses": [item.status.value for item in result.gateway_results],
                "trace": agent.last_trace,
                "audit_events": len(agent.gateway.audit_events),
                "error": result.provider_error,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
