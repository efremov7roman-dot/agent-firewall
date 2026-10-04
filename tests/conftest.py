from collections.abc import Iterable
from datetime import UTC, datetime

from agent_firewall.domain import AgentIdentity, Capability, SecurityContext, ToolRequest

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)


def make_context(
    capabilities: Iterable[Capability] = (), *, evaluated_at: datetime = NOW
) -> SecurityContext:
    return SecurityContext(
        identity=AgentIdentity(
            agent_id="agent-1",
            principal="portfolio-demo",
            environment="sandbox",
        ),
        capabilities=tuple(capabilities),
        evaluated_at=evaluated_at,
    )


def make_request(tool: str, arguments: dict[str, object]) -> ToolRequest:
    return ToolRequest(
        trace_id="trace-1",
        agent_id="agent-1",
        tool=tool,
        arguments=arguments,
    )
