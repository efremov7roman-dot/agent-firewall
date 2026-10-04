"""Optional live-model smoke run; requires explicit environment configuration."""

from datetime import UTC, datetime

from agent_firewall import (
    AgentIdentity,
    AgentTask,
    Capability,
    CapabilityName,
    FinancialAgent,
    OpenAIResponsesProvider,
    SecurityContext,
)


def main() -> None:
    provider = OpenAIResponsesProvider.from_environment()
    agent = FinancialAgent(provider=provider)
    context = SecurityContext(
        identity=AgentIdentity(
            agent_id="openai-demo",
            principal="local-developer",
            environment="sandbox",
        ),
        capabilities=(Capability(name=CapabilityName.MARKET_READ, agent_id="openai-demo"),),
        evaluated_at=datetime.now(UTC),
    )
    result = agent.run(
        AgentTask(trace_id="openai-price-demo", user_instruction="What is the BTC price?"),
        context,
    )
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
