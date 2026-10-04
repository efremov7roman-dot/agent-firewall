"""Provider-facing tool specifications derived from the trusted registry."""

from __future__ import annotations

from agent_firewall.agent.models import ToolSpec
from agent_firewall.domain import INITIAL_TOOL_REGISTRY, ToolRegistry

TOOL_DESCRIPTIONS = {
    "get_market_price": "Read the deterministic sandbox price for one symbol.",
    "get_portfolio": "Read sandbox balances and positions.",
    "get_open_orders": "Read open sandbox orders, optionally filtered by symbol.",
    "create_order": "Create a sandbox order using a USD notional.",
    "cancel_order": "Cancel one sandbox order by ID.",
    "transfer_asset": "Transfer a USD-valued amount of an asset in the sandbox.",
    "withdraw_asset": "Withdraw a USD-valued amount from the sandbox; approval is required.",
}


def build_tool_specs(registry: ToolRegistry = INITIAL_TOOL_REGISTRY) -> tuple[ToolSpec, ...]:
    return tuple(
        ToolSpec(
            name=definition.name,
            description=TOOL_DESCRIPTIONS[definition.name],
            parameters=definition.arguments_model.model_json_schema(),
        )
        for definition in registry.definitions
    )
