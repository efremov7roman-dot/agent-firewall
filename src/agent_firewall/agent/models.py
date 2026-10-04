"""Typed agent/provider messages with explicit trust classification."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_firewall.gateway import GatewayResult


class AgentModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ContentTrust(StrEnum):
    TRUSTED_SYSTEM = "TRUSTED_SYSTEM"
    UNTRUSTED_USER = "UNTRUSTED_USER"
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"
    UNTRUSTED_TOOL = "UNTRUSTED_TOOL"
    UNTRUSTED_MODEL = "UNTRUSTED_MODEL"


class ExternalContent(AgentModel):
    source: str = Field(min_length=1)
    content: str
    trust: ContentTrust = ContentTrust.UNTRUSTED_EXTERNAL

    @field_validator("trust")
    @classmethod
    def require_external_trust(cls, value: ContentTrust) -> ContentTrust:
        if value is not ContentTrust.UNTRUSTED_EXTERNAL:
            raise ValueError("external content must remain untrusted")
        return value


class AgentTask(AgentModel):
    trace_id: str = Field(min_length=1)
    user_instruction: str = Field(min_length=1)
    external_content: tuple[ExternalContent, ...] = ()


class ToolSpec(AgentModel):
    name: str
    description: str
    parameters: dict[str, Any]


class ProposedToolCall(AgentModel):
    call_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    arguments: dict[str, Any]
    trust: ContentTrust = ContentTrust.UNTRUSTED_MODEL

    @field_validator("trust")
    @classmethod
    def require_model_trust(cls, value: ContentTrust) -> ContentTrust:
        if value is not ContentTrust.UNTRUSTED_MODEL:
            raise ValueError("model tool calls must remain untrusted")
        return value


class ModelTurn(AgentModel):
    response_id: str | None = None
    text: str = ""
    tool_calls: tuple[ProposedToolCall, ...] = ()

    @field_validator("tool_calls")
    @classmethod
    def unique_call_ids(cls, value: tuple[ProposedToolCall, ...]) -> tuple[ProposedToolCall, ...]:
        call_ids = [call.call_id for call in value]
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("tool call IDs must be unique within a turn")
        return value


class ToolOutcome(AgentModel):
    call_id: str
    output: str
    trust: ContentTrust = ContentTrust.UNTRUSTED_TOOL

    @field_validator("trust")
    @classmethod
    def require_tool_trust(cls, value: ContentTrust) -> ContentTrust:
        if value is not ContentTrust.UNTRUSTED_TOOL:
            raise ValueError("tool output must remain untrusted")
        return value


class AgentRunStatus(StrEnum):
    COMPLETED = "COMPLETED"
    TOOL_LIMIT_REACHED = "TOOL_LIMIT_REACHED"
    PROVIDER_ERROR = "PROVIDER_ERROR"


class AgentRunResult(AgentModel):
    trace_id: str
    status: AgentRunStatus
    final_text: str = ""
    gateway_results: tuple[GatewayResult, ...] = ()
    provider_error: str | None = None
