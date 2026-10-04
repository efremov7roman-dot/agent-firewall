"""Action-bound, expiring, single-use approval workflow."""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from agent_firewall.domain import Decision, PolicyDecision, SecurityContext, ToolRequest


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"


class ApprovalErrorCode(StrEnum):
    UNKNOWN_APPROVAL = "UNKNOWN_APPROVAL"
    UNAUTHORIZED_APPROVER = "UNAUTHORIZED_APPROVER"
    INVALID_APPROVAL_STATE = "INVALID_APPROVAL_STATE"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"


class ApprovalError(RuntimeError):
    def __init__(self, code: ApprovalErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


class ApprovalModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ApprovalRecord(ApprovalModel):
    approval_id: str
    agent_id: str
    principal: str
    environment: str
    tool: str
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    normalized_arguments: dict[str, Any]
    reason: str
    requested_at: datetime
    expires_at: datetime
    status: ApprovalStatus
    authority: str | None = None
    resolved_at: datetime | None = None
    consumed_at: datetime | None = None


class ApprovalCheck(ApprovalModel):
    approved: bool
    approval_id: str | None = None
    status: ApprovalStatus | None = None


class ApprovalLedger(ApprovalModel):
    allowed_authorities: frozenset[str]
    records: tuple[ApprovalRecord, ...]


class ApprovalVerifier(Protocol):
    def check(
        self,
        *,
        request: ToolRequest,
        decision: PolicyDecision,
        context: SecurityContext,
    ) -> ApprovalCheck: ...


class DenyAllApprovalVerifier:
    """Safe default until an explicit trusted approval manager is supplied."""

    def check(
        self,
        *,
        request: ToolRequest,
        decision: PolicyDecision,
        context: SecurityContext,
    ) -> ApprovalCheck:
        del request, decision, context
        return ApprovalCheck(approved=False)


class ApprovalManager:
    """Manage exact-action approvals without delegating authority to the model."""

    def __init__(
        self,
        *,
        allowed_authorities: frozenset[str],
        default_ttl: timedelta = timedelta(minutes=5),
        storage_path: Path | None = None,
        initial_records: tuple[ApprovalRecord, ...] = (),
    ) -> None:
        if not allowed_authorities:
            raise ValueError("at least one approval authority is required")
        if default_ttl <= timedelta(0):
            raise ValueError("default_ttl must be positive")
        self._allowed_authorities = allowed_authorities
        self._default_ttl = default_ttl
        self._storage_path = storage_path
        self._records = {record.approval_id: record for record in initial_records}
        self._lock = RLock()
        if len(self._records) != len(initial_records):
            raise ValueError("approval IDs must be unique")

    @property
    def records(self) -> tuple[ApprovalRecord, ...]:
        with self._lock:
            return tuple(self._records.values())

    def get(self, approval_id: str) -> ApprovalRecord:
        with self._lock, self._storage_guard():
            self._reload_unlocked()
            return self._get_unlocked(approval_id)

    def check(
        self,
        *,
        request: ToolRequest,
        decision: PolicyDecision,
        context: SecurityContext,
    ) -> ApprovalCheck:
        with self._lock, self._storage_guard():
            self._reload_unlocked()
            return self._check_unlocked(request=request, decision=decision, context=context)

    def _check_unlocked(
        self,
        *,
        request: ToolRequest,
        decision: PolicyDecision,
        context: SecurityContext,
    ) -> ApprovalCheck:
        if decision.decision is not Decision.REQUIRE_APPROVAL:
            return ApprovalCheck(approved=False)
        digest = action_digest(request, decision, context)
        matching = [
            record
            for record in reversed(tuple(self._records.values()))
            if record.agent_id == context.identity.agent_id
            and record.principal == context.identity.principal
            and record.environment == context.identity.environment
            and record.tool == request.tool
            and record.action_digest == digest
            and record.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
        ]
        for record in matching:
            if context.evaluated_at < record.requested_at:
                continue
            if context.evaluated_at >= record.expires_at:
                self._replace_unlocked(
                    record.model_copy(
                        update={
                            "status": ApprovalStatus.EXPIRED,
                            "resolved_at": context.evaluated_at,
                        }
                    )
                )
                continue
            if record.status is ApprovalStatus.APPROVED:
                consumed = record.model_copy(
                    update={
                        "status": ApprovalStatus.CONSUMED,
                        "consumed_at": context.evaluated_at,
                    }
                )
                self._replace_unlocked(consumed)
                return ApprovalCheck(
                    approved=True,
                    approval_id=consumed.approval_id,
                    status=consumed.status,
                )
            return ApprovalCheck(
                approved=False,
                approval_id=record.approval_id,
                status=record.status,
            )

        normalized = decision.normalized_arguments
        if normalized is None:
            return ApprovalCheck(approved=False)
        record = ApprovalRecord(
            approval_id=uuid4().hex,
            agent_id=context.identity.agent_id,
            principal=context.identity.principal,
            environment=context.identity.environment,
            tool=request.tool,
            action_digest=digest,
            normalized_arguments=normalized,
            reason=decision.reason.value,
            requested_at=context.evaluated_at,
            expires_at=context.evaluated_at + self._default_ttl,
            status=ApprovalStatus.PENDING,
        )
        self._replace_unlocked(record)
        return ApprovalCheck(
            approved=False,
            approval_id=record.approval_id,
            status=record.status,
        )

    def approve(self, approval_id: str, *, authority: str, at: datetime) -> ApprovalRecord:
        with self._lock, self._storage_guard():
            self._reload_unlocked()
            self._require_authority(authority)
            record = self._get_unlocked(approval_id)
            self._require_pending_and_current(record, at)
            approved = record.model_copy(
                update={
                    "status": ApprovalStatus.APPROVED,
                    "authority": authority,
                    "resolved_at": at,
                }
            )
            self._replace_unlocked(approved)
            return approved

    def reject(self, approval_id: str, *, authority: str, at: datetime) -> ApprovalRecord:
        with self._lock, self._storage_guard():
            self._reload_unlocked()
            self._require_authority(authority)
            record = self._get_unlocked(approval_id)
            self._require_pending_and_current(record, at)
            rejected = record.model_copy(
                update={
                    "status": ApprovalStatus.REJECTED,
                    "authority": authority,
                    "resolved_at": at,
                }
            )
            self._replace_unlocked(rejected)
            return rejected

    def save(self, path: Path | None = None) -> Path:
        with self._lock:
            target = path or self._storage_path
            if target is None:
                raise ValueError("approval storage path is not configured")
            with self._storage_guard(target):
                self._persist_unlocked(target)
                return target

    @classmethod
    def from_file(
        cls, path: Path, *, default_ttl: timedelta = timedelta(minutes=5)
    ) -> ApprovalManager:
        ledger = ApprovalLedger.model_validate_json(path.read_text(encoding="utf-8"))
        return cls(
            allowed_authorities=ledger.allowed_authorities,
            default_ttl=default_ttl,
            storage_path=path,
            initial_records=ledger.records,
        )

    def _replace_unlocked(self, record: ApprovalRecord) -> None:
        self._records[record.approval_id] = record
        if self._storage_path is not None:
            self._persist_unlocked(self._storage_path)

    def _persist_unlocked(self, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        ledger = ApprovalLedger(
            allowed_authorities=self._allowed_authorities,
            records=tuple(self._records.values()),
        )
        temporary = target.with_suffix(target.suffix + f".{uuid4().hex}.tmp")
        temporary.write_text(ledger.model_dump_json(indent=2), encoding="utf-8")
        temporary.replace(target)

    def _reload_unlocked(self) -> None:
        if self._storage_path is None or not self._storage_path.exists():
            return
        ledger = ApprovalLedger.model_validate_json(self._storage_path.read_text(encoding="utf-8"))
        self._allowed_authorities = ledger.allowed_authorities
        self._records = {record.approval_id: record for record in ledger.records}

    def _get_unlocked(self, approval_id: str) -> ApprovalRecord:
        try:
            return self._records[approval_id]
        except KeyError:
            raise ApprovalError(ApprovalErrorCode.UNKNOWN_APPROVAL) from None

    @contextmanager
    def _storage_guard(self, path: Path | None = None) -> Iterator[None]:
        target = path or self._storage_path
        if target is None:
            yield
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        lock_path = target.with_suffix(target.suffix + ".lock")
        deadline = time.monotonic() + 5
        descriptor: int | None = None
        while descriptor is None:
            try:
                descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("approval ledger lock acquisition timed out") from None
                time.sleep(0.01)
        os.close(descriptor)
        try:
            yield
        finally:
            lock_path.unlink(missing_ok=True)

    def _require_authority(self, authority: str) -> None:
        if authority not in self._allowed_authorities:
            raise ApprovalError(ApprovalErrorCode.UNAUTHORIZED_APPROVER)

    def _require_pending_and_current(self, record: ApprovalRecord, at: datetime) -> None:
        if at.utcoffset() is None or at < record.requested_at:
            raise ApprovalError(ApprovalErrorCode.INVALID_APPROVAL_STATE)
        if at >= record.expires_at:
            expired = record.model_copy(
                update={"status": ApprovalStatus.EXPIRED, "resolved_at": at}
            )
            self._replace_unlocked(expired)
            raise ApprovalError(ApprovalErrorCode.APPROVAL_EXPIRED)
        if record.status is not ApprovalStatus.PENDING:
            raise ApprovalError(ApprovalErrorCode.INVALID_APPROVAL_STATE)


def action_digest(
    request: ToolRequest,
    decision: PolicyDecision,
    context: SecurityContext,
) -> str:
    payload = {
        "agent_id": request.agent_id,
        "principal": context.identity.principal,
        "environment": context.identity.environment,
        "tool": request.tool,
        "arguments": decision.model_dump(mode="json")["normalized_arguments"],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
