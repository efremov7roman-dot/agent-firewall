"""Structured in-memory and JSONL audit recorders."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from threading import RLock
from typing import Protocol

from agent_firewall.gateway.models import GatewayAuditEvent, GatewayStatus


class AuditRecorder(Protocol):
    @property
    def events(self) -> tuple[GatewayAuditEvent, ...]: ...

    def record(self, event: GatewayAuditEvent) -> None: ...


class InMemoryAuditRecorder:
    def __init__(self) -> None:
        self._events: list[GatewayAuditEvent] = []
        self._lock = RLock()

    @property
    def events(self) -> tuple[GatewayAuditEvent, ...]:
        with self._lock:
            return tuple(event.model_copy(deep=True) for event in self._events)

    def record(self, event: GatewayAuditEvent) -> None:
        with self._lock:
            previous = self._events[-1].event_hash if self._events else None
            self._events.append(_seal_event(event, previous))

    def verify_integrity(self) -> bool:
        with self._lock:
            return _verify_chain(tuple(self._events))


class JsonlAuditRecorder:
    """Append-only local recorder suitable for developer inspection and replay."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = RLock()

    @property
    def events(self) -> tuple[GatewayAuditEvent, ...]:
        with self._lock:
            if not self.path.exists():
                return ()
            return tuple(
                GatewayAuditEvent.model_validate_json(line)
                for line in self.path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )

    def record(self, event: GatewayAuditEvent) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            existing = self.events
            previous = existing[-1].event_hash if existing else None
            sealed = _seal_event(event, previous)
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(sealed.model_dump_json())
                stream.write("\n")
                stream.flush()

    def verify_integrity(self) -> bool:
        with self._lock:
            return _verify_chain(self.events)

    def query(
        self,
        *,
        trace_id: str | None = None,
        status: GatewayStatus | None = None,
    ) -> tuple[GatewayAuditEvent, ...]:
        return tuple(
            event
            for event in self.events
            if (trace_id is None or event.trace_id == trace_id)
            and (status is None or event.status is status)
        )


def _event_digest(event: GatewayAuditEvent, previous_hash: str | None) -> str:
    payload = event.model_dump(mode="json", exclude={"event_hash", "previous_event_hash"})
    encoded = json.dumps(
        {"previous_event_hash": previous_hash, "event": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _seal_event(event: GatewayAuditEvent, previous_hash: str | None) -> GatewayAuditEvent:
    copied = event.model_copy(deep=True, update={"previous_event_hash": previous_hash})
    return copied.model_copy(update={"event_hash": _event_digest(copied, previous_hash)})


def _verify_chain(events: tuple[GatewayAuditEvent, ...]) -> bool:
    previous: str | None = None
    for event in events:
        if event.previous_event_hash != previous:
            return False
        if event.event_hash != _event_digest(event, previous):
            return False
        previous = event.event_hash
    return True
