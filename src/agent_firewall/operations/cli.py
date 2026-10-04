"""Read-only CLI for approval, audit, and deterministic replay inspection."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from agent_firewall.gateway import (
    ApprovalLedger,
    ApprovalStatus,
    DecisionReplay,
    GatewayStatus,
    JsonlAuditRecorder,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-firewall")
    commands = parser.add_subparsers(dest="command", required=True)

    audit = commands.add_parser("audit", help="inspect JSONL audit events")
    audit.add_argument("--file", type=Path, required=True)
    audit.add_argument("--trace-id")
    audit.add_argument("--status", choices=[status.value for status in GatewayStatus])

    denied = commands.add_parser("denied", help="show blocked audit events")
    denied.add_argument("--file", type=Path, required=True)

    replay = commands.add_parser("replay", help="re-evaluate one recorded decision")
    replay.add_argument("--file", type=Path, required=True)
    replay.add_argument("--event-id", required=True)

    approvals = commands.add_parser("approvals", help="inspect an approval ledger")
    approvals.add_argument("--file", type=Path, required=True)
    approvals.add_argument("--status", choices=[status.value for status in ApprovalStatus])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command in {"audit", "denied"}:
        status = (
            GatewayStatus.BLOCKED
            if args.command == "denied"
            else GatewayStatus(args.status)
            if args.status
            else None
        )
        trace_id = args.trace_id if args.command == "audit" else None
        events = JsonlAuditRecorder(args.file).query(trace_id=trace_id, status=status)
        _emit([event.model_dump(mode="json") for event in events])
        return 0
    if args.command == "replay":
        events = JsonlAuditRecorder(args.file).events
        event = next((item for item in events if item.event_id == args.event_id), None)
        if event is None:
            _emit({"error": "EVENT_NOT_FOUND", "event_id": args.event_id})
            return 2
        _emit(DecisionReplay().replay(event).model_dump(mode="json"))
        return 0

    ledger = ApprovalLedger.model_validate_json(args.file.read_text(encoding="utf-8"))
    selected = [
        record
        for record in ledger.records
        if args.status is None or record.status is ApprovalStatus(args.status)
    ]
    _emit([record.model_dump(mode="json") for record in selected])
    return 0


def _emit(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))
