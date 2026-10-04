import json
import logging
from io import StringIO

from agent_firewall.logging import configure_logging


def test_configure_logging_emits_machine_readable_event() -> None:
    stream = StringIO()
    logger = configure_logging(level=logging.INFO, stream=stream)

    logger.info("foundation ready")

    event = json.loads(stream.getvalue())
    assert event["level"] == "INFO"
    assert event["logger"] == "agent_firewall"
    assert event["message"] == "foundation ready"
    assert event["timestamp"].endswith("+00:00")


def test_reconfiguration_does_not_duplicate_handlers() -> None:
    first_stream = StringIO()
    second_stream = StringIO()
    configure_logging(stream=first_stream)
    logger = configure_logging(stream=second_stream)

    logger.warning("one event")

    assert first_stream.getvalue() == ""
    assert len(second_stream.getvalue().splitlines()) == 1
