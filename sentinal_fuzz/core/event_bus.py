"""Simple synchronous event emitter for Sentinal-Fuzz.

The ``EventBus`` decouples scan-phase code from presentation (CLI
progress, logging, webhooks).  Scanner emits events; the CLI (or any
other consumer) registers handlers.

Usage::

    bus = EventBus()
    bus.on("finding", lambda finding: print(finding.title))
    bus.emit("finding", finding=some_finding)

Events emitted by Scanner:
    - ``url_found``       — kwargs: url (str)
    - ``crawl_complete``  — kwargs: endpoints (list[Endpoint])
    - ``finding``         — kwargs: finding (Finding)
    - ``scan_complete``   — kwargs: result (ScanResult)
    - ``stage_changed``   — kwargs: stage (str)
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

from sentinal_fuzz.utils.logger import get_logger

log = get_logger("event_bus")

# Type alias for event handler functions
EventHandler = Callable[..., Any]


class EventBus:
    """Synchronous event emitter with error isolation.

    Handlers that raise exceptions are logged but do **not** interrupt
    the scan pipeline.  This keeps the scanner resilient even when a
    UI callback misbehaves.

    Attributes:
        _handlers: Mapping of event names → list of handler functions.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)

    def on(self, event: str, handler: EventHandler) -> None:
        """Register a handler for *event*.

        Args:
            event:   Event name (e.g. ``"finding"``, ``"crawl_complete"``).
            handler: A callable; will be invoked with ``**kwargs``
                     when the event fires.
        """
        self._handlers[event].append(handler)
        log.debug("Handler registered for '%s': %s", event, handler)

    def off(self, event: str, handler: EventHandler) -> None:
        """Unregister a previously registered handler.

        Silently ignores handlers that are not registered.

        Args:
            event:   Event name.
            handler: The handler to remove.
        """
        try:
            self._handlers[event].remove(handler)
        except ValueError:
            pass

    def emit(self, event: str, **kwargs: Any) -> None:
        """Fire *event*, calling all registered handlers with *kwargs*.

        Errors in handlers are logged and swallowed.

        Args:
            event:    Event name.
            **kwargs: Keyword arguments forwarded to every handler.
        """
        for handler in self._handlers.get(event, []):
            try:
                handler(**kwargs)
            except Exception as exc:
                log.warning(
                    "Event handler error on '%s': %s — %s",
                    event,
                    type(handler).__qualname__,
                    exc,
                )

    def clear(self, event: str | None = None) -> None:
        """Remove all handlers, or all handlers for a specific event.

        Args:
            event: If provided, only clear handlers for this event.
                   If ``None``, clear everything.
        """
        if event is None:
            self._handlers.clear()
        else:
            self._handlers.pop(event, None)
