import asyncio
import json
import logging

log = logging.getLogger("nullbait.event_bus")


class EventBus:
    """
    super lightweight pub/sub. every connected websocket client
    registers a queue here. when a new attack event comes in,
    we push it into every queue. each websocket connection then
    pulls from its own queue and sends to its client.
    """

    def __init__(self):
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q = asyncio.Queue(maxsize=100)
        self._subscribers.add(q)
        log.debug("new subscriber, total now %d", len(self._subscribers))
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self._subscribers.discard(q)
        log.debug("subscriber left, total now %d", len(self._subscribers))

    async def publish(self, event: dict):
        if not self._subscribers:
            return  # nobody's listening, don't bother

        message = json.dumps(event, default=str)
        dead_queues = []

        for q in self._subscribers:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                # client's too slow consuming, drop this message for them
                # rather than blocking the whole publish for everyone else
                log.warning("subscriber queue full, dropping message")

        for q in dead_queues:
            self._subscribers.discard(q)


event_bus = EventBus()
