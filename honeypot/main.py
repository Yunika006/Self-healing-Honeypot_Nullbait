import asyncio
import logging
import os
import signal
import sys

from services.ssh_honeypot import start_ssh_honeypot
from services.http_honeypot import start_http_honeypot
from services.ftp_honeypot import start_ftp_honeypot
from services.api_honeypot import start_api_honeypot

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)]
)

log = logging.getLogger("nullbait.main")

SSH_PORT = int(os.getenv("SSH_HONEYPOT_PORT", 2222))
HTTP_PORT = int(os.getenv("HTTP_HONEYPOT_PORT", 8080))
FTP_PORT = int(os.getenv("FTP_HONEYPOT_PORT", 2121))
API_PORT = int(os.getenv("API_HONEYPOT_PORT", 8888))


async def main():
    log.info("NullBait honeypot engine booting up")

    tasks = await asyncio.gather(
        start_ssh_honeypot(SSH_PORT),
        start_http_honeypot(HTTP_PORT),
        start_ftp_honeypot(FTP_PORT),
        start_api_honeypot(API_PORT),
        return_exceptions=True
    )

    names = ["ssh", "http", "ftp", "api"]
    for name, result in zip(names, tasks):
        if isinstance(result, Exception):
            log.error("service %s died with: %s", name, result)


def _handle_sigterm(*_):
    log.info("caught SIGTERM, shutting down gracefully")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_sigterm)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("keyboard interrupt — bye")
