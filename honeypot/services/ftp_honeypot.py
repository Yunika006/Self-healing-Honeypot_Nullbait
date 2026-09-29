"""
fake FTP server — speaks just enough of RFC 959 to fool
automated scanners and FTP brute force tools.
responds with realistic FTP status codes.
"""

import asyncio
import logging
import os
import random

from utils.logger import log_event
from utils.geo_lookup import get_geo

log = logging.getLogger("nullbait.ftp")

# realistic vsftpd banner — 2.3.4 is infamous (backdoor vulnerability)
# so it'll attract extra attention from vuln scanners
FTP_BANNER = b"220 (vsFTPd 2.3.4)\r\n"


async def handle_ftp_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    peer = writer.get_extra_info("peername")
    if not peer:
        writer.close()
        return

    attacker_ip, attacker_port = peer[0], peer[1]
    geo = await get_geo(attacker_ip)

    log.info("ftp connect from %s:%d", attacker_ip, attacker_port)

    await log_event(
        attacker_ip=attacker_ip,
        attacker_port=attacker_port,
        service="ftp",
        honeypot_port=int(os.getenv("FTP_HONEYPOT_PORT", 2121)),
        event_type="connect",
        extra=geo,
    )

    writer.write(FTP_BANNER)
    await writer.drain()

    username = None

    try:
        while True:
            try:
                line_raw = await asyncio.wait_for(reader.readline(), timeout=30.0)
            except asyncio.TimeoutError:
                break

            if not line_raw:
                break

            line = line_raw.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            # FTP commands are space separated: "USER admin"
            parts = line.split(" ", 1)
            cmd   = parts[0].upper()
            arg   = parts[1] if len(parts) > 1 else ""

            log.debug("ftp cmd from %s: %r %r", attacker_ip, cmd, arg)

            if cmd == "USER":
                username = arg
                # 331 = password required
                writer.write(b"331 Please specify the password.\r\n")
                await log_event(
                    attacker_ip=attacker_ip,
                    attacker_port=attacker_port,
                    service="ftp",
                    honeypot_port=int(os.getenv("FTP_HONEYPOT_PORT", 2121)),
                    event_type="login_attempt",
                    username=username,
                    raw_payload=line,
                    extra=geo,
                )

            elif cmd == "PASS":
                password = arg
                log.info(
                    "ftp login attempt from %s — user=%r pass=%r",
                    attacker_ip, username, password
                )
                await log_event(
                    attacker_ip=attacker_ip,
                    attacker_port=attacker_port,
                    service="ftp",
                    honeypot_port=int(os.getenv("FTP_HONEYPOT_PORT", 2121)),
                    event_type="login_attempt",
                    username=username,
                    password=password,
                    raw_payload=line,
                    extra=geo,
                )
                # always deny but add a random delay so brute force tools slow down
                await asyncio.sleep(random.uniform(0.5, 2.0))
                writer.write(b"530 Login incorrect.\r\n")

            elif cmd == "QUIT":
                writer.write(b"221 Goodbye.\r\n")
                break

            elif cmd == "SYST":
                writer.write(b"215 UNIX Type: L8\r\n")

            elif cmd == "FEAT":
                writer.write(b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")

            else:
                # log anything we don't recognise as a potential payload
                await log_event(
                    attacker_ip=attacker_ip,
                    attacker_port=attacker_port,
                    service="ftp",
                    honeypot_port=int(os.getenv("FTP_HONEYPOT_PORT", 2121)),
                    event_type="payload",
                    raw_payload=line,
                    extra=geo,
                )
                writer.write(b"500 Unknown command.\r\n")

            await writer.drain()

    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.error("ftp handler error for %s: %s", attacker_ip, e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_ftp_honeypot(port: int):
    server = await asyncio.start_server(
        handle_ftp_connection,
        host="0.0.0.0",
        port=port,
    )
    log.info("fake FTP honeypot listening on 0.0.0.0:%d", port)
    async with server:
        await server.serve_forever()
