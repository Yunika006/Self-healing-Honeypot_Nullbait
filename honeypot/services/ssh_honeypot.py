import asyncio
import logging
import os
import random
import re
import time
from datetime import datetime

from utils.logger import log_event
from utils.geo_lookup import get_geo

log = logging.getLogger("nullbait.ssh")

# realistic OpenSSH banner — version 7.4 is old enough to be
# a juicy target, which is exactly what we want
SSH_BANNER = b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n"

# fake shell prompt shown after "successful" login on attempt 3
# (we let them in on the 3rd try to waste more of their time)
FAKE_PROMPT = b"root@debian-prod-01:~# "

# commands we fake responses for — enough to seem real
FAKE_CMD_RESPONSES = {
    "id":      b"uid=0(root) gid=0(root) groups=0(root)\n",
    "whoami":  b"root\n",
    "uname -a": b"Linux debian-prod-01 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1+deb9u1 x86_64 GNU/Linux\n",
    "pwd":     b"/root\n",
    "ls":      b"backup  creds.txt  db_dump.sql  .ssh\n",
    "cat /etc/passwd": b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    "cat creds.txt": b"cat: creds.txt: Permission denied\n",  # tease them
    "ifconfig": b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0\n",
    "netstat -an": b"Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n",
}


async def handle_ssh_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter
):
    peer = writer.get_extra_info("peername")
    if not peer:
        writer.close()
        return

    attacker_ip, attacker_port = peer[0], peer[1]
    log.info("ssh connect from %s:%d", attacker_ip, attacker_port)

    # geo lookup in background — don't block the connection for it
    geo = await get_geo(attacker_ip)

    await log_event(
        attacker_ip=attacker_ip,
        attacker_port=attacker_port,
        service="ssh",
        honeypot_port=int(os.getenv("SSH_HONEYPOT_PORT", 2222)),
        event_type="connect",
        extra=geo,
    )

    try:
        # send the SSH banner — this is the first thing a real SSH server does
        writer.write(SSH_BANNER)
        await writer.drain()

        # read whatever the client sends (key exchange, version string, etc.)
        # we don't actually process it — just eat the bytes
        try:
            client_banner = await asyncio.wait_for(reader.readline(), timeout=10.0)
            log.debug("ssh client banner from %s: %s", attacker_ip, client_banner[:60])
        except asyncio.TimeoutError:
            log.info("ssh client %s timed out on banner", attacker_ip)
            return

        # most proper SSH clients will now do key exchange and fail.
        # but a LOT of brute force tools use raw TCP and just try
        # user:pass combos directly — those we handle here.
        # give them a fake password prompt after a tiny delay
        await asyncio.sleep(random.uniform(0.3, 0.8))  # simulate server latency

        attempts = 0
        max_attempts = random.randint(3, 5)  # vary it so it doesn't look scripted

        while attempts < max_attempts:
            # fake login prompt
            writer.write(b"\r\nlogin: ")
            await writer.drain()

            try:
                username_raw = await asyncio.wait_for(reader.readline(), timeout=30.0)
            except asyncio.TimeoutError:
                break

            username = username_raw.decode("utf-8", errors="ignore").strip()
            if not username:
                break

            writer.write(b"Password: ")
            await writer.drain()

            try:
                password_raw = await asyncio.wait_for(reader.readline(), timeout=30.0)
            except asyncio.TimeoutError:
                break

            password = password_raw.decode("utf-8", errors="ignore").strip()

            log.info(
                "ssh login attempt from %s — user=%r pass=%r (attempt %d/%d)",
                attacker_ip, username, password, attempts + 1, max_attempts
            )

            await log_event(
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                service="ssh",
                honeypot_port=int(os.getenv("SSH_HONEYPOT_PORT", 2222)),
                event_type="login_attempt",
                username=username,
                password=password,
                raw_payload=f"{username}:{password}",
                extra=geo,
            )

            attempts += 1

            # let them "in" on the last attempt — keeps them engaged longer
            if attempts == max_attempts:
                await asyncio.sleep(random.uniform(1.0, 2.0))
                writer.write(b"\r\nWelcome to Debian GNU/Linux 9 (stretch)\r\n\r\n")
                writer.write(b"Last login: ")
                # fake a recent login timestamp
                writer.write(datetime.now().strftime("Mon %b %d %H:%M:%S 2024 from 185.220.101.47\r\n").encode())
                writer.write(b"\r\n")
                writer.write(FAKE_PROMPT)
                await writer.drain()

                # now handle their commands
                await _handle_fake_shell(
                    reader, writer, attacker_ip, attacker_port, geo
                )
                return
            else:
                # failed attempt
                await asyncio.sleep(random.uniform(0.5, 1.5))
                writer.write(b"\r\nPermission denied, please try again.\r\n")
                await writer.drain()

    except (ConnectionResetError, BrokenPipeError):
        log.debug("ssh client %s disconnected mid-session", attacker_ip)
    except Exception as e:
        log.error("unexpected error in ssh handler for %s: %s", attacker_ip, e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _handle_fake_shell(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    attacker_ip: str,
    attacker_port: int,
    geo: dict,
):
    """
    once the attacker is 'in', give them a fake shell.
    log every command they run. respond convincingly to
    common recon commands. stall on anything dangerous.
    """
    log.info("attacker %s entered fake shell", attacker_ip)

    while True:
        try:
            cmd_raw = await asyncio.wait_for(reader.readline(), timeout=60.0)
        except asyncio.TimeoutError:
            log.info("fake shell session for %s timed out", attacker_ip)
            break

        cmd = cmd_raw.decode("utf-8", errors="ignore").strip()
        if not cmd:
            writer.write(FAKE_PROMPT)
            await writer.drain()
            continue

        log.info("ssh shell command from %s: %r", attacker_ip, cmd)

        await log_event(
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
            service="ssh",
            honeypot_port=int(os.getenv("SSH_HONEYPOT_PORT", 2222)),
            event_type="command",
            command=cmd,
            raw_payload=cmd,
            extra=geo,
        )

        if cmd.lower() in ("exit", "logout", "quit"):
            writer.write(b"logout\r\n")
            await writer.drain()
            break

        # check our fake response table first
        response = FAKE_CMD_RESPONSES.get(cmd.lower())

        if response:
            await asyncio.sleep(random.uniform(0.05, 0.2))
            writer.write(response)
        elif cmd.startswith("wget") or cmd.startswith("curl"):
            # they're trying to download malware — stall them with a fake hang
            await asyncio.sleep(random.uniform(4.0, 8.0))
            writer.write(b"curl: (6) Could not resolve host: " + cmd.split()[-1].encode() + b"\n")
        elif cmd.startswith("cat"):
            writer.write(b"cat: " + cmd[4:].strip().encode() + b": No such file or directory\n")
        elif "rm" in cmd or "mkfs" in cmd or "dd if=" in cmd:
            # destructive commands — pretend to run then fake a permission error
            await asyncio.sleep(random.uniform(1.0, 3.0))
            writer.write(b"bash: Operation not permitted\n")
        else:
            writer.write(b"bash: " + cmd.split()[0].encode() + b": command not found\n")

        writer.write(FAKE_PROMPT)
        await writer.drain()


async def start_ssh_honeypot(port: int):
    server = await asyncio.start_server(
        handle_ssh_connection,
        host="0.0.0.0",
        port=port,
    )
    log.info("fake SSH honeypot listening on 0.0.0.0:%d", port)
    async with server:
        await server.serve_forever()
