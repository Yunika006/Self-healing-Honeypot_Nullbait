import asyncio
import logging
import os
import time
from datetime import datetime

from utils.logger import log_event
from utils.geo_lookup import get_geo

log = logging.getLogger("nullbait.http")

# ── in-memory failed-attempt tracker ────────────────────────
# key: attacker_ip, value: {"count": int, "first_attempt": timestamp}
# this resets if the honeypot container restarts — that's fine,
# it's just for the "account locked" illusion, not real security
_failed_attempts = {}
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_SECONDS = 300  # 5 minutes


def _record_failure(ip: str) -> int:
    """bump the failure counter for this ip, return current count"""
    now = time.time()
    entry = _failed_attempts.get(ip)

    if entry is None or (now - entry["first_attempt"]) > LOCKOUT_WINDOW_SECONDS:
        # first failure, or the old window expired — start fresh
        _failed_attempts[ip] = {"count": 1, "first_attempt": now}
        return 1

    entry["count"] += 1
    return entry["count"]


def _is_locked(ip: str) -> bool:
    entry = _failed_attempts.get(ip)
    if not entry:
        return False
    if (time.time() - entry["first_attempt"]) > LOCKOUT_WINDOW_SECONDS:
        return False
    return entry["count"] >= LOCKOUT_THRESHOLD


# ── favicon, just a tiny valid PNG so the browser tab looks normal ──
# this is a 16x16 transparent png, base64 decoded once at import time
import base64
_FAVICON_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAEUlEQVR42mNk+M9QzwAEjDAGACWfAwGd"
    "6/IhAAAAAElFTkSuQmCC"
)


def _http_response(status_line: str, headers: dict, body: bytes) -> bytes:
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    return f"HTTP/1.1 {status_line}\r\n{header_lines}\r\n".encode() + body


LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Meridian Corp - Employee Portal</title>
  <link rel="icon" href="/favicon.ico">
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ background: #f4f5f7; font-family: 'Segoe UI', Arial, sans-serif;
           display: flex; flex-direction: column; align-items: center;
           justify-content: center; min-height: 100vh; color: #222; }}
    .topbar {{ position: fixed; top: 0; left: 0; right: 0; height: 4px;
              background: linear-gradient(90deg, #003366, #0066cc); }}
    .login-box {{ background: #ffffff; border: 1px solid #d8dde3; border-radius: 6px;
                 padding: 36px 40px; width: 380px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
    .logo {{ text-align: center; margin-bottom: 24px; }}
    .logo .mark {{ width: 48px; height: 48px; background: #003366; border-radius: 8px;
                  display: inline-flex; align-items: center; justify-content: center;
                  color: white; font-weight: bold; font-size: 20px; margin-bottom: 10px; }}
    .logo h2 {{ color: #1a1a1a; font-size: 18px; font-weight: 600; }}
    .logo p {{ color: #6b7280; font-size: 12px; margin-top: 2px; }}
    label {{ color: #374151; font-size: 13px; display: block; margin-bottom: 6px; font-weight: 500; }}
    input[type=text], input[type=password] {{
      width: 100%; padding: 9px 12px; background: #f9fafb;
      border: 1px solid #d1d5db; color: #111; border-radius: 4px;
      font-size: 14px; margin-bottom: 16px; outline: none;
    }}
    input[type=text]:focus, input[type=password]:focus {{ border-color: #0066cc; background: #fff; }}
    button {{ width: 100%; padding: 10px; background: #003366;
             color: white; border: none; border-radius: 4px;
             font-size: 14px; cursor: pointer; font-weight: 500; }}
    button:hover {{ background: #00264d; }}
    .row {{ display: flex; justify-content: space-between; align-items: center;
           margin-top: 14px; font-size: 12px; }}
    .row a {{ color: #0066cc; text-decoration: none; }}
    .row a:hover {{ text-decoration: underline; }}
    select {{ font-size: 12px; color: #6b7280; border: none; background: transparent; }}
    .footer {{ color: #9ca3af; font-size: 11px; text-align: center; margin-top: 24px; line-height: 1.6; }}
    .banner {{ background: #fff8e1; border: 1px solid #ffe082; color: #7a5c00;
              font-size: 12px; padding: 8px 14px; border-radius: 4px; margin-bottom: 18px; }}
  </style>
</head>
<body>
  <div class="topbar"></div>
  <div class="login-box">
    <div class="logo">
      <div class="mark">M</div>
      <h2>Meridian Corp Intranet</h2>
      <p>Employee &amp; Contractor Access Portal</p>
    </div>
    {banner}
    <form method="POST" action="/login">
      <label>Employee ID or Email</label>
      <input type="text" name="username" autocomplete="off">
      <label>Password</label>
      <input type="password" name="Password">
      <button type="submit">Sign In</button>
      <div class="row">
        <a href="/forgot-password">Forgot password?</a>
        <select disabled><option>EN (US)</option></select>
      </div>
    </form>
    <div class="footer">
      Meridian Corp Internal systems. <br>
      IT Helpdesk: helpdesk@meridiancorp.local
    </div>
  </div>
</body>
</html>
"""

FORGOT_PASSWORD_HTML = """<!DOCTYPE html>
<html><head><title>Meridian Corp - Password Reset</title>
<style>body{{font-family:'Segoe UI',Arial,sans-serif;background:#f4f5f7;display:flex;
align-items:center;justify-content:center;height:100vh;}}
.box{{background:#fff;border:1px solid #d8dde3;padding:32px;width:360px;border-radius:6px;text-align:center;}}
p{{color:#374151;font-size:13px;line-height:1.6;margin-bottom:16px;}}
a{{color:#0066cc;font-size:13px;text-decoration:none;}}</style></head>
<body><div class="box">
<p>Password resets must be requested through the IT Helpdesk.<br>
Email helpdesk@meridiancorp.local with your employee ID.</p>
<a href="/">Back to sign in</a>
</div></body></html>
"""


def _render_login_page(locked: bool) -> bytes:
    if locked:
        banner = (
            '<div class="banner">This account has been temporarily locked due to '
            "multiple failed sign-in attempts. Contact IT Helpdesk if this wasn't you.</div>"
        )
    else:
        banner = ""
    html = LOGIN_PAGE_HTML.format(banner=banner)
    return _http_response(
        "200 OK",
        {
            "Content-Type": "text/html; charset=utf-8",
            "Server": "Microsoft-IIS/10.0",
            "X-Powered-By": "ASP.NET",
        },
        html.encode(),
    )


LOGIN_FAILED_HTML = """<!DOCTYPE html>
<html><head><title>Meridian Corp - Employee Portal</title>
<style>body{{font-family:'Segoe UI',Arial,sans-serif;background:#f4f5f7;display:flex;
align-items:center;justify-content:center;height:100vh;}}
.box{{background:#fff;border:1px solid #d8dde3;padding:32px;width:360px;border-radius:6px;}}
p{{color:#b91c1c;font-size:13px;margin-bottom:16px;}}
a{{color:#0066cc;font-size:13px;text-decoration:none;}}</style></head>
<body><div class="box">
<p>{message}</p>
<a href="/">Back to sign in</a>
</div></body></html>
"""

NOT_FOUND = _http_response(
    "404 Not Found",
    {"Content-Type": "text/html"},
    b"<html><body><h1>404 Not Found</h1></body></html>",
)


async def handle_http_connection(reader, writer):
    peer = writer.get_extra_info("peername")
    if not peer:
        writer.close()
        return

    attacker_ip, attacker_port = peer[0], peer[1]
    geo = await get_geo(attacker_ip)

    try:
        raw = await asyncio.wait_for(reader.read(8192), timeout=15.0)
        if not raw:
            return

        request_text = raw.decode("utf-8", errors="ignore")
        lines = request_text.split("\r\n")
        if not lines:
            return

        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 2:
            return

        method = parts[0].upper()
        path = parts[1]

        user_agent = ""
        for line in lines[1:]:
            if line.lower().startswith("user-agent:"):
                user_agent = line[11:].strip()
                break

        log.info("http %s %s from %s (ua: %s)", method, path, attacker_ip, user_agent[:60])

        await log_event(
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
            service="http",
            honeypot_port=int(os.getenv("HTTP_HONEYPOT_PORT", 8080)),
            event_type="request",
            raw_payload=request_line,
            extra={"user_agent": user_agent, "path": path, "method": method, **geo},
        )

        if method == "GET" and path == "/favicon.ico":
            writer.write(_http_response(
                "200 OK", {"Content-Type": "image/x-icon"}, _FAVICON_BYTES
            ))

        elif method == "GET" and path in ("/", "/index.html", "/admin", "/login"):
            writer.write(_render_login_page(_is_locked(attacker_ip)))

        elif method == "GET" and path == "/forgot-password":
            writer.write(_http_response(
                "200 OK", {"Content-Type": "text/html; charset=utf-8"},
                FORGOT_PASSWORD_HTML.encode()
            ))

        elif method == "POST" and path == "/login":
            body = ""
            if "\r\n\r\n" in request_text:
                body = request_text.split("\r\n\r\n", 1)[1]

            username, password = _parse_form_body(body)
            log.info("http login attempt from %s user=%r pass=%r", attacker_ip, username, password)

            await log_event(
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                service="http",
                honeypot_port=int(os.getenv("HTTP_HONEYPOT_PORT", 8080)),
                event_type="login_attempt",
                username=username,
                password=password,
                raw_payload=body,
                extra={"user_agent": user_agent, **geo},
            )

            fail_count = _record_failure(attacker_ip)

            if fail_count >= LOCKOUT_THRESHOLD:
                message = (
                    "This account has been temporarily locked due to multiple "
                    "failed sign-in attempts. Contact IT Helpdesk if this wasn't you."
                )
                await log_event(
                    attacker_ip=attacker_ip,
                    attacker_port=attacker_port,
                    service="http",
                    honeypot_port=int(os.getenv("HTTP_HONEYPOT_PORT", 8080)),
                    event_type="lockout_triggered",
                    raw_payload=f"{fail_count} failed attempts",
                    extra={"user_agent": user_agent, **geo},
                )
            else:
                message = "Invalid employee ID or password. Please try again."

            html = LOGIN_FAILED_HTML.format(message=message)
            writer.write(_http_response(
                "200 OK", {"Content-Type": "text/html; charset=utf-8"}, html.encode()
            ))

        elif path == "/robots.txt":
            writer.write(_http_response(
                "200 OK", {"Content-Type": "text/plain"},
                b"User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /hr-portal\n"
            ))

        elif path in ("/admin/config", "/backup", "/.env", "/wp-login.php",
                      "/phpmyadmin", "/.git/config", "/config.php", "/hr-portal"):
            await log_event(
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                service="http",
                honeypot_port=int(os.getenv("HTTP_HONEYPOT_PORT", 8080)),
                event_type="path_probe",
                raw_payload=path,
                extra={"user_agent": user_agent, **geo},
            )
            writer.write(_http_response(
                "403 Forbidden", {"Content-Type": "text/html"},
                b"<html><body><h1>403 Forbidden</h1></body></html>"
            ))
        else:
            writer.write(NOT_FOUND)

        await writer.drain()

    except asyncio.TimeoutError:
        log.debug("http client %s timed out", attacker_ip)
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.error("http handler error for %s: %s", attacker_ip, e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _parse_form_body(body):
    from urllib.parse import unquote_plus
    params = {}
    for part in body.strip().split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            params[unquote_plus(k)] = unquote_plus(v)
    return params.get("username", ""), params.get("password", "")


async def start_http_honeypot(port):
    server = await asyncio.start_server(handle_http_connection, host="0.0.0.0", port=port)
    log.info("fake HTTP honeypot listening on 0.0.0.0:%d", port)
    async with server:
        await server.serve_forever()
