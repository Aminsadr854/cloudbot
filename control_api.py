import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import time

from aiohttp import web

from control_service import InputError, OPERATIONS, execute
from providers import ProviderError
from store import Store

log = logging.getLogger("cloudbot.control_api")
TOKEN_PATH = Path(os.environ.get("CLOUDBOT_CONTROL_TOKEN_FILE",
                                 "/opt/cloudbot/data/control_api.token"))
MAX_BODY = 16 * 1024
TOKEN_KEY = web.AppKey("control_token", str)
STORE_FACTORY_KEY = web.AppKey("store_factory", object)
UI_DIR = Path(__file__).parent / "ui"


def read_token():
    token = TOKEN_PATH.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise RuntimeError("control API token must be at least 32 characters")
    return token


PAGE_ROUTES = {
    "/", "/overview", "/accounts", "/proxies", "/hetzner", "/vultr",
    "/linode", "/compute", "/ips", "/ssh", "/dns", "/watchdog", "/settings",
    "/index.html", "/favicon.ico"
}


@web.middleware
async def authenticate(request, handler):
    if request.path in ("/health", "/login", "/v1/auth/telegram", "/v1/auth/me", "/v1/auth/logout"):
        return await handler(request)
    # Allow serving UI frontend shell on all page routes without blocking (client prompts for token)
    if request.path in PAGE_ROUTES or request.path.startswith("/ui/"):
        return await handler(request)
    header = request.headers.get("Authorization", "")
    supplied = header[7:] if header.startswith("Bearer ") else ""
    if not supplied:
        supplied = request.cookies.get("cloudbot_token", "")
    if not supplied or not hmac.compare_digest(supplied, request.app[TOKEN_KEY]):
        return web.json_response({"error": "unauthorized"}, status=401)
    return await handler(request)


async def handle_login(request):
    otp = request.query.get("otp", "").strip()
    token = request.query.get("token", "").strip()
    app_token = request.app[TOKEN_KEY]
    store = request.app[STORE_FACTORY_KEY]()
    valid = False
    try:
        if otp:
            user_id = store.verify_and_consume_login_otp(otp)
            owner_id = int(os.environ.get("CLOUDBOT_OWNER", "0"))
            if user_id and (owner_id == 0 or int(user_id) == owner_id):
                valid = True
        elif token and hmac.compare_digest(token, app_token):
            valid = True
    finally:
        store.close()

    if valid:
        resp = web.HTTPFound("/")
        resp.set_cookie(
            "cloudbot_token", app_token,
            path="/",
            httponly=True,
            samesite="Lax",
            secure=request.scheme == "https" or request.headers.get("X-Forwarded-Proto") == "https",
            max_age=30 * 86400,
        )
        raise resp

    bot_user = os.environ.get("CLOUDBOT_BOT_USERNAME", "vpnmanagerkiabot")
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>ورود به پنل هاستینگ</title>
<style>body{{background:#0d1117;color:#c9d1d9;font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;direction:rtl;}}
.box{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:32px;text-align:center;max-width:420px;box-shadow:0 8px 24px rgba(0,0,0,0.5);}}
h2{{color:#f85149;margin-top:0;}}
p{{color:#8b949e;line-height:1.6;font-size:14px;}}
a{{display:inline-block;margin-top:16px;background:#238636;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;font-weight:600;transition:background .2s;}}
a:hover{{background:#2ea043;}}
</style></head>
<body>
<div class="box">
<h2>❌ لینک ورود منقضی یا نامعتبر است</h2>
<p>این لینک یک‌بار مصرف بوده یا اعتبار زمانی آن (۱۰ دقیقه) پایان یافته است.<br>برای دریافت لینک ورود مستقیم وارد ربات تلگرام شوید:</p>
<a href="https://t.me/{bot_user}?start=login">🤖 دریافت لینک جدید در ربات تلگرام</a>
</div>
</body></html>"""
    return web.Response(text=html, content_type="text/html", status=403)


async def auth_telegram(request):
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON body"}, status=400)

    bot_token = os.environ.get("CLOUDBOT_TOKEN", "").strip()
    owner_id = int(os.environ.get("CLOUDBOT_OWNER", "0"))
    if not bot_token or not owner_id:
        return web.json_response({"error": "telegram auth not configured"}, status=500)

    received_hash = data.get("hash")
    if not received_hash:
        return web.json_response({"error": "missing hash"}, status=400)

    try:
        auth_date = int(data.get("auth_date", 0))
    except (ValueError, TypeError):
        return web.json_response({"error": "invalid auth_date"}, status=400)
    if time.time() - auth_date > 86400:
        return web.json_response({"error": "telegram authentication expired"}, status=401)

    check_pairs = []
    for k in sorted(data.keys()):
        if k != "hash":
            check_pairs.append(f"{k}={data[k]}")
    check_string = "\n".join(check_pairs)

    secret = hashlib.sha256(bot_token.encode("utf-8")).digest()
    calc_hash = hmac.new(secret, check_string.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc_hash, received_hash):
        return web.json_response({"error": "invalid telegram signature"}, status=401)

    uid = int(data.get("id", 0))
    if uid != owner_id:
        return web.json_response({"error": "access restricted to bot owner"}, status=403)

    app_token = request.app[TOKEN_KEY]
    resp = web.json_response({"status": "ok", "token": app_token})
    resp.set_cookie(
        "cloudbot_token", app_token,
        path="/",
        httponly=True,
        samesite="Lax",
        secure=request.scheme == "https" or request.headers.get("X-Forwarded-Proto") == "https",
        max_age=30 * 86400,
    )
    return resp


async def handle_auth_me(request):
    header = request.headers.get("Authorization", "")
    supplied = header[7:] if header.startswith("Bearer ") else ""
    if not supplied:
        supplied = request.cookies.get("cloudbot_token", "")
    authenticated = bool(supplied and hmac.compare_digest(supplied, request.app[TOKEN_KEY]))
    bot_user = os.environ.get("CLOUDBOT_BOT_USERNAME", "vpnmanagerkiabot")
    return web.json_response({
        "authenticated": authenticated,
        "bot_username": bot_user,
    })


async def handle_logout(_request):
    resp = web.json_response({"status": "ok"})
    resp.del_cookie("cloudbot_token", path="/")
    return resp


async def ui_index(_request):
    index_file = UI_DIR / "index.html"
    if index_file.is_file():
        return web.FileResponse(index_file)
    return web.Response(text="Cloudbot UI not found", status=404)


async def ui_static(request):
    filename = request.match_info["filename"]
    file_path = (UI_DIR / filename).resolve()
    if file_path.is_file() and file_path.is_relative_to(UI_DIR):
        return web.FileResponse(file_path)
    return web.Response(text="File not found", status=404)


async def health(_request):
    return web.json_response({"status": "ok"})


async def operations(_request):
    return web.json_response({"operations": OPERATIONS, "endpoint": "/v1/operations/{name}"})


async def run_operation(request):
    if request.content_length and request.content_length > MAX_BODY:
        return web.json_response({"error": "request too large"}, status=413)
    try:
        args = await request.json(loads=json.loads)
    except (ValueError, UnicodeDecodeError):
        return web.json_response({"error": "body must be a JSON object"}, status=400)
    if not isinstance(args, dict):
        return web.json_response({"error": "body must be a JSON object"}, status=400)
    store = request.app[STORE_FACTORY_KEY]()
    try:
        result = await execute(request.match_info["name"], args, store)
        return web.json_response(result)
    except (InputError, ProviderError) as exc:
        return web.json_response({"error": str(exc)}, status=400)
    except Exception as exc:
        log.exception("control API operation %s failed", request.match_info["name"])
        err_msg = str(exc).strip()
        return web.json_response({"error": err_msg if err_msg else "operation failed; check service logs"}, status=502)
    finally:
        store.close()


def build_app(token=None, store_factory=Store):
    app = web.Application(middlewares=[authenticate], client_max_size=MAX_BODY)
    app[TOKEN_KEY] = token or read_token()
    app[STORE_FACTORY_KEY] = store_factory
    for route in PAGE_ROUTES:
        if route != "/favicon.ico":
            app.router.add_get(route, ui_index)
    app.router.add_get("/ui/{filename:.*}", ui_static)
    app.router.add_get("/login", handle_login)
    app.router.add_get("/v1/auth/me", handle_auth_me)
    app.router.add_post("/v1/auth/telegram", auth_telegram)
    app.router.add_post("/v1/auth/logout", handle_logout)
    app.router.add_get("/health", health)
    app.router.add_get("/v1/operations", operations)
    app.router.add_post("/v1/operations/{name}", run_operation)
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    host = os.environ.get("CLOUDBOT_CONTROL_HOST", "0.0.0.0")
    port = int(os.environ.get("CLOUDBOT_CONTROL_PORT", "9601"))
    log.info("Starting Cloudbot Console on http://%s:%d", host, port)
    web.run_app(build_app(), host=host, port=port)
