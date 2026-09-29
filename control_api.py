"""Loopback-only, owner-authenticated JSON API for Cloudbot automation."""

import hmac
import json
import logging
import os
from pathlib import Path

from aiohttp import web

from control_service import InputError, OPERATIONS, execute
from store import Store

log = logging.getLogger("cloudbot.control_api")
TOKEN_PATH = Path(os.environ.get("CLOUDBOT_CONTROL_TOKEN_FILE",
                                 "/opt/cloudbot/data/control_api.token"))
MAX_BODY = 16 * 1024
TOKEN_KEY = web.AppKey("control_token", str)
STORE_FACTORY_KEY = web.AppKey("store_factory", object)


def read_token():
    token = TOKEN_PATH.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise RuntimeError("control API token must be at least 32 characters")
    return token


@web.middleware
async def authenticate(request, handler):
    if request.path == "/health":
        return await handler(request)
    header = request.headers.get("Authorization", "")
    supplied = header[7:] if header.startswith("Bearer ") else ""
    if not supplied or not hmac.compare_digest(supplied, request.app[TOKEN_KEY]):
        return web.json_response({"error": "unauthorized"}, status=401)
    return await handler(request)


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
    except InputError as exc:
        return web.json_response({"error": str(exc)}, status=400)
    except Exception:
        log.exception("control API operation %s failed", request.match_info["name"])
        return web.json_response({"error": "operation failed; check service logs"}, status=502)
    finally:
        store.close()


def build_app(token=None, store_factory=Store):
    app = web.Application(middlewares=[authenticate], client_max_size=MAX_BODY)
    app[TOKEN_KEY] = token or read_token()
    app[STORE_FACTORY_KEY] = store_factory
    app.router.add_get("/health", health)
    app.router.add_get("/v1/operations", operations)
    app.router.add_post("/v1/operations/{name}", run_operation)
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    web.run_app(build_app(), host="127.0.0.1", port=int(os.environ.get("CLOUDBOT_CONTROL_PORT", "9601")))
