"""Refresh saved cloud inventory independently of connected browsers."""

import asyncio
from contextlib import suppress
import logging
import time
import uuid

from control_service import execute

log = logging.getLogger("cloudbot.account_sync")
SYNC_INTERVAL = 3600
CHANGE_POLL_INTERVAL = 2


async def sync_accounts(store_factory, account_ids=None):
    store = store_factory()
    try:
        accounts = store.accounts()
        if account_ids is not None:
            accounts = [a for a in accounts if a['id'] in account_ids]
        scopes = [{}] if account_ids is None else [{'account_id': a['id']} for a in accounts]
        jobs = [(name, {"refresh": True, **scope}) for scope in scopes for name in
                ("all_servers", "all_floating_ips", "check_all_accounts")]
        jobs.extend(("hetzner_primary_ips", {"account_id": a["id"], "refresh": True})
                    for a in accounts if a["provider"] == "hetzner")
        for operation, args in jobs:
            try:
                result = await asyncio.wait_for(execute(operation, args, store), timeout=900)
                if result.get("account_errors"):
                    log.warning("Account sync %s completed with account errors", operation)
            except Exception:
                # Existing snapshots survive failed reads. Continue other resources.
                log.warning("Account sync %s failed; retaining saved data", operation)
        log.info("Account sync completed")
    finally:
        store.close()


async def run_sync(store_factory, interval=SYNC_INTERVAL):
    next_full_sync = 0
    while True:
        started = asyncio.get_running_loop().time()
        store = store_factory()
        try:
            requests = store.pending_sync()
            full_sync = started >= next_full_sync or 0 in requests
            if full_sync or requests:
                previous = store.get_cache('sync_state') or {}
                store.set_cache('sync_state', {**previous, 'running': True})
                log.info("Starting automatic account sync (%s)", 'all' if full_sync else 'changed accounts')
                if full_sync:
                    await sync_accounts(store_factory)
                    next_full_sync = started + interval
                else:
                    await sync_accounts(store_factory, account_ids=set(requests))
                store.acknowledge_sync(requests)
                store.set_cache('sync_state', {'running': False, 'revision': uuid.uuid4().hex,
                                               'completed_at': time.time()})
        except Exception:
            log.exception("Automatic account sync failed")
        finally:
            store.close()
        # One worker serializes all passes; later mutations keep their queue revision.
        await asyncio.sleep(CHANGE_POLL_INTERVAL)


async def account_sync_context(store_factory, app):
    task = asyncio.create_task(run_sync(store_factory))
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
