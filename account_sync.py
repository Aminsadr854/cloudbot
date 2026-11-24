"""Refresh saved cloud inventory independently of connected browsers."""

import asyncio
from contextlib import suppress
import html
import logging
import time
import uuid

from control_service import execute
from webhook import telegram_send

log = logging.getLogger("cloudbot.account_sync")
SYNC_INTERVAL = 3600
CHANGE_POLL_INTERVAL = 2
HEALTH_KEY = 'account_health_state'
RECHECK_DELAY = 30


def _bad(item):
    return item.get('status') in ('error', 'suspended')


def _reason(item):
    return str(item.get('error') or item.get('status') or '')[:300]


async def _confirm_down(store, ids):
    """Re-check accounts that just failed so one transient provider blip never pages the owner."""
    await asyncio.sleep(RECHECK_DELAY)
    confirmed = {}
    for acc_id in ids:
        try:
            res = await asyncio.wait_for(
                execute('check_all_accounts', {'refresh': True, 'account_id': acc_id}, store), timeout=300)
        except Exception:
            continue
        for item in res.get('accounts', []):
            if _bad(item):
                confirmed[acc_id] = item
    return confirmed


async def notify_account_health(store, result, send=telegram_send):
    """Tell the owner when an account goes down or comes back.

    State is kept per account in SQLite so restarts do not repeat alerts. An account seen for the
    first time is only recorded, never alerted; an alert is marked sent only after Telegram accepted it.
    """
    items = {i['account']['id']: i for i in result.get('accounts', []) if i.get('account')}
    if not items:
        return
    state = store.get_cache(HEALTH_KEY) or {}
    state = {str(k): v for k, v in state.items()}
    state = {k: v for k, v in state.items() if int(k) in {a['id'] for a in store.accounts()}}
    fresh = [i for i, it in items.items() if _bad(it) and str(i) in state and not state[str(i)].get('down')]
    confirmed = await _confirm_down(store, fresh) if fresh else {}
    for acc_id, item in items.items():
        key, prev = str(acc_id), state.get(str(acc_id), {})
        name = html.escape(str(item['account'].get('label') or acc_id))
        provider = html.escape(str(item['account'].get('provider') or ''))
        if _bad(item):
            if key not in state:
                state[key] = {'down': True, 'notified': True}
                continue
            if prev.get('down') and prev.get('notified'):
                continue
            if not prev.get('down') and acc_id not in confirmed:
                continue
            shown = confirmed.get(acc_id, item)
            try:
                await send(f"🔴 <b>Account {name}</b> ({provider}) is down\n"
                           f"{html.escape(_reason(shown))}")
                state[key] = {'down': True, 'notified': True}
            except Exception:
                log.warning("Account down alert for %s not delivered", acc_id)
                state[key] = {'down': True, 'notified': False}
        elif prev.get('down'):
            if prev.get('notified'):
                try:
                    await send(f"🟢 <b>Account {name}</b> ({provider}) is back")
                except Exception:
                    log.warning("Account recovery alert for %s not delivered", acc_id)
                    continue
            state[key] = {'down': False}
        else:
            state[key] = {'down': False}
    store.set_cache(HEALTH_KEY, state)


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
        jobs.extend(("account_traffic", {"account_id": a["id"], "refresh": True}) for a in accounts
                    if a["provider"] in ("hetzner", "linode", "vultr", "fastly"))
        for operation, args in jobs:
            try:
                result = await asyncio.wait_for(execute(operation, args, store), timeout=900)
                if operation == "check_all_accounts":
                    try:
                        await notify_account_health(store, result)
                    except Exception:
                        log.exception("Account health notification failed")
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
