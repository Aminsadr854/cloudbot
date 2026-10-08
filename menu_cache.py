"""Account-scoped display cache. Mutating provider methods always remain live."""
import asyncio
import copy
import logging
import time

log = logging.getLogger(__name__)


class MenuCache:
    def __init__(self, ttl=1800, retry=30):
        self.ttl, self.retry = ttl, retry
        self.entries, self.tasks = {}, {}
        self.identities, self.revisions = {}, {}

    def revision(self, account):
        account_id = int(account['id'])
        identity = tuple(account.get(k) for k in ('provider', 'token', 'proxy', 'proxy_family'))
        if self.identities.get(account_id) != identity:
            self.invalidate(account_id)
            self.identities[account_id] = identity
        return self.revisions.get(account_id, 0)

    def invalidate(self, account_id):
        account_id = int(account_id)
        self.revisions[account_id] = self.revisions.get(account_id, 0) + 1
        for key in list(self.entries):
            if key[0] == account_id:
                self.entries.pop(key, None)

    def current(self, account, revision):
        account_id = int(account["id"])
        identity = tuple(account.get(k) for k in ("provider", "token", "proxy", "proxy_family"))
        return (self.identities.get(account_id) == identity
                and self.revisions.get(account_id, 0) == revision)

    def fresh(self, account, name):
        key = (int(account['id']), self.revision(account), name)
        entry = self.entries.get(key)
        return entry is not None and entry[1] > time.monotonic()

    def peek(self, account, name):
        key = (int(account['id']), self.revision(account), name)
        entry = self.entries.get(key)
        return copy.deepcopy(entry[0]) if entry else None

    def _start(self, account, name, loader, ttl):
        revision = self.revision(account)
        key = (int(account['id']), revision, name)
        task = self.tasks.get(key)
        if task and not task.done():
            return task

        async def refresh():
            try:
                value = await loader()
                if self.current(account, revision):
                    self.entries[key] = (copy.deepcopy(value), time.monotonic() + ttl)
                return value
            except Exception:
                entry = self.entries.get(key)
                if entry:
                    self.entries[key] = (entry[0], time.monotonic() + self.retry)
                raise

        task = asyncio.create_task(refresh(), name=f'menu-cache-{key[0]}-{name}')
        self.tasks[key] = task

        def finished(done):
            if self.tasks.get(key) is done:
                self.tasks.pop(key, None)
            if not done.cancelled() and done.exception():
                log.warning('Menu refresh failed: account=%s resource=%s (%s)',
                            key[0], name, type(done.exception()).__name__)
        task.add_done_callback(finished)
        return task

    async def get(self, account, name, loader, *, force=False, ttl=None):
        ttl = self.ttl if ttl is None else ttl
        revision = self.revision(account)
        key = (int(account['id']), revision, name)
        entry = self.entries.get(key)
        if entry is not None and not force:
            if entry[1] <= time.monotonic():
                self._start(account, name, loader, ttl)
            return copy.deepcopy(entry[0])
        value = await asyncio.shield(self._start(account, name, loader, ttl))
        # A mutation/credential edit happened while this request was in flight.
        if not self.current(account, revision):
            raise RuntimeError('اطلاعات اکانت تغییر کرد؛ دوباره منو را باز کنید.')
        return copy.deepcopy(value)
