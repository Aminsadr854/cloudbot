"""Persistent bot HTTP traffic budgets; not a vendor billing measurement.

Body reads reserve their allowance before reading. SQLite serializes charges
across processes; unused read allowance is refunded. TLS, CONNECT and socket
buffering are outside this application counter.
"""
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

import aiohttp
from cryptography.fernet import Fernet

from proxy_pool import components, match_proxy_template


class TrafficLimitExceeded(ValueError):
    def __init__(self):
        super().__init__('Provider traffic limit reached. Raise the GB limit or reset its usage counter.')


class ProxyUsage:
    def __init__(self, proxy, db_path=None, key_path=None):
        self.db_path = db_path or os.environ.get('CLOUDBOT_DB', '/opt/cloudbot/data/cloudbot.db')
        self.provider_id = None
        if not proxy or not Path(self.db_path).is_file():
            return
        key_path = key_path or os.environ.get('CLOUDBOT_KEY', '/opt/cloudbot/data/secret.key')
        fernet = Fernet(Path(key_path).read_bytes().strip())
        parsed = components(proxy)
        with closing(self._connection()) as con:
            for row in con.execute('SELECT id, template FROM proxy_providers'):
                template = json.loads(fernet.decrypt(row['template']))
                if match_proxy_template(template, parsed):
                    self.provider_id = row['id']
                    break

    def _connection(self):
        con = sqlite3.connect(self.db_path, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    def _charge(self, amount, partial=False, expected_reset=None):
        if self.provider_id is None:
            return amount
        con = self._connection()
        try:
            con.execute('BEGIN IMMEDIATE')
            row = con.execute('SELECT usage_limit_bytes, usage_bytes, usage_reset_at FROM proxy_providers WHERE id=?',
                              (self.provider_id,)).fetchone()
            if row is None:
                raise TrafficLimitExceeded()
            if amount < 0 and expected_reset != row['usage_reset_at']:
                return 0
            self.reset_epoch = row['usage_reset_at']
            remaining = max(0, row['usage_limit_bytes'] - row['usage_bytes']) if row['usage_limit_bytes'] else amount
            if amount > remaining:
                if not partial or remaining == 0:
                    raise TrafficLimitExceeded()
                amount = remaining
            con.execute('UPDATE proxy_providers SET usage_bytes=MAX(0, usage_bytes+?) WHERE id=?',
                        (amount, self.provider_id))
            con.commit()
            return amount
        finally:
            con.close()

    def ensure_available(self):
        if self.provider_id is not None:
            with closing(self._connection()) as con:
                row = con.execute('SELECT usage_limit_bytes, usage_bytes FROM proxy_providers WHERE id=?',
                                  (self.provider_id,)).fetchone()
                if row is None or (row['usage_limit_bytes'] and row['usage_bytes'] >= row['usage_limit_bytes']):
                    raise TrafficLimitExceeded()

    def consume(self, amount):
        return self._charge(amount)

    def trace_configs(self):
        if self.provider_id is None:
            return []
        trace = aiohttp.TraceConfig()

        async def headers_sent(session, context, params):
            line = f'{params.method} {params.url.raw_path_qs} HTTP/1.1\r\n'
            headers = ''.join(f'{k}: {v}\r\n' for k, v in params.headers.items())
            self.consume(len((line + headers + '\r\n').encode()))

        async def chunk_sent(session, context, params):
            self.consume(len(params.chunk))

        trace.on_request_headers_sent.append(headers_sent)
        trace.on_request_chunk_sent.append(chunk_sent)
        return [trace]

    async def json(self, response):
        if self.provider_id is None:
            return await response.json()
        return json.loads(await self.text(response))

    async def text(self, response):
        if self.provider_id is None:
            return await response.text()
        headers = sum(len(k) + len(v) + 4 for k, v in response.raw_headers) + 32
        self.consume(headers)
        body = bytearray()
        while not response.content.at_eof():
            reserved = self._charge(16384, partial=True)
            epoch = self.reset_epoch
            chunk = await response.content.read(reserved)
            self._charge(-(reserved - len(chunk)), expected_reset=epoch)
            body.extend(chunk)
        response._body = bytes(body)
        return await response.text()
