"""Proxy formats, encrypted pools and transactional allocation.

The claim table is authoritative for both bound and temporarily reserved
proxies. Legacy duplicates are represented by a blocked claim, never silently
reassigned. No network operation runs inside a SQLite transaction.
"""
from contextlib import contextmanager
import hashlib
import hmac
import json
import re
import secrets
import time
from urllib.parse import quote, unquote, urlsplit

import pycountry


class ProxyPoolError(ValueError):
    pass


POOL_SCHEMA = """
CREATE TABLE IF NOT EXISTS proxy_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    template BLOB NOT NULL,
    identity TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    family TEXT NOT NULL DEFAULT 'default'
);
CREATE TABLE IF NOT EXISTS proxy_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    UNIQUE(provider_id, session_id)
);
CREATE TABLE IF NOT EXISTS proxy_claims (
    proxy_key TEXT PRIMARY KEY,
    account_id INTEGER,
    request_token TEXT UNIQUE,
    expires_at REAL,
    expected_revision INTEGER,
    proxy BLOB,
    provider_id INTEGER,
    country TEXT,
    session_id TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS proxy_claim_pair
    ON proxy_claims(provider_id, country, session_id);
CREATE UNIQUE INDEX IF NOT EXISTS proxy_claim_active_account
    ON proxy_claims(account_id) WHERE request_token IS NULL AND account_id IS NOT NULL;
"""

_ALIASES = {
    'USA': 'US', 'UK': 'GB', 'DEUTSCHLAND': 'DE', 'THE NETHERLANDS': 'NL',
    'SOUTH KOREA': 'KR', 'NORTH KOREA': 'KP', 'RUSSIA': 'RU',
    'TURKEY': 'TR', 'VIETNAM': 'VN', 'IRAN': 'IR', 'UAE': 'AE',
    'آلمان': 'DE', 'المان': 'DE', 'آمریکا': 'US', 'امریکا': 'US',
    'ایالات متحده': 'US', 'انگلستان': 'GB', 'انگلیس': 'GB', 'بریتانیا': 'GB',
    'سنگاپور': 'SG', 'اسلواکی': 'SK', 'هلند': 'NL', 'فرانسه': 'FR',
    'کانادا': 'CA', 'ترکیه': 'TR', 'روسیه': 'RU', 'ایران': 'IR',
    'امارات': 'AE', 'فنلاند': 'FI', 'سوئد': 'SE', 'ژاپن': 'JP',
    'استرالیا': 'AU', 'هند': 'IN', 'لهستان': 'PL', 'اسپانیا': 'ES',
}


def resolve_country(value):
    value = ' '.join(str(value or '').strip().split()).upper()
    value = value.replace('ي', 'ی').replace('ك', 'ک')
    value = _ALIASES.get(value, value)
    try:
        # Exact lookup only: never guess a country from a fuzzy match.
        return pycountry.countries.lookup(value).alpha_2
    except LookupError:
        raise ProxyPoolError('کشور نامعتبر است؛ نام کشور یا کد دوحرفی مثل DE را بفرست.') from None


def components(value):
    """Parse the bot's proxy syntax without importing network clients."""
    scheme = 'http'
    raw = str(value or '').strip()
    if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', raw):
        scheme, raw = raw.split('://', 1)
    if scheme not in {'http', 'https', 'socks4', 'socks5'}:
        raise ProxyPoolError('نوع پراکسی نامعتبر است.')
    bare_fields = raw.split(':', 2)
    if '@' not in raw or raw.startswith('[') or (len(bare_fields) == 3 and bare_fields[1].isdigit()):
        if raw.startswith('['):
            end = raw.find(']')
            if end < 0 or raw[end + 1:end + 2] != ':':
                raise ProxyPoolError('میزبان IPv6 باید داخل [] باشد.')
            host, fields = raw[:end + 1], raw[end + 2:].split(':', 2)
        else:
            fields = raw.split(':', 3)
            host, fields = fields[0], fields[1:]
        if len(fields) == 3:
            port, user, password = fields
            raw = f'{quote(user, safe="")}:{quote(password, safe="")}@{host}:{port}'
        elif len(fields) == 1:
            raw = f'{host}:{fields[0]}'
        else:
            raise ProxyPoolError('قالب باید host:port:username:password باشد.')
    try:
        p = urlsplit(f'{scheme}://{raw}')
        port = p.port
        if (not p.hostname or len(p.hostname) > 253 or any(c.isspace() for c in p.hostname)
                or not port or p.path not in ('', '/') or p.query or p.fragment):
            raise ValueError()
    except ValueError:
        raise ProxyPoolError('میزبان یا پورت پراکسی نامعتبر است.') from None
    return {'scheme': scheme, 'host': p.hostname.lower(), 'port': port,
            'username': unquote(p.username or ''), 'password': unquote(p.password or ''),
            'auth': p.username is not None}


def proxy_string(p):
    host = f'[{p["host"]}]' if ':' in p['host'] else p['host']
    auth = (f'{quote(p["username"], safe="")}:{quote(p["password"], safe="")}@'
            if p.get('auth', True) else '')
    return f'{p["scheme"]}://{auth}{host}:{p["port"]}'


def session_ids(text):
    values = [s.strip() for s in str(text).splitlines() if s.strip()]
    if not values or any(not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', s) for s in values):
        raise ProxyPoolError('شناسه‌ها را یکی در هر خط بفرست؛ فقط حروف، عدد، _ و - مجاز است.')
    return list(dict.fromkeys(values))


def inferred_username(user):
    for pattern in (r'^(.*-country-)([A-Za-z]{2})(-ssid-)([A-Za-z0-9_-]+?)(-sst-.*)$',
                    r'^(.*_zone_)([A-Za-z]{2})(_sid_)([A-Za-z0-9_-]+?)(_time_.*)$'):
        m = re.fullmatch(pattern, user)
        if m:
            prefix, country, separator, sid, suffix = m.groups()
            return prefix + '{country}' + separator + '{session}' + suffix, country.upper(), sid
    return None


def template_pattern(username):
    pattern = re.escape(username)
    pattern = pattern.replace(re.escape('{country}'), r'(?P<country>[A-Za-z]{2})')
    pattern = pattern.replace(re.escape('{session}'), r'(?P<session>[A-Za-z0-9_-]+?)')
    return re.compile('^' + pattern + '$')


def username_namespace(username):
    # Session duration is a connection setting, not a separate session realm.
    for marker, ending in (('-country-{country}-ssid-{session}-sst-', '-sst-'),
                           ('_zone_{country}_sid_{session}_time_', '_time_')):
        if marker in username:
            return username.rsplit(ending, 1)[0]
    return username


def import_format(text):
    """Return one format and IDs. Numbering is ignored only for proxy lines."""
    lines = [v.strip() for v in str(text).splitlines() if v.strip()]
    if not lines:
        raise ProxyPoolError('قالب خالی است.')
    if any(marker in unquote(lines[0]) for marker in ('{country}', '{session}', '{session_id}', '{sessionid}')):
        p = components(lines[0])
        user = p['username'].replace('{session_id}', '{session}').replace('{sessionid}', '{session}')
        p['username'] = user
        if user.count('{session}') != 1 or user.count('{country}') > 1:
            raise ProxyPoolError('نام کاربری باید دقیقاً یک {session} و حداکثر یک {country} داشته باشد.')
        if '{' in user.replace('{country}', '').replace('{session}', '') or '}' in user.replace('{country}', '').replace('{session}', ''):
            raise ProxyPoolError('فقط {country} و {session} پشتیبانی می‌شود.')
        if any('{' in str(p[k]) or '}' in str(p[k]) for k in ('host', 'password')):
            raise ProxyPoolError('جای‌نگهدار فقط در نام کاربری مجاز است.')
        return p, session_ids('\n'.join(lines[1:])) if len(lines) > 1 else []
    template, ids = None, []
    for line in lines:
        if re.fullmatch(r'\d+[.)]?', line):
            continue
        p = components(line)
        inferred = inferred_username(p['username'])
        if not inferred:
            raise ProxyPoolError('قالب ناشناخته؛ {country} و {session} را در نام کاربری مشخص کن.')
        username, country, sid = inferred
        resolve_country(country)
        p['username'] = username
        if template is not None and p != template:
            raise ProxyPoolError('همه خطوط باید از یک میزبان، قالب و رمز عبور باشند.')
        template = p
        ids.append(sid)
    if template is None:
        raise ProxyPoolError('هیچ خط پراکسی معتبری پیدا نشد.')
    return template, list(dict.fromkeys(ids))


class ProxyPoolStore:
    @contextmanager
    def proxy_transaction(self):
        self.con.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.con.commit()
        except BaseException:
            self.con.rollback()
            raise

    def _proxy_hash(self, value):
        # A keyed digest keeps authentication data out of readable indexes.
        key = self.f._signing_key
        return hmac.new(key, json.dumps(value, ensure_ascii=False).encode(), hashlib.sha256).hexdigest()

    def proxy_providers(self):
        return [{**dict(r), 'template': json.loads(self.f.decrypt(r['template']))}
                for r in self.con.execute('SELECT * FROM proxy_providers ORDER BY id')]

    def proxy_provider(self, provider_id):
        return next((p for p in self.proxy_providers() if p['id'] == int(provider_id)), None)

    def _proxy_identity(self, proxy):
        p = components(proxy)
        provider_id, country, sid = None, None, None
        inferred = inferred_username(p['username'])
        for provider in self.proxy_providers():
            t = provider['template']
            if (t['host'], t['port']) != (p['host'], p['port']):
                continue
            m = template_pattern(t['username']).fullmatch(p['username'])
            if m:
                provider_id, country, sid = provider['id'], m['country'].upper(), m['session']
                p['username'] = username_namespace(t['username']).replace('{country}', country).replace('{session}', sid)
                break
            if inferred and username_namespace(inferred[0]) == username_namespace(t['username']):
                provider_id, country, sid = provider['id'], inferred[1], inferred[2]
                p['username'] = username_namespace(t['username']).replace('{country}', country).replace('{session}', sid)
                break
        if provider_id is None:
            if inferred:
                username, country, sid = inferred
                p['username'] = username_namespace(username).replace('{country}', country).replace('{session}', sid)
        # Protocol, password and IPv4/IPv6 are not separate proxy identities.
        return self._proxy_hash([p['host'], p['port'], p['username']]), provider_id, country, sid

    def _sync_proxy_claims(self):
        self.con.execute('DELETE FROM proxy_claims WHERE request_token IS NULL')
        groups = {}
        for acc in self.accounts():
            if not acc['proxy']:
                continue
            try:
                identity = self._proxy_identity(acc['proxy'])
            except ProxyPoolError:
                continue  # Preserve a malformed legacy value for the owner to edit.
            groups.setdefault(identity, []).append(acc['id'])
        for (key, provider_id, country, sid), owners in groups.items():
            pending = self.con.execute('SELECT * FROM proxy_claims WHERE proxy_key=?', (key,)).fetchone()
            if (len(owners) == 1 and pending and pending['request_token']
                    and pending['account_id'] == owners[0] and pending['expires_at'] > time.time()):
                self.con.execute('UPDATE proxy_claims SET provider_id=?,country=?,session_id=? WHERE proxy_key=?',
                                 (provider_id, country, sid, key))
                continue
            self.con.execute('DELETE FROM proxy_claims WHERE proxy_key=?', (key,))
            self.con.execute('INSERT INTO proxy_claims(proxy_key,account_id,provider_id,country,session_id) VALUES(?,?,?,?,?)',
                             (key, owners[0] if len(owners) == 1 else None, provider_id, country, sid))

    def proxy_conflicts(self):
        groups = {}
        for a in self.accounts():
            if a['proxy']:
                try:
                    key = self._proxy_identity(a['proxy'])[0]
                except ProxyPoolError:
                    continue
                groups.setdefault(key, []).append({'id': a['id'], 'label': a['label']})
        return [owners for owners in groups.values() if len(owners) > 1]

    def add_proxy_provider(self, label, template, ids, family='default'):
        family = 'default'
        if not str(label).strip():
            raise ProxyPoolError('نام نامعتبر است.')
        raw_tpl = proxy_string(template) if isinstance(template, dict) else str(template)
        template, _ = import_format(raw_tpl)
        identity = self._proxy_hash([template['host'], template['port'], username_namespace(template['username'])])
        with self.proxy_transaction():
            if self.con.execute('SELECT 1 FROM proxy_providers WHERE identity=?', (identity,)).fetchone():
                raise ProxyPoolError('این قالب قبلاً ثبت شده؛ شناسه‌ها را به همان ارائه‌دهنده اضافه کن.')
            cur = self.con.execute('INSERT INTO proxy_providers(label,template,identity,family) VALUES(?,?,?,?)',
                                   (label.strip(), self.f.encrypt(json.dumps(template).encode()), identity, family))
            pid = cur.lastrowid
            self._add_proxy_sessions(pid, ids)
            if not self.get('proxy_default'):
                self.con.execute("INSERT OR REPLACE INTO settings(k,v) VALUES('proxy_default',?)", (str(pid),))
            self._sync_proxy_claims()
        return pid

    def _add_proxy_sessions(self, pid, ids):
        ids = session_ids('\n'.join(ids))
        start = self.con.execute('SELECT COALESCE(MAX(position),-1)+1 FROM proxy_sessions WHERE provider_id=?', (pid,)).fetchone()[0]
        count = 0
        for position, sid in enumerate(ids, start):
            count += self.con.execute('INSERT OR IGNORE INTO proxy_sessions(provider_id,session_id,position) VALUES(?,?,?)',
                                      (pid, sid, position)).rowcount
        return count

    def add_proxy_sessions(self, pid, ids):
        with self.proxy_transaction():
            if not self.proxy_provider(pid):
                raise ProxyPoolError('ارائه‌دهنده یافت نشد.')
            return self._add_proxy_sessions(pid, ids)

    def proxy_sessions(self, pid):
        return [dict(r) for r in self.con.execute('SELECT * FROM proxy_sessions WHERE provider_id=? ORDER BY position', (pid,))]

    def proxy_binding(self, acc_id):
        acc = self.account(acc_id)
        if not acc or not acc['proxy']:
            return None
        try:
            _, pid, country, sid = self._proxy_identity(acc['proxy'])
        except ProxyPoolError:
            return None
        return {'provider_id': pid, 'country': country, 'session_id': sid} if pid else None

    def manage_proxy_provider(self, pid, action, value=None):
        with self.proxy_transaction():
            p = self.proxy_provider(pid)
            if not p:
                raise ProxyPoolError('ارائه‌دهنده یافت نشد.')
            if action == 'rename':
                if not str(value or '').strip():
                    raise ProxyPoolError('نام خالی است.')
                self.con.execute('UPDATE proxy_providers SET label=? WHERE id=?', (str(value).strip(), pid))
            elif action == 'default':
                if not p['enabled']:
                    raise ProxyPoolError('ابتدا ارائه‌دهنده را فعال کن.')
                self.con.execute("INSERT OR REPLACE INTO settings(k,v) VALUES('proxy_default',?)", (str(pid),))
            elif action == 'toggle':
                self.con.execute('UPDATE proxy_providers SET enabled=1-enabled WHERE id=?', (pid,))
                self.con.execute('DELETE FROM proxy_claims WHERE provider_id=? AND request_token IS NOT NULL', (pid,))
                self._sync_proxy_claims()
            elif action == 'format':
                self._expire_proxy_reservations()
                if self.con.execute('SELECT 1 FROM proxy_claims WHERE provider_id=?', (pid,)).fetchone():
                    raise ProxyPoolError('قالب در استفاده است؛ ابتدا پراکسی اکانت‌ها را آزاد کن.')
                template, _ = import_format(proxy_string(value))
                identity = self._proxy_hash([template['host'], template['port'], username_namespace(template['username'])])
                if self.con.execute('SELECT 1 FROM proxy_providers WHERE identity=? AND id<>?', (identity, pid)).fetchone():
                    raise ProxyPoolError('این قالب قبلاً ثبت شده است.')
                self.con.execute('UPDATE proxy_providers SET template=?,identity=? WHERE id=?',
                                 (self.f.encrypt(json.dumps(template).encode()), identity, pid))
                self._sync_proxy_claims()
            elif action == 'delete':
                self._expire_proxy_reservations()
                if self.con.execute('SELECT 1 FROM proxy_claims WHERE provider_id=?', (pid,)).fetchone():
                    raise ProxyPoolError('این ارائه‌دهنده در استفاده است؛ ابتدا اتصال اکانت‌ها را آزاد کن.')
                self.con.execute('DELETE FROM proxy_sessions WHERE provider_id=?', (pid,))
                self.con.execute('DELETE FROM proxy_providers WHERE id=?', (pid,))
                self.con.execute("DELETE FROM settings WHERE k='proxy_default' AND v=?", (str(pid),))
            else:
                raise ProxyPoolError('عملیات نامعتبر است.')

    def manage_proxy_session(self, pid, sid, action):
        with self.proxy_transaction():
            self._expire_proxy_reservations()
            if action == 'toggle':
                self.con.execute('UPDATE proxy_sessions SET enabled=1-enabled WHERE provider_id=? AND session_id=?', (pid, sid))
                self.con.execute('DELETE FROM proxy_claims WHERE provider_id=? AND session_id=? AND request_token IS NOT NULL', (pid, sid))
                self._sync_proxy_claims()
            elif action == 'delete':
                if self.con.execute('SELECT 1 FROM proxy_claims WHERE provider_id=? AND session_id=?', (pid, sid)).fetchone():
                    raise ProxyPoolError('این شناسه در استفاده است؛ ابتدا اتصال اکانت را آزاد کن.')
                self.con.execute('DELETE FROM proxy_sessions WHERE provider_id=? AND session_id=?', (pid, sid))
            else:
                raise ProxyPoolError('عملیات نامعتبر است.')

    def _expire_proxy_reservations(self):
        if self.con.execute('DELETE FROM proxy_claims WHERE request_token IS NOT NULL AND expires_at<=?', (time.time(),)).rowcount:
            self._sync_proxy_claims()

    def release_proxy_reservation(self, token):
        with self.proxy_transaction():
            self.con.execute('DELETE FROM proxy_claims WHERE request_token=?', (token,))
            self._sync_proxy_claims()

    def _guard_proxy(self, proxy, acc_id=None, request_token=None):
        self._expire_proxy_reservations()
        if not proxy:
            return
        key, pid, country, sid = self._proxy_identity(proxy)
        claim = self.con.execute('SELECT * FROM proxy_claims WHERE proxy_key=?', (key,)).fetchone()
        if claim:
            if claim['request_token']:
                if claim['request_token'] != request_token:
                    raise ProxyPoolError('این پراکسی در حال تخصیص است؛ دوباره تلاش کن.')
            elif claim['account_id'] != acc_id:
                raise ProxyPoolError('این پراکسی متعلق به اکانت دیگری است یا تعارض دارد.')
        # Check account data as well, including legacy duplicate ownership.
        for account in self.accounts():
            if account['id'] == acc_id or not account['proxy']:
                continue
            try:
                occupied = self._proxy_identity(account['proxy'])[0] == key
            except ProxyPoolError:
                continue
            if occupied:
                raise ProxyPoolError(f'این پراکسی در اکانت #{account["id"]} استفاده شده است.')

    def reserve_proxy(self, proxy, acc_id=None, provider_id=None):
        with self.proxy_transaction():
            return self._reserve_proxy(proxy, acc_id, provider_id)

    def _reserve_proxy(self, proxy, acc_id=None, provider_id=None):
        self._expire_proxy_reservations()
        account = self.account(acc_id) if acc_id else None
        if acc_id and not account:
            raise ProxyPoolError('اکانت یافت نشد.')
        if acc_id:
            self.con.execute('DELETE FROM proxy_claims WHERE account_id=? AND request_token IS NOT NULL', (acc_id,))
            self._sync_proxy_claims()
        self._guard_proxy(proxy, acc_id)
        key, pid, country, sid = self._proxy_identity(proxy)
        if provider_id is not None and pid != provider_id:
            raise ProxyPoolError('قالب پراکسی تغییر کرده است.')
        if pid:
            p = self.proxy_provider(pid)
            current = bool(account and account['proxy'] and self._proxy_identity(account['proxy'])[0] == key)
            session = self.con.execute('SELECT enabled FROM proxy_sessions WHERE provider_id=? AND session_id=?', (pid, sid)).fetchone()
            if not current and (not p['enabled'] or (session and not session[0])):
                raise ProxyPoolError('ارائه‌دهنده یا شناسه غیرفعال شده است.')
            if not session:
                self._add_proxy_sessions(pid, [sid])
        # Reserving the current proxy is idempotent; the old claim is restored
        # by reconciliation when the pending request ends.
        token = secrets.token_urlsafe(24)
        self.con.execute('DELETE FROM proxy_claims WHERE proxy_key=?', (key,))
        self.con.execute('INSERT INTO proxy_claims VALUES(?,?,?,?,?,?,?,?,?)',
                         (key, acc_id, token, time.time() + 600,
                          account['proxy_revision'] if account else None,
                          self.f.encrypt(proxy.encode()), pid, country, sid))
        return {'token': token, 'proxy': proxy, 'provider_id': pid,
                'country': country, 'session_id': sid}

    def allocate_proxy(self, pid, country, acc_id=None, another=False):
        country = resolve_country(country)
        with self.proxy_transaction():
            provider = self.proxy_provider(pid)
            if not provider or not provider['enabled']:
                raise ProxyPoolError('ارائه‌دهنده غیرفعال است؛ یکی دیگر انتخاب کن.')
            self._expire_proxy_reservations()
            if acc_id:
                self.con.execute('DELETE FROM proxy_claims WHERE account_id=? AND request_token IS NOT NULL', (acc_id,))
                self._sync_proxy_claims()
            binding = self.proxy_binding(acc_id) if acc_id else None
            ids = [s['session_id'] for s in self.proxy_sessions(pid) if s['enabled']]
            if binding and binding['provider_id'] == pid:
                if another:
                    ids = [s for s in ids if s != binding['session_id']]
                elif binding['session_id'] in ids or binding['country'] == country:
                    if binding['session_id'] in ids:
                        ids.remove(binding['session_id'])
                    ids.insert(0, binding['session_id'])
            for sid in ids:
                t = dict(provider['template'])
                t['username'] = t['username'].replace('{country}', country).replace('{session}', sid)
                proxy = proxy_string(t)
                try:
                    self._guard_proxy(proxy, acc_id)
                except ProxyPoolError:
                    continue
                result = self._reserve_proxy(proxy, acc_id, pid)
                return {**result, 'family': 'default'}
            raise ProxyPoolError(f'برای {country} شناسه آزاد وجود ندارد؛ شناسه اضافه کن یا ارائه‌دهنده را عوض کن.')

    def proxy_availability(self, pid, country):
        country = resolve_country(country)
        provider = self.proxy_provider(pid)
        if not provider:
            raise ProxyPoolError('ارائه‌دهنده یافت نشد.')
        available = 0
        with self.proxy_transaction():
            for s in self.proxy_sessions(pid):
                if not s['enabled'] or not provider['enabled']:
                    continue
                p = dict(provider['template'])
                p['username'] = p['username'].replace('{country}', country).replace('{session}', s['session_id'])
                try:
                    self._guard_proxy(proxy_string(p))
                    available += 1
                except ProxyPoolError:
                    pass
        return available

    def _check_proxy_reservation(self, token, acc_id, proxy):
        self._expire_proxy_reservations()
        r = self.con.execute('SELECT * FROM proxy_claims WHERE request_token=?', (token,)).fetchone()
        if not r or r['account_id'] != acc_id or self.f.decrypt(r['proxy']).decode() != proxy:
            raise ProxyPoolError('درخواست منقضی یا لغو شده است؛ دوباره پراکسی را انتخاب کن.')
        if acc_id:
            account = self.account(acc_id)
            if not account or account['proxy_revision'] != r['expected_revision']:
                raise ProxyPoolError('پراکسی اکانت تغییر کرده؛ درخواست قدیمی ذخیره نشد.')
        if r['provider_id']:
            provider = self.proxy_provider(r['provider_id'])
            session = self.con.execute('SELECT enabled FROM proxy_sessions WHERE provider_id=? AND session_id=?',
                                       (r['provider_id'], r['session_id'])).fetchone()
            current = bool(acc_id and self.account(acc_id)['proxy'] and self._proxy_identity(self.account(acc_id)['proxy'])[0] == r['proxy_key'])
            if not current and (not provider or not provider['enabled'] or not session or not session[0]):
                raise ProxyPoolError('ارائه‌دهنده یا شناسه غیرفعال شده است.')
        self._guard_proxy(proxy, acc_id, token)
