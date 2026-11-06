const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const context = { window: {}, URL, encodeURIComponent, Date, setTimeout };
vm.createContext(context);
vm.runInContext(fs.readFileSync('projects/cloudbot/ui/api-client.js', 'utf8'), context);
const app = fs.readFileSync('projects/cloudbot/ui/app.js', 'utf8');
const normalizeStart = app.indexOf('function normalizeProxyInput(');
const normalizeEnd = app.indexOf('\nfunction updateProxyInputPreview', normalizeStart);
vm.runInContext(app.slice(normalizeStart, normalizeEnd), context);

const normalized = [
  ['host.example:8080:user:pass', 'http://user:pass@host.example:8080'],
  ['user:pass@host.example:8080', 'http://user:pass@host.example:8080'],
  ['socks5://user:pass@host.example:1080', 'socks5://user:pass@host.example:1080'],
  ['proxy: host.example:8080:user:p@ss', 'http://user:p%40ss@host.example:8080'],
];
for (const [raw, expected] of normalized) assert.equal(context.normalizeProxyInput(raw).value, expected, raw);
assert.throws(() => context.normalizeProxyInput('host-without-port'), /Use host:port/);
assert.throws(() => context.normalizeProxyInput('ftp://host:21'), /HTTP, HTTPS/);

function response(status, body, retryAfter) {
  return { status, ok: status >= 200 && status < 300,
    headers: { get: name => name === 'Retry-After' ? retryAfter : null },
    json: async () => body };
}

(async () => {
  let calls = 0;
  const waits = [];
  const client = context.window.CloudbotApiClient.create({
    maxAttempts: 4,
    sleep: async ms => waits.push(ms),
    fetchImpl: async () => (++calls < 4 ? response(503, { error: 'temporary' }, '0') : response(200, { ok: true })),
  });
  assert.deepEqual(await client.request('accounts'), { ok: true });
  assert.equal(calls, 4);
  assert.equal(waits.length, 3);

  let mutationCalls = 0;
  const mutation = context.window.CloudbotApiClient.create({
    sleep: async () => { throw new Error('mutation was retried'); },
    fetchImpl: async () => { mutationCalls += 1; return response(503, { error: 'temporary' }); },
  });
  await assert.rejects(() => mutation.request('delete_server', {}), /temporary/);
  assert.equal(mutationCalls, 1);
  console.log('Proxy input normalization and safe API retry behavior passed.');
})();
