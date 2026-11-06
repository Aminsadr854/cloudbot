const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const context = { window: {}, state: { accountErrors: {}, accountBilling: {} }, escapeHtml: value => String(value), icon: name => `[${name}]` };
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, 'ui/sync-manager.js'), 'utf8'), context);
const app = fs.readFileSync(path.join(__dirname, 'ui/app.js'), 'utf8');
for (const name of ['getAccountFailureStatus', 'formatAccountBillingDetails', 'renderAccountsManagement', 'renderProviderHubView']) {
  const start = app.indexOf(`function ${name}(`);
  const end = app.indexOf('\nfunction ', start + 1);
  vm.runInContext(app.slice(start, end), context);
}
const cases = [
  ['Account suspended: 2 server(s) reported suspended by the provider.', 'suspended'],
  ['ProxyError: Provider traffic limit reached. Raise the GB limit or reset its usage counter.', 'quota'],
  ['HTTP 401: {"errors": [{"reason": "Invalid Token"}]}', 'auth'],
  ['HTTP 401: Unauthorized', 'auth'],
  ['HTTP 403: insufficient token permissions', 'access'],
  ['HTTP 401: Unauthorized IP address', 'access'],
  ['HTTP 503: upstream proxy temporarily unavailable', 'provider'],
  ['HTTP 429: rate limit exceeded', 'provider'],
  ['ClientHttpProxyError: 407 Proxy Authentication Required', 'proxy'],
  ['HTTP 403 Forbidden - Proxy authentication failed', 'proxy'],
  ['ClientProxyConnectionError: connection refused', 'proxy'],
  ['ProxyTimeoutError: timed out', 'proxy'],
  ['ClientConnectorError: DNS lookup failed', 'connection'],
  ['TimeoutError: request timed out', 'connection'],
];
for (const [error, kind] of cases) {
  context.state.accountErrors[14] = error;
  const failure = context.getAccountFailureStatus(14);
  assert.equal(failure.kind, kind, error);
  assert.equal(context.window.CloudbotSync.proxyFailure(error), kind === 'proxy', error);
  const billing = context.formatAccountBillingDetails({ provider: 'linode' }, null, failure);
  assert.ok(billing.balanceDisplay.includes(failure.title), error);
  assert.equal(billing.badge, null, 'Do not show a duplicate/misleading proxy badge');
  if (kind !== 'proxy') assert.ok(!billing.balanceDisplay.includes('Proxy Failed'), error);
}
context.state.accountErrors = {};
context.state.servers = [{ account_id: 14, status: 'suspended' }, { account_id: 15, status: 'running' }];
let suspension = context.getAccountFailureStatus(14);
assert.equal(suspension.kind, 'suspended');
assert.equal(suspension.isProxy, false);
assert.equal(context.getAccountFailureStatus(15), null);
context.state.servers[0].status = 'billing_suspension';
assert.equal(context.getAccountFailureStatus(14).kind, 'suspended', 'Linode billing_suspension promotes account status');
const suspendedBilling = context.formatAccountBillingDetails({ provider: 'linode' },
  { status: 'suspended', info: { balance: 12, owed: 12 } }, suspension);
assert.ok(suspendedBilling.balanceDisplay.includes('$12.00 owed'), 'Suspension retains billing details');
context.state.servers = [{ account_id: 14, status: 'offline' }];
assert.equal(context.getAccountFailureStatus(14), null, 'Stopped servers are not suspended');
context.state.accountBilling[14] = { status: 'suspended', error: 'Account suspended' };
assert.equal(context.getAccountFailureStatus(14).kind, 'suspended', 'Saved checks retain suspension');
context.state.accountBilling[14] = { status: 'ok' };
assert.equal(context.getAccountFailureStatus(14), null, 'Recovery clears suspension');
const elements = {};
context.document = { getElementById: id => elements[id] ||= { style: {}, innerHTML: '' }, querySelectorAll: () => [] };
context.PROVIDERS = {};
context.providerSupports = () => false;
context.formatRegion = () => ({ flag: '', name: 'Poland' });
context.formatAccountProxyLabel = () => 'Pool (PL: test-session)';
Object.assign(context.state, { servers: [], floatingIps: [], primaryIps: [], providerSelectedAccount: {} });
for (const provider of ['linode', 'hetzner', 'vultr', 'upcloud']) {
  context.PROVIDERS[provider] = { name: provider, logo: '', badgeClass: '' };
  context.state.accounts = [{ id: 14, provider, label: 'test-account', has_proxy: true }];
  for (const [error, kind] of cases) {
    context.state.accountErrors[14] = error;
    context.state.providerSelectedAccount[provider] = 14;
    context.renderProviderHubView(provider);
    const html = elements[`${provider}-servers-view`].innerHTML;
    assert.ok(html.includes(context.window.CloudbotSync.accountFailure(error).title), `${provider}: ${error}`);
    assert.equal(html.includes('Reconfigure Proxy'), kind === 'proxy', `${provider}: ${error}`);
    if (kind !== 'proxy') assert.ok(!html.includes('Proxy Failed'), `${provider}: ${error}`);
    assert.ok(html.includes('Instance inventory is unavailable'), provider);
    context.state.providerSelectedAccount[provider] = null;
    context.renderProviderHubView(provider);
    const card = elements[`${provider}-accounts-grid`].innerHTML;
    if (kind !== 'proxy') assert.ok(!card.includes('Proxy Failed'), provider);
  }
}
context.state.accounts = [{ id: 14, provider: 'linode', label: 'billing-account' }];
context.state.accountErrors = {};
context.state.accountBilling[14] = { status: 'suspended', error: 'Account suspended', info: { balance: 12 } };
context.state.recoveryStatus = {};
context.state.activeAccountFilter = "linode";
context.renderAccountsManagement();
assert.ok(elements['accounts-master-grid'].innerHTML.includes('>Suspended</span>'), 'Main account list shows suspension');
assert.ok(elements['accounts-master-grid'].innerHTML.includes('$12.00 owed'), 'Main list retains billing');
(async () => {
  const manager = context.window.CloudbotSync.createManager({ resourceNames: [] });
  for (const [error, kind] of cases.filter(([, kind]) => kind !== 'proxy')) {
    const generation = manager.begin();
    let calls = 0;
    await manager.recoverProxy({ generation, account: { id: 14, has_proxy: true }, error,
      retryRead: async () => { calls++; }, healProxy: async () => { calls++; } });
    assert.equal(calls, 0, `No proxy recovery for ${kind}`);
  }
  console.log('Account error classification, billing badges, and recovery guards passed.');
})();
