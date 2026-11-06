const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const app = fs.readFileSync(path.join(__dirname, 'ui/app.js'), 'utf8');
const elements = {};
function element(id) {
  return elements[id] ||= { value: '', hidden: false, style: {}, innerHTML: '',
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener() {}, setAttribute() {}, removeAttribute() {},
    closest() { return this; }, dispatchEvent() {} };
}
const events = {};
const phases = [];
const context = { window: {}, console, Event: class {},
  document: { getElementById: element, querySelectorAll: () => [], querySelector: () => null,
    addEventListener: (name, callback) => { events[name] = callback; }, hidden: false },
  state: { authenticated: true, accounts: [{ id: 7, provider: 'vultr', label: 'Account 7' }],
    sshKeys: [], proxyProviders: [] },
  syncManager: null, renderSyncStatus() {}, renderAllViews() {}, updateBadges() {}, showToast() {},
  loadAllPhase: async (generation, force) => { phases.push(force); },
  autoRecoverFailedAccounts: async () => {}, escapeHtml: x => x,
  updateDeployCountPreview() {}, prefetchAccountDeployOptions() {},
  updateCloudCredentialHint() {}, populateAddAccProxyProviders() {},
  switchAddAccountProxyMode() {}, updateAddAccProxyRegionHint() {}, updateProxyInputPreview() {}
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, 'ui/sync-manager.js'), 'utf8'), context);
for (const name of ['api', 'pollAutomaticSync', 'getRefreshScope', 'initSyncManager', 'loadAll', 'openModal', 'resetDeploySelectors',
  'updateDeployProviderPicker', 'openDeployModalForProvider', 'openDeployModalForAccount', 'openAddAccountModal']) {
  const start = app.search(new RegExp(`^(?:async )?function ${name}\\(`, 'm'));
  assert.ok(start >= 0, name);
  const rest = app.slice(start);
  const end = rest.slice(1).search(/\n(?:async )?function /);
  vm.runInContext(end < 0 ? rest : rest.slice(0, end + 1), context);
}
(async () => {
  await context.loadAll();
  assert.deepEqual(phases, [false], 'Opening the console must not force a live refresh');
  phases.length = 0;
  await context.loadAll(true);
  assert.ok(phases.includes(true), 'Refresh must request live data');
  phases.length = 0;
  if (events.visibilitychange) events.visibilitychange();
  await Promise.resolve();
  assert.deepEqual(phases, [], 'Returning to the tab must not fetch data');
  context.window.CloudbotApiClient = { READ_OPERATIONS: new Set(['sync_status', 'accounts']) };
  let revision = 'first';
  context.apiClient = { request: async () => ({ revision }) };
  await context.pollAutomaticSync();
  assert.deepEqual(phases, [false], 'New sync revision reloads saved inventory automatically');
  phases.length = 0;
  await context.pollAutomaticSync();
  assert.deepEqual(phases, [], 'Unchanged revision does not reload inventory');
  await context.api('power_server', { account_id: 7 });
  await context.pollAutomaticSync();
  assert.deepEqual(phases, [false], 'Successful mutation automatically reloads local account data');
  phases.length = 0;
  revision = 'second';
  await context.pollAutomaticSync();
  assert.deepEqual(phases, [false], 'Finished background sync updates the open console');
  context.openDeployModalForAccount(7, 'vultr');
  assert.equal(element('deploy-account-select').value, 7);
  assert.equal(element('deploy-account-group').hidden, true);
  assert.equal(element('deploy-provider-group').hidden, true);
  context.openDeployModalForProvider('vultr');
  assert.equal(element('deploy-account-group').hidden, false, 'Provider hub still allows account selection');
  context.openAddAccountModal('vultr');
  assert.equal(element('acc-provider').value, 'vultr');
  assert.equal(element('add-account-provider-group').hidden, true);
  context.openAddAccountModal();
  assert.equal(element('add-account-provider-group').hidden, false, 'Generic add flow restores provider selection');
  context.state.activeAccountFilter = 'linode';
  context.openAddAccountModal();
  assert.equal(element('acc-provider').value, 'linode', 'Contextual account filter sets default provider');
  assert.equal(element('add-account-provider-group').hidden, false, 'Contextual filter keeps provider selection visible');
  context.state.activeAccountFilter = null;
  console.log('Manual refresh and contextual creation flows passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
