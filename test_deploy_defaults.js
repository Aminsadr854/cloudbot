const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const app = fs.readFileSync(path.join(__dirname, 'ui/app.js'), 'utf8');

const elements = {};
function element(id) {
  return elements[id] ||= {
    value: '',
    hidden: false,
    style: {},
    innerHTML: '',
    options: [],
    classList: {
      tokens: new Set(),
      add(c) { this.tokens.add(c); },
      remove(c) { this.tokens.delete(c); },
      toggle(c, force) {
        if (force === undefined) {
          if (this.tokens.has(c)) this.tokens.delete(c);
          else this.tokens.add(c);
        } else if (force) this.tokens.add(c);
        else this.tokens.delete(c);
      }
    },
    addEventListener() {},
    setAttribute() {},
    removeAttribute() {},
    closest() { return this; },
    dispatchEvent(e) {
      if (this.onchange) this.onchange(e);
    }
  };
}

const context = {
  window: {},
  console,
  Event: class { constructor(type) { this.type = type; } },
  document: {
    getElementById: element,
    querySelectorAll: () => [],
    querySelector: () => null,
    addEventListener: () => {},
    hidden: false
  },
  PROVIDERS: {
    hetzner: { name: "Hetzner Cloud", logo: "/ui/assets/hetzner.svg" },
    vultr: { name: "Vultr", logo: "/ui/assets/vultr.svg" },
    linode: { name: "Linode / Akamai", logo: "/ui/assets/linode.svg" },
    upcloud: { name: "UpCloud", logo: "/ui/assets/cloud.svg" },
    cloudferro: { name: "CloudFerro", logo: "/ui/assets/cloud.svg" }
  },
  state: {
    authenticated: true,
    accounts: [
      { id: 101, provider: 'hetzner', label: 'Hetzner Prod', region: 'fsn1', has_proxy: false },
      { id: 102, provider: 'hetzner', label: 'Hetzner Staging', region: 'nbg1', has_proxy: true },
      { id: 201, provider: 'vultr', label: 'Vultr Single', region: 'ewr', has_proxy: false }
    ],
    sshKeys: [{ id: 1, name: 'Default Admin Key' }],
    providerSelectedAccount: { hetzner: 101, vultr: null }
  },
  escapeHtml: x => String(x),
  openModal: () => {},
  closeModal: () => {},
  showToast: () => {},
  updateDeployCountPreview: () => {},
  formatRegion: r => ({ flag: '🇩🇪', name: r || 'Germany' })
};

vm.createContext(context);

// Extract helper functions and deploy functions
for (const name of [
  'pickDefaultPlan',
  'pickDefaultImage',
  'updateDeployContextBanner',
  'resetDeploySelectors',
  'updateDeployProviderPicker',
  'openDeployModalForProvider',
  'openDeployModalForAccount'
]) {
  const start = app.search(new RegExp(`^(?:async )?function ${name}\\(`, 'm'));
  assert.ok(start >= 0, `Could not find function ${name}`);
  const rest = app.slice(start);
  const end = rest.slice(1).search(/\n(?:async )?function /);
  vm.runInContext(end < 0 ? rest : rest.slice(0, end + 1), context);
}

// 1. Test smart default plan picker
assert.equal(context.pickDefaultPlan([{ id: 'cx11' }, { id: 'cx22' }, { id: 'ccx13' }], 'hetzner'), 'cx22');
assert.equal(context.pickDefaultPlan([{ id: 'cpx11' }, { id: 'cpx21' }], 'hetzner'), 'cpx11');
assert.equal(context.pickDefaultPlan([{ id: 'vc2-1c-2gb' }, { id: 'vc2-1c-1gb' }], 'vultr'), 'vc2-1c-1gb');
assert.equal(context.pickDefaultPlan([{ id: 'g6-standard-1' }, { id: 'g6-nanode-1' }], 'linode'), 'g6-nanode-1');
assert.equal(context.pickDefaultPlan([{ id: '1xCPU-1GB' }, { id: '2xCPU-2GB' }], 'upcloud'), '1xCPU-1GB');

// 2. Test smart default image picker
assert.equal(context.pickDefaultImage([
  { id: 'debian-12', label: 'Debian 12' },
  { id: 'ubuntu-22.04', label: 'Ubuntu 22.04' },
  { id: 'ubuntu-24.04', label: 'Ubuntu 24.04' }
]), 'ubuntu-24.04');
assert.equal(context.pickDefaultImage([
  { id: 'centos-9', label: 'CentOS Stream 9' },
  { id: 'ubuntu-22.04', label: 'Ubuntu 22.04' }
]), 'ubuntu-22.04');

// 3. Test openDeployModalForProvider when user is inside Hetzner account (id: 101)
context.state.providerSelectedAccount.hetzner = 101;
context.openDeployModalForProvider('hetzner');

assert.equal(element('deploy-account-select').value, 101, 'Should pre-select the active Hetzner account');
assert.equal(element('deploy-provider-group').hidden, true, 'Provider group should be hidden in provider-specific modal');
assert.equal(element('deploy-account-group').hidden, false, 'Account group should remain visible for confirmation and editing');
assert.equal(element('deploy-name-input').value, 'node-01', 'Should set default hostname');

// 4. Test openDeployModalForProvider when provider has only 1 account (vultr id: 201)
context.state.providerSelectedAccount.vultr = null;
context.openDeployModalForProvider('vultr');
assert.equal(element('deploy-account-select').value, 201, 'Should auto-select single available provider account');

console.log('All deploy default selections, cascading options, and smart prefill tests passed.');
