const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const app = fs.readFileSync(path.join(__dirname, 'ui/app.js'), 'utf8');
const accounts = [{id:1,provider:'hetzner'}, {id:2,provider:'hetzner'}, {id:3,provider:'vultr'}];
const calls = [], states = [];
const context = { window:{}, console, state:{ authenticated:true, accounts, accountBilling:{},
  servers:[{id:'old-3',account_id:3}],floatingIps:[],primaryIps:[{id:'old-ip-3',account_id:3}],
  providerSelectedAccount:{}, activeTab:'tab-overview', activeAccountFilter:'all', ipsAccountFilter:'all'},
  syncManager:null, document:{getElementById:()=>null}, renderSyncStatus:s=>states.push(s),
  renderAllViews(){},updateBadges(){},renderOverview(){},renderIPManagement(){},renderHetznerHub(){},showToast(){},
  api:async(op,args={})=>{
    calls.push({op,args});
    const selected = accounts.filter(a=>(!args.account_id || a.id===Number(args.account_id)) && (!args.provider || a.provider===args.provider));
    if(op==='accounts')return {accounts};
    if(op==='all_servers')return {servers:selected.map(a=>({id:`new-${a.id}`,account_id:a.id})),account_errors:{}};
    if(op==='all_floating_ips')return {floating_ips:[],account_errors:{}};
    if(op==='check_all_accounts')return {accounts:[]};
    if(op==='hetzner_primary_ips')return {primary_ips:[]};
    return {};
  }
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname,'ui/sync-manager.js'),'utf8'),context);
for(const name of ['getRefreshScope','initSyncManager','loadAll','loadAllPhase']){
  const start=app.search(new RegExp(`^(?:async )?function ${name}\\(`,'m'));
  assert.ok(start>=0,name);
  const rest=app.slice(start),end=rest.slice(1).search(/\n(?:async )?function /);
  vm.runInContext(end<0?rest:rest.slice(0,end+1),context);
}
(async()=>{
  await context.loadAll();
  const remoteOps=new Set(['all_servers','all_floating_ips','check_all_accounts','hetzner_primary_ips','dns_zones']);
  assert.ok(calls.filter(c=>remoteOps.has(c.op)).every(c=>c.args.cached_only===true),'Default view must be strictly cache-only, including misses');
  assert.ok(states.every(s=>Object.values(s.resources).every(r=>r.status!=='syncing')),'Saved data must not show a live-sync banner');
  calls.length=0;
  await context.loadAll(true,{provider:'hetzner'});
  for(const c of calls.filter(c=>['all_servers','all_floating_ips','check_all_accounts'].includes(c.op)))assert.equal(c.args.provider,'hetzner');
  assert.ok(!calls.some(c=>c.op==='dns_zones'),'Provider refresh must not fetch unrelated DNS');
  assert.ok(context.state.servers.some(s=>s.id==='new-3'),'Other-provider snapshot must remain visible');
  calls.length=0;
  await context.loadAll(true,{account_id:2});
  for(const c of calls.filter(c=>remoteOps.has(c.op)))assert.equal(c.args.account_id,2,c.op);
  for(const provider of ['hetzner','vultr','linode','upcloud','cloudferro']){
    context.state.activeTab=`tab-${provider}`;
    context.state.providerSelectedAccount={};
    assert.equal(context.getRefreshScope().provider,provider);
    context.state.providerSelectedAccount[provider]=7;
    assert.equal(context.getRefreshScope().account_id,7);
  }
  console.log('Cache-only defaults, scoped refresh requests, and preserved other-provider data passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
