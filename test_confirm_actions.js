const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const elements = {};
class Element extends EventTarget {
  constructor() { super(); this.textContent = ''; this.value = ''; this.style = {}; }
  querySelectorAll() { return [elements.no]; }
  click() { this.dispatchEvent(new Event('click')); if(this.onclick) return this.onclick(); }
}
for(const id of ['modal-confirm-dialog','confirm-dialog-title','confirm-dialog-desc','confirm-dialog-submit-btn',
  'confirm-typed-container','confirm-typed-label','confirm-typed-input','no']) elements[id] = new Element();
const document = new Element();
document.getElementById = id => elements[id];
let visible = false;
const context = { document, setTimeout:()=>{}, showToast:message=>{throw Error(message);},
  openModal:()=>{visible=true;}, closeModal:()=>{visible=false;},
  runWithButtonLoading:async(button,action)=>action() };
vm.createContext(context);
const source=fs.readFileSync(path.join(__dirname,'ui/app.js'),'utf8');
vm.runInContext(source.slice(source.indexOf('function confirmAction('),source.indexOf('\nfunction copyText(',source.indexOf('function confirmAction('))),context);
(async()=>{
  let actions=0;
  const yes=context.confirmAction('Delete example server and all its data?', 'DELETE_SERVER', async()=>{actions++;});
  assert.equal(actions,0,'Opening a confirmation must not execute the action');
  assert.equal(elements['confirm-dialog-desc'].textContent,'Delete example server and all its data?');
  assert.equal(elements['confirm-dialog-submit-btn'].textContent,'Yes');
  await elements['confirm-dialog-submit-btn'].click();
  assert.equal(await yes,true);
  await elements['confirm-dialog-submit-btn'].click();
  assert.equal(actions,1,'Yes executes exactly once without typed input');
  const no=context.confirmAction('Delete another server?', 'DELETE_SERVER', async()=>{actions++;});
  elements.no.click();
  assert.equal(await no,false);
  assert.equal(actions,1,'No must not execute the action');
  assert.equal(visible,false);
  const option=context.confirmAction({title:'Detach addresses?',message:'Addresses will remain allocated.',expectedWord:'DETACH',confirmText:'Detach'});
  assert.equal(elements['confirm-dialog-desc'].textContent,'Addresses will remain allocated.');
  assert.equal(elements['confirm-dialog-submit-btn'].textContent,'Yes');
  await elements['confirm-dialog-submit-btn'].click();
  assert.equal(await option,true,'Promise callers also need only Yes');
  const dismissed=context.confirmAction({message:'Cancel this action?',expectedWord:'DELETE'});
  elements.no.click();
  assert.equal(await dismissed,false);
  console.log('Yes/No confirmation, explanations, cancellation and single execution passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
