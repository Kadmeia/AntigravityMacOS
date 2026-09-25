const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    value: '', style: {}, options: [], handlers: {},
    classList: {add() {}, remove() {}},
    setAttribute() {}, appendChild() {},
    addEventListener(event, callback) { this.handlers[event] = callback; }
  });
  return elements.get(id);
}
const context = vm.createContext({
  document: {getElementById: element, activeElement: null,
    addEventListener() {}, createElement() { return element('created'); }},
  window: {location: {hash: '#token=test', pathname: '/', search: ''}},
  history: {replaceState() {}}, URLSearchParams, Headers,
  fetch: async () => ({ok: true, json: async () => ({apps: []})}),
  setInterval() {}, clearInterval() {}, setTimeout() {}, console,
});
// Evaluate the entire startup: a missing global callback must fail this test.
vm.runInContext(fs.readFileSync(path.join(__dirname, '../frontend/app.js'), 'utf8'), context);
vm.runInContext(`
  isTargetPatched({apps: [{id: 'desktop', installed: true}]}, 'ide');
`, context);
assert.equal(element('btnPatchAction').disabled, true);
vm.runInContext(`
  isTargetPatched({apps: [{id: 'desktop', installed: true}]}, 'desktop');
`, context);
assert.equal(element('btnPatchAction').disabled, false);
element('proxyHost').value = 'my-unsaved-proxy';
element('proxyHost').handlers.input();
vm.runInContext(`render({apps: [], config: {custom_proxy: {host: 'old-proxy'}}})`, context);
assert.equal(element('proxyHost').value, 'my-unsaved-proxy');
console.log('Frontend: startup, target selection, and unsaved edits passed');
