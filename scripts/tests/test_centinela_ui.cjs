// Isolated DOM tests, with all fetches and timers mocked. No browser or network.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const {spawnSync} = require('node:child_process');
const {JSDOM} = require('jsdom');
const repo = resolve(__dirname, '../..');
const fixture = spawnSync(resolve(repo, 'piloto_kali/prototipo/.venv/bin/python'), [resolve(__dirname, 'ui_fixture.py')], {cwd: repo, encoding: 'utf8'});
assert.equal(fixture.status, 0, fixture.stderr);
const data = JSON.parse(fixture.stdout);
const source = name => readFileSync(resolve(__dirname, '../dualstack_ui', name), 'utf8');
const response = (body, status = 200) => ({ok: status < 400, status, json: async () => body, text: async () => body});
const tick = () => new Promise(resolve => setImmediate(resolve));

function surface(html, fetch) {
  const dom = new JSDOM(html, {url: 'https://centinela.test/', runScripts: 'outside-only'});
  const w = dom.window;
  w.fetch = fetch;
  w.setTimeout = () => 0;
  w.testIntervals = [];
  w.setInterval = fn => {w.testIntervals.push(fn);return 0;};
  w.requestAnimationFrame = () => 0;
  w.matchMedia = () => ({matches: false, addEventListener() {}});
  w.scrollTo = w.HTMLElement.prototype.scrollIntoView = () => {};
  w.CSS = {escape: value => value};
  w.ResizeObserver = class {observe() {} disconnect() {}};
  return dom;
}

test('administrator console starts, switches pages and opens either audit after repeated refreshes', async () => {
  const requests = [];
  let publications = {};
  const dom = surface(data.templates.index, async (url, options) => {
    requests.push(url);
    if (url === '/api/state') return response(structuredClone(data.state));
    if (url.startsWith('/api/run?')) return response(data.details[new URL(url, 'https://centinela.test').searchParams.get('key')]);
    if (url === '/api/admin/users') return response({users: [{id:'alice', name:'Empresa Alice', role:'auditor', active:true}]});
    if (url === '/api/admin/publications') return response({publications});
    if (url === '/api/admin/publish' || url === '/api/admin/unpublish') {
      assert.equal(options.headers['X-CSRF-Token'], 'test-csrf');
      const value = JSON.parse(options.body);
      assert.equal(value.user, 'alice');
      assert.ok(['first','second'].includes(value.key));
      publications = url.endsWith('/publish') ? {[value.key]:[{user:'alice',published_at:'2026-11-08'}]} : {};
      return response({ok:true});
    }
    if (url === '/api/lab/personal/interfaces') return response({interfaces:[]});
    throw new Error('Unexpected request: ' + url);
  });
  try {
    dom.window.eval(source('app.js') + '\n' + source('workspace.js') + '\nwindow.testPoll = poll;');
    await tick();await tick();
    assert.match(dom.window.document.getElementById('connection').textContent, /^Conectado/);
    for (const page of ['history','lab','kpi','models','new','thesis','history']) {
      dom.window.document.querySelector(`[data-page="${page}"]`).click();
      await tick();
      assert.equal(dom.window.document.getElementById('page-' + page).hidden, false);
    }
    for (let i = 0; i < 3; i++) {await dom.window.testPoll();await tick();}
    const buttons = [...dom.window.document.querySelectorAll('#history button')];
    assert.equal(buttons.length, 2);
    for (const button of buttons) {button.click();await tick();await tick();}
    assert.ok(requests.includes('/api/run?key=first'));
    assert.ok(requests.includes('/api/run?key=second'));
    for (const fn of dom.window.testIntervals) await fn();
    await tick();
    assert.equal(dom.window.document.getElementById('publish-card').hidden, false);
    dom.window.document.querySelector('#publish-targets button').click();await tick();await tick();
    assert.equal(dom.window.document.querySelector('#publish-targets button').textContent,'Retirar');
    assert.match(dom.window.document.getElementById('publish-note').textContent,/Empresa Alice ya ve/);
    dom.window.document.querySelector('#publish-targets button').click();await tick();await tick();
    assert.equal(dom.window.document.querySelector('#publish-targets button').textContent,'Publicar');
    assert.match(dom.window.document.getElementById('publish-note').textContent,/Se retiró/);
  } finally {dom.window.close();}
});

test('company portal never presents an empty assessment as 100 percent clean', async () => {
  const dom = surface(data.templates.cliente, async url => response(url === '/api/state' ? data.state : data.details.first));
  try {
    dom.window.eval(source('cliente.js'));await tick();await tick();
    assert.doesNotMatch(dom.window.document.querySelector('.posture-ring').textContent, /100%/);
    assert.match(dom.window.document.querySelector('.posture').textContent, /Sin datos/);
    assert.equal(dom.window.document.querySelectorAll('.report-link').length, 2);
  } finally {dom.window.close();}
});

test('an old failed company request cannot overwrite the newly selected report', async () => {
  let rejectOld;
  const dom = surface(data.templates.cliente, async url => {
    if (url === '/api/state') return response(data.state);
    if (url.endsWith('first')) return new Promise((_, reject) => {rejectOld = reject;});
    return response(data.details.second);
  });
  try {
    // Start with a resolved second audit, then overlap two user selections.
    const state = {...data.state, runs:[data.details.second.run,data.details.first.run]};
    state.runs[0] = {...state.runs[0],started_at:'2030-01-01'};
    const original = dom.window.fetch;
    dom.window.fetch = url => url === '/api/state' ? Promise.resolve(response(state)) : original(url);
    dom.window.eval(source('cliente.js'));await tick();await tick();
    const buttons=[...dom.window.document.querySelectorAll('.audit-item')];
    buttons[1].click();buttons[0].click();await tick();
    rejectOld(new Error('Old request failed'));await tick();
    assert.ok(dom.window.document.querySelector('.portal-head'));
    assert.equal(dom.window.document.querySelector('.audit-item[aria-current="true"] small').textContent, data.details.second.run.started_display);
  } finally {dom.window.close();}
});

test('login renews a stale challenge and restores the submit button on rejected credentials', async () => {
  const calls=[];
  const dom = surface('<meta name="csrf-token" content="old"><form id="login-form"><input name="username" value="alice"><input id="password" name="password" type="password" value="wrong"><button type="submit">Entrar</button></form><button id="toggle-password"></button><p id="login-error" hidden></p>', async (url, options) => {
    calls.push([url,options]);
    if(url === '/login') return response('<meta name="csrf-token" content="new">');
    return response({error:'Usuario o contraseña incorrectos.'}, calls.length === 1 ? 403 : 400);
  });
  try {
    dom.window.eval(source('login.js'));
    dom.window.document.getElementById('toggle-password').click();
    assert.equal(dom.window.document.getElementById('password').type,'text');
    dom.window.document.getElementById('login-form').dispatchEvent(new dom.window.Event('submit',{cancelable:true}));
    await tick();await tick();
    assert.equal(calls.length,3);
    assert.equal(calls[2][1].headers['X-CSRF-Token'],'new');
    assert.equal(dom.window.document.querySelector('[type=submit]').disabled,false);
    assert.equal(dom.window.document.getElementById('login-error').hidden,false);
  } finally {dom.window.close();}
});
