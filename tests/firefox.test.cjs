const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../dist/firefox/extension');
const source = fs.readFileSync(path.join(root, 'service-worker.js'), 'utf8');
function setup(options = {}) {
  let listener;
  const requests = [];
  const injections = [];
  const cookieQueries = [];
  const tab = options.tab ?? { id: 8, url: 'https://audit.example/path' };
  const page = {
    meta: { url: tab.url, hostname: 'audit.example', scannedAt: '2026-11-09T00:00:00Z' },
    findings: [], technologies: [], forms: [], endpoints: [], scripts: [], headers: {},
  };
  const api = {
    runtime: { onMessage: { addListener: fn => { listener = fn; } } },
    tabs: { query: async () => [tab] },
    scripting: { executeScript: async args => {
      injections.push(args);
      if (options.injectionError) throw new Error(options.injectionError);
      return [{ result: page }];
    }},
    cookies: { getAll: async args => {
      cookieQueries.push(args);
      if (options.cookieError) throw new Error(options.cookieError);
      return [{ name: 'session', value: 'DO_NOT_EXPORT_THIS_SECRET', domain: '.audit.example',
        path: '/', secure: false, httpOnly: false, sameSite: 'no_restriction', session: true }];
    }},
  };
  const context = {
    URL, console,
    fetch: async input => {
      const url = String(input);
      requests.push(url);
      if (url.startsWith('https://dns.google/resolve?')) {
        return { json: async () => ({ Answer: [{ data: '203.0.113.7' }] }) };
      }
      return { status: 404, ok: false, url };
    },
    [options.namespace || 'browser']: api,
  };
  vm.runInNewContext(source, context, { filename: 'service-worker.js' });
  const scan = () => new Promise(resolve => {
    assert.equal(listener({ type: 'rf5:scan' }, {}, value => resolve(JSON.parse(JSON.stringify(value)))), true);
  });
  return { scan, requests, injections, cookieQueries, listener };
}

test('Firefox package preserves upgrade identity and declares external DNS transmission', () => {
  const m = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  assert.equal(m.version, '3.1.2');
  assert.equal(m.manifest_version, 3);
  assert.equal(m.browser_specific_settings.gecko.id, 'rf5-recon@rogerf5.dev');
  assert.equal(m.browser_specific_settings.gecko.strict_min_version, '140.0');
  assert.equal(m.browser_specific_settings.gecko_android.strict_min_version, '142.0');
  assert.deepEqual(m.icons, { '128': 'icon128.png' });
  assert.deepEqual(m.action.default_icon, m.icons);
  assert.deepEqual(m.browser_specific_settings.gecko.data_collection_permissions.required, ['browsingActivity']);
  assert.deepEqual(m.background.scripts, ['service-worker.js']);
  assert.equal(m.background.service_worker, undefined);
});

test('native Firefox API completes scan and exports cookie flags without cookie values', async () => {
  const state = setup();
  assert.equal(state.requests.length, 0, 'opening extension must not start DNS or HTTP requests');
  const response = await state.scan();
  assert.equal(response.ok, true);
  assert.equal(state.injections[0].target.tabId, 8);
  assert.equal(state.requests.filter(url => url.startsWith('https://dns.google/resolve?')).length, 5);
  assert.equal(state.requests.filter(url => url.startsWith('https://audit.example/')).length, 3);
  assert.equal(response.report.cookies[0].httpOnly, false);
  assert.equal(response.report.cookies[0].value, undefined);
  assert.equal(JSON.stringify(response).includes('DO_NOT_EXPORT_THIS_SECRET'), false);
  assert.ok(response.report.findings.some(item => item.title.includes('Secure')));
  assert.ok(response.report.findings.some(item => item.title.includes('HttpOnly')));
});

test('Chrome promise API fallback remains usable', async () => {
  const state = setup({ namespace: 'chrome' });
  assert.equal((await state.scan()).ok, true);
});

test('restricted URLs are rejected before script injection or network requests', async () => {
  const state = setup({ tab: { id: 8, url: 'about:addons' } });
  const response = await state.scan();
  assert.equal(response.ok, false);
  assert.match(response.error, /HTTP o HTTPS/);
  assert.equal(state.injections.length, 0);
  assert.equal(state.requests.length, 0);
  assert.equal(state.cookieQueries.length, 0);
});

test('Firefox container selects the matching cookie store', async () => {
  const state = setup({ tab: { id: 8, url: 'https://audit.example/path', cookieStoreId: 'firefox-container-2' } });
  assert.equal((await state.scan()).ok, true);
  assert.equal(state.cookieQueries[0].storeId, 'firefox-container-2');
});

test('script permission failure reaches popup as a structured error without extra requests', async () => {
  const state = setup({ injectionError: 'Missing host permission' });
  const response = await state.scan();
  assert.equal(response.ok, false);
  assert.equal(response.error, 'Missing host permission');
  assert.equal(state.requests.length, 0);
  assert.equal(state.cookieQueries.length, 0);
});

test('cookie API errors do not report a successful empty audit', async () => {
  const state = setup({ cookieError: 'Cookie access denied' });
  const response = await state.scan();
  assert.equal(response.ok, false);
  assert.equal(response.error, 'Cookie access denied');
});

test('IP targets skip external DNS queries', async () => {
  const state = setup({ tab: { id: 8, url: 'http://127.0.0.1:8000/' } });
  const response = await state.scan();
  assert.equal(response.ok, true);
  assert.equal(state.requests.some(url => url.startsWith('https://dns.google')), false);
  assert.equal(state.requests.length, 3);
});

test('unrelated extension messages do not start a scan', () => {
  const state = setup();
  assert.equal(state.listener({ type: 'unrelated' }, {}, () => { throw new Error('unexpected reply'); }), undefined);
  assert.equal(state.requests.length, 0);
});

test('popup treats page-controlled HTML and severity as text', () => {
  class Node {
    constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children = nodes; }
    addEventListener() {}
    set innerHTML(_) { throw new Error('Unsafe HTML rendering'); }
  }
  const nodes = new Map();
  const document = {
    querySelector: selector => { if (!nodes.has(selector)) nodes.set(selector, new Node(selector)); return nodes.get(selector); },
    createElement: tag => new Node(tag),
    createTextNode: text => Object.assign(new Node('#text'), { textContent: text }),
  };
  const attack = '<img src=x onerror=alert(1)>';
  const data = { meta: { url: attack, hostname: attack }, findings: [{ severity: attack, title: attack, detail: attack, evidence: attack }], technologies: [attack], cookies: [], endpoints: [], scripts: [], forms: [] };
  const context = vm.createContext({ document, browser: {}, data });
  vm.runInContext(fs.readFileSync(path.join(root, 'popup.js'), 'utf8'), context);
  vm.runInContext('render(data)', context);
  const all = node => [node, ...node.children.flatMap(all)];
  const rendered = [...nodes.values()].flatMap(all);
  assert.ok(rendered.some(node => node.textContent === attack));
  assert.equal(rendered.some(node => node.tag === 'img'), false);
  assert.ok(rendered.some(node => node.className === 'card finding info'));
  assert.equal(nodes.get('#summary').hidden, false);
});

