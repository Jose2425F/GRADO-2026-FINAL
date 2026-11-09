// Fresh local login smoke: owns its server/data and never starts an audit.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdir, mkdtemp, rm, writeFile} from 'node:fs/promises';
import net from 'node:net';
import {tmpdir} from 'node:os';
import {isAbsolute, join, relative, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const python = process.env.CENTINELA_SMOKE_PYTHON || join(repo, 'piloto_kali/prototipo/.venv/bin/python');
const artifactInput = process.env.CENTINELA_SMOKE_ARTIFACTS || process.argv[2];
const artifacts = artifactInput ? resolve(artifactInput) : null;
if (artifacts) {
  const location = relative(resolve(repo), artifacts);
  assert(location === '..' || location.startsWith('..' + sep) || isAbsolute(location),
    'Guarda los artefactos fuera del repositorio.');
  await mkdir(artifacts, {recursive: true});
}
const temporary = await mkdtemp(join(tmpdir(), 'centinela-smoke-'));
const data = join(temporary, 'data');
const runs = join(temporary, 'runs');
const privateHome = join(temporary, 'home');
await mkdir(privateHome, {mode: 0o700});
const username = 'smoke-' + randomBytes(6).toString('hex');
const password = randomBytes(32).toString('base64url');
const sensitive = [password];
const redact = value => sensitive.reduce((text, secret) => text.split(secret).join('[redacted]'), String(value));
const childEnv = {
  PATH: process.env.PATH,
  LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
  HOME: privateHome, XDG_CONFIG_HOME: join(privateHome, '.config'),
  CENTINELA_DATA_DIR: data,
  DOCKER_HOST: 'unix://' + join(temporary, 'nonexistent-docker.sock'),
  LANGSMITH_TRACING: 'false', LANGCHAIN_TRACING_V2: 'false',
  ...(process.env.CENTINELA_CI_GUARD_PATH ? {PYTHONPATH: process.env.CENTINELA_CI_GUARD_PATH} : {}),
};
let backend;
let browser;
let backendOutput = '';
const pageErrors = [];
const consoleErrors = [];
const assetFailures = [];
const externalRequests = [];
const forbiddenPosts = [];
const servedAssets = new Set();
const summary = {status: 'running', temporary_account: true, temporary_data: true,
  backend_owned_by_test: true, existing_panel_contacted: false,
  docker_endpoint_is_nonexistent_temporary_socket: true,
  audit_requests_sent: 0, provider_requests_sent: 0};

async function runAdmin() {
  const child = spawn(python, [join(repo, 'scripts/administrar_centinela.py'),
    '--data-dir', data, 'crear-admin', username, '--nombre', 'Aceptación temporal'],
    // A new session prevents getpass from opening the caller's controlling TTY.
    {cwd: repo, env: childEnv, detached: true, stdio: ['pipe', 'pipe', 'pipe']});
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  child.stdin.on('error', () => {}); // A failed spawn is reported by its error event.
  child.stdin.end(password + '\n' + password + '\n');
  const failure = new Promise((_, reject) => child.once('error', reject));
  const timeout = setTimeout(() => child.kill('SIGKILL'), 15000);
  try {
    const [code] = await Promise.race([once(child, 'exit'), failure]);
    assert.equal(code, 0, 'La CLI de administrador temporal no terminó correctamente: ' + redact(output));
  } finally { clearTimeout(timeout); }
}

async function unusedPort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise((resolveClose, reject) => server.close(error => error ? reject(error) : resolveClose()));
  assert(port > 1024 && port !== 8765, 'La prueba necesita un puerto local propio.');
  return port;
}

async function stopBackend() {
  if (!backend?.pid || backend.exitCode !== null || backend.signalCode !== null) return;
  const stopped = once(backend, 'exit');
  backend.kill('SIGINT');
  let timer;
  try {
    await Promise.race([stopped, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('El servidor temporal no terminó.')), 5000);
    })]);
  } catch {
    // This is the exact child process started above, never a PID discovered by name.
    if (backend.exitCode === null && backend.signalCode === null) backend.kill('SIGKILL');
    await stopped;
  } finally { clearTimeout(timer); }
}

try {
  await runAdmin();
  const port = await unusedPort();
  const base = 'http://127.0.0.1:' + port;
  backend = spawn(python, [join(repo, 'scripts/dualstack_panel.py'),
    '--port', String(port), '--runs', runs],
    {cwd: repo, env: childEnv, stdio: ['ignore', 'pipe', 'pipe']});
  let backendSpawnError;
  backend.on('error', error => { backendSpawnError = error; });
  const collect = chunk => { backendOutput = (backendOutput + chunk).slice(-100000); };
  backend.stdout.on('data', collect); backend.stderr.on('data', collect);
  const deadline = Date.now() + 20000;
  while (true) {
    if (backendSpawnError) throw backendSpawnError;
    assert(backend.exitCode === null, 'El backend temporal terminó al iniciar: ' + redact(backendOutput));
    try {
      const response = await fetch(base + '/login', {redirect: 'manual', signal: AbortSignal.timeout(1000)});
      if (response.status === 200) break;
    } catch {}
    assert(Date.now() < deadline, 'El backend temporal no respondió: ' + redact(backendOutput));
    await new Promise(resolveWait => setTimeout(resolveWait, 100));
  }
  browser = await chromium.launch({headless: true,
    ...(process.env.CHROMIUM_BINARY ? {executablePath: process.env.CHROMIUM_BINARY} : {})});
  const context = await browser.newContext({viewport: {width: 1440, height: 960}});
  await context.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.protocol === 'http:' || url.protocol === 'https:') {
      if (url.origin !== base) {
        externalRequests.push({origin: url.origin, method: request.method()});
        await route.abort('blockedbyclient'); return;
      }
      if (!['GET', 'HEAD'].includes(request.method()) &&
          !['/api/auth/login', '/api/auth/logout'].includes(url.pathname)) {
        forbiddenPosts.push({path: url.pathname, method: request.method()});
        await route.abort('blockedbyclient'); return;
      }
    }
    await route.continue();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on('pageerror', error => pageErrors.push(redact(error.message)));
  const recordConsole = message => { if (message.type() === 'error') consoleErrors.push(redact(message.text())); };
  page.on('console', recordConsole);
  page.on('response', response => {
    const url = new URL(response.url());
    if (url.origin === base && /\.(?:css|js|webp|png|svg|woff2?)$/.test(url.pathname)) {
      servedAssets.add(url.pathname);
      if (response.status() >= 400) assetFailures.push({path: url.pathname, status: response.status()});
    }
  });
  await page.goto(base + '/login');
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  await page.locator('#login-form [type=submit]').click();
  await page.waitForURL(base + '/');
  await page.waitForFunction(() => document.querySelector('#connection')?.textContent.startsWith('Conectado'));
  const state = await page.evaluate(async () => {
    const response = await fetch('/api/state');
    return {status: response.status, body: await response.json()};
  });
  assert.equal(state.status, 200, 'No se pudo leer el estado autenticado.');
  assert.deepEqual(state.body.runs, [], 'La cuenta temporal debe empezar sin auditorías.');
  assert.equal(state.body.openai_available, false, 'La prueba debe iniciar sin configuración privada de OpenAI.');
  const me = await page.evaluate(async () => (await fetch('/api/me')).json());
  assert.equal(me.user.username, username);
  assert.equal(me.user.role, 'admin');
  for (const cookie of await context.cookies()) sensitive.push(cookie.value);
  await page.goto(base + '/admin');
  const users = await page.evaluate(async () => {
    const response = await fetch('/api/admin/users');
    return {status: response.status, body: await response.json()};
  });
  assert.equal(users.status, 200);
  assert.equal(users.body.users.length, 1, 'Sólo debe existir el administrador generado para esta prueba.');
  assert.equal(users.body.users[0].username, username);
  assert.equal(await page.locator('form').count() > 0, true, 'No se renderizó la administración.');
  assert(servedAssets.size >= 4, 'No se cargaron los recursos locales de la interfaz.');
  assert.deepEqual(assetFailures, []);
  assert.deepEqual(pageErrors, []);
  assert.deepEqual(consoleErrors, []);
  assert.deepEqual(forbiddenPosts, []);
  assert.deepEqual(externalRequests, []);
  if (artifacts) await page.screenshot({path: join(artifacts, 'admin-fresh.png'), fullPage: true});
  page.off('console', recordConsole); // The deliberate unauthenticated request below is expected to return401.
  await page.locator('[data-logout]').first().click();
  await page.waitForURL(base + '/login');
  const loggedOut = await page.evaluate(async () => (await fetch('/api/me')).status);
  assert.equal(loggedOut, 401, 'La sesión no se revocó al salir.');
  assert.deepEqual(pageErrors, []);
  assert.deepEqual(forbiddenPosts, []);
  assert.deepEqual(externalRequests, []);
  Object.assign(summary, {status: 'passed', login: true, administrator_ui: true,
    authenticated_state: true, empty_history: true, logout_revokes_session: true,
    local_assets_loaded: servedAssets.size, page_errors: 0, console_errors_before_logout: 0,
    external_requests_attempted: 0, forbidden_post_requests_attempted: 0,
    backend_port_is_separate_from8765: true, private_configuration_used: false});
} catch (error) {
  summary.status = 'failed'; summary.error = redact(error.stack || error.message || error);
  console.error(summary.error);
  process.exitCode = 1;
} finally {
  try {
    if (browser) await browser.close();
  } catch (error) {
    summary.status = 'failed'; summary.cleanup_error = redact(error.message); process.exitCode = 1;
  } finally {
    await stopBackend();
    await rm(temporary, {recursive: true, force: true});
  }
  summary.owned_backend_stopped = true;
  summary.temporary_data_removed = true;
  if (artifacts) await writeFile(join(artifacts, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
  console.log(JSON.stringify(summary));
}
