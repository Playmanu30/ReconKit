'use strict';

/* ReconKit frontend — no framework, no build step. */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const term = $('#term');
const STATUS_LABEL = {
  idle: 'idle', running: 'running', done: 'done', failed: 'failed',
  error: 'error', timeout: 'timeout', cancelled: 'stopped', interrupted: 'interrupted',
};
const ENGINE_LABEL = {
  ready: 'ready', missing: 'missing', conflict: 'wrong binary',
  needs_key: 'needs key', unverified: 'check binary', unsupported: 'needs WSL',
};

const state = {
  tools: [],
  tool: null,
  scan: null,
  es: null,
  roots: [],
  ai: { enabled: false, model: '' },
  lines: 0,
  timer: null,
  pending: null,
  handoff: null,
};

/* ---------------------------------------------------------------- utils */

function h(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

async function api(path, options = {}) {
  const opts = { ...options };
  if (opts.body) opts.headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = null;
    try { detail = (await res.json()).detail; } catch { /* not json */ }
    const message = typeof detail === 'string'
      ? detail
      : (detail && detail.message) || `Request failed (${res.status})`;
    const error = new Error(message);
    error.code = detail && detail.code;
    error.status = res.status;
    throw error;
  }
  return res.json();
}

let toastTimer;
function toast(message, kind = '') {
  const node = $('#toast');
  node.textContent = message;
  node.dataset.kind = kind;
  node.classList.add('is-on');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove('is-on'), 4500);
}

function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}

function fmtDuration(seconds) {
  const total = Math.max(0, Math.round(Number(seconds) || 0));
  const minutes = Math.floor(total / 60);
  return minutes ? `${minutes}m ${String(total % 60).padStart(2, '0')}s` : `${total}s`;
}

function statusLabel(status) {
  return STATUS_LABEL[status] || status || 'idle';
}

function targetLine(scan) {
  const inputs = scan.input_count ? ` · ${scan.input_count} inputs` : '';
  return `${scan.tool_name} → ${scan.target}${inputs}`;
}

function countLines(text) {
  return (text.match(/\n/g) || []).length;
}

function copyText(text) {
  if (!text) return;
  navigator.clipboard.writeText(text)
    .then(() => toast('Copied to clipboard'))
    .catch(() => toast('Copy failed', 'error'));
}

/* ---------------------------------------------------------------- data */

async function init() {
  try {
    const [data, scope] = await Promise.all([api('/api/tools'), api('/api/scope')]);
    state.ai = data.ai || state.ai;
    $('#aiNote').textContent = state.ai.enabled ? `AI · ${state.ai.model}` : 'local rules · no API key';
    state.roots = scope.roots;
    setTools(data.tools || []);
    renderScope();
    renderMeta(null);
    await Promise.all([loadRuns(), loadShots()]);
    if (state.tools.length) selectTool(state.tools[0]);
  } catch (error) {
    toast(error.message, 'error');
  }
}

function setTools(tools) {
  state.tools = tools;
  if (state.tool) state.tool = tools.find((tool) => tool.id === state.tool.id) || null;
  updateEngineSummary();
  renderTools();
}

function updateEngineSummary() {
  const total = state.tools.length;
  const ready = state.tools.filter((tool) => tool.engine.status === 'ready').length;
  $('#engineText').textContent = `${ready}/${total} engines ready`;
  $('#engineMeter .meter-dot').dataset.s = ready === 0 ? 'none' : ready === total ? 'ready' : 'partial';
  updateFoot();
}

function updateFoot() {
  $('#sideFoot').textContent = `${state.tools.length} tools · ${state.roots.length} in scope`;
  $('#scopeCount').textContent = String(state.roots.length);
}

/* ---------------------------------------------------------------- tools */

const collapsedGroups = new Set();
const CATEGORY = 'Reconnaissance';

function collapsibleGroup(label, key, query) {
  const section = h('div', 'tool-section');
  const open = Boolean(query) || !collapsedGroups.has(key);
  if (!open) section.classList.add('is-collapsed');
  const header = h('button', 'tool-group', label);
  header.type = 'button';
  header.setAttribute('aria-expanded', String(open));
  header.addEventListener('click', () => {
    const collapsed = section.classList.toggle('is-collapsed');
    header.setAttribute('aria-expanded', String(!collapsed));
    if (query) return;
    if (collapsed) collapsedGroups.add(key);
    else collapsedGroups.delete(key);
  });
  const itemsBox = h('div', 'tool-items');
  section.append(header, itemsBox);
  return { section, itemsBox };
}

function renderTools() {
  const query = $('#toolSearch').value.trim().toLowerCase();
  const list = $('#toolList');
  list.textContent = '';

  const category = collapsibleGroup(CATEGORY, CATEGORY, query);
  category.section.classList.add('tool-section--top');
  const groups = [...new Set(state.tools.map((tool) => tool.group))];
  for (const group of groups) {
    const items = state.tools.filter((tool) => tool.group === group
      && (!query || `${tool.name} ${tool.blurb} ${tool.id}`.toLowerCase().includes(query)));
    if (!items.length) continue;

    const sub = collapsibleGroup(group, group, query);
    for (const tool of items) {
      const button = h('button', 'tool');
      button.type = 'button';
      button.dataset.id = tool.id;
      button.dataset.state = tool.engine.status;
      button.title = tool.engine.message || tool.blurb;
      button.append(
        h('span', 'tool-name', tool.name),
        h('span', 'tool-blurb', tool.blurb),
        h('span', 'tool-state'),
      );
      button.querySelector('.tool-state').dataset.s = tool.engine.status;
      if (state.tool && state.tool.id === tool.id) button.setAttribute('aria-current', 'true');
      button.addEventListener('click', () => selectTool(tool));
      sub.itemsBox.append(button);
    }
    category.itemsBox.append(sub.section);
  }
  if (category.itemsBox.childElementCount) list.append(category.section);
  else list.append(h('p', 'muted', 'No tool matches that filter.'));
}

function selectTool(tool, opts = {}) {
  if (!tool) return;
  if (state.scan && state.scan.status === 'running' && state.tool && state.tool.id !== tool.id) {
    toast('Stop the running scan before switching tools.', 'error');
    return;
  }

  state.tool = tool;
  $('#toolGroup').textContent = tool.group;
  $('#toolName').textContent = tool.name;
  $('#toolBlurb').textContent = tool.blurb;
  $('#target').placeholder = tool.target === 'url' ? 'https://example.com'
    : tool.target === 'host' ? '10.0.0.5 or example.com' : 'example.com';
  if (opts.target != null) $('#target').value = opts.target;
  else if (!opts.keepScan) $('#target').value = '';

  $('#preview').hidden = !tool.preview;
  $('#previewText').textContent = tool.preview || '';
  renderBadges(tool);
  renderOptions(tool);
  renderTools();

  if (!opts.keepScan) {
    state.scan = null;
    hideHandoff();
    setTerm('');
    setStatus('idle');
    $('#consoleTarget').textContent = '';
    $('#consoleTimer').textContent = '';
    $('#consoleExit').textContent = '';
    renderMeta(null);
    setAnalysis('');
    updateActions();
  }
}

function renderBadges(tool) {
  const box = $('#toolBadges');
  box.textContent = '';
  const badges = [];
  badges.push([tool.target === 'url' ? 'web target' : tool.target === 'host' ? 'host / ip' : 'domain', 'kind']);
  if (tool.api) badges.push(['third-party api', 'api']);
  else badges.push([tool.passive ? 'passive sources' : 'active scan', tool.passive ? 'passive' : 'warn']);
  badges.push([`${tool.timeout >= 120 ? `${Math.round(tool.timeout / 60)}m` : `${tool.timeout}s`} cap`, 'kind']);
  if (tool.engine.status !== 'ready') {
    badges.push([ENGINE_LABEL[tool.engine.status] || tool.engine.status, 'warn']);
  }
  for (const [text, kind] of badges) {
    const badge = h('span', 'badge', text);
    badge.dataset.kind = kind;
    badge.title = tool.engine.message || text;
    box.append(badge);
  }
}

function renderOptions(tool) {
  const box = $('#options');
  box.textContent = '';

  for (const opt of tool.options) {
    const wrap = h('div', opt.kind === 'bool' ? 'opt opt-check' : 'opt');
    const id = `opt-${opt.key}`;

    if (opt.kind === 'bool') {
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.id = id;
      input.dataset.opt = opt.key;
      input.checked = Boolean(opt.default);
      const label = h('label', 'opt-label', opt.label);
      label.htmlFor = id;
      wrap.append(input, label);
    } else if (opt.kind === 'select') {
      const label = h('label', 'opt-label', opt.label);
      label.htmlFor = id;
      const select = document.createElement('select');
      select.id = id;
      select.dataset.opt = opt.key;
      for (const choice of opt.choices) {
        const option = document.createElement('option');
        option.value = choice;
        option.textContent = choice;
        select.append(option);
      }
      select.value = opt.default;
      wrap.append(label, select);
    } else {
      const label = h('label', 'opt-label', opt.label);
      label.htmlFor = id;
      const input = document.createElement('input');
      input.type = 'text';
      input.id = id;
      input.dataset.opt = opt.key;
      input.value = opt.default;
      input.spellcheck = false;
      wrap.append(label, input);
    }

    if (opt.hint) wrap.append(h('span', 'hint', opt.hint));
    box.append(wrap);
  }

  if (!tool.api) {
    const wrap = h('div', 'opt extra-flags');
    const label = h('label', 'opt-label', 'Extra flags');
    label.htmlFor = 'extraFlags';
    const input = document.createElement('input');
    input.type = 'text';
    input.id = 'extraFlags';
    input.placeholder = '-timeout 20 -random-agent';
    input.spellcheck = false;
    input.autocomplete = 'off';
    wrap.append(label, input, h('span', 'hint', 'Appended as separate arguments. Only use flags you understand.'));
    box.append(wrap);
  }
}

function collectOptions() {
  const values = {};
  for (const node of $$('[data-opt]', $('#options'))) {
    values[node.dataset.opt] = node.type === 'checkbox' ? node.checked : node.value;
  }
  return values;
}

function buildBody() {
  if (!state.tool) { toast('Pick a tool first.', 'error'); return null; }
  const target = $('#target').value.trim();
  if (!target) { $('#target').focus(); toast('Enter a target.', 'error'); return null; }
  const extra = $('#extraFlags');
  return {
    tool_id: state.tool.id,
    target,
    options: collectOptions(),
    extra_args: extra ? extra.value : '',
  };
}

/* ---------------------------------------------------------------- scans */

function setStatus(status) {
  const pill = $('#statusPill');
  pill.dataset.status = status || 'idle';
  pill.textContent = statusLabel(status);
}

function setTerm(text) {
  term.textContent = '';
  state.lines = 0;
  if (!text) {
    term.append(h('span', 'term-empty', 'No output yet. Pick a tool, enter a target, and run it.'));
  } else {
    term.textContent = text;
    state.lines = countLines(text);
    term.scrollTop = 0;
  }
  updateLineCount();
}

function appendTerm(text) {
  if (!text) return;
  const empty = term.querySelector('.term-empty');
  if (empty) empty.remove();

  for (const line of text.match(/[^\n]*\n|[^\n]+/g) || [text]) {
    const span = document.createElement('span');
    span.textContent = line;
    const tone = toneOf(line);
    if (tone) span.className = tone;
    term.append(span);
  }

  state.lines += countLines(text);
  if (term.childNodes.length > 4000) {
    term.textContent = term.textContent.slice(-300000);
    state.lines = countLines(term.textContent);
  }

  if ($('#autoscroll').checked
      && term.scrollHeight - term.scrollTop - term.clientHeight < 90) {
    term.scrollTop = term.scrollHeight;
  }
  updateLineCount();
}

function toneOf(line) {
  if (/\b(critical|high|vulnerab|exploit|CVE-\d{4})/i.test(line) || /\[!\]/.test(line)) return 'hot';
  if (/\b(401|403|forbidden|denied|timed?\s?out|timeout|error)\b/i.test(line)) return 'warn';
  if (/\b(200|201|204|301|302|303|307|308)\b/i.test(line) || /\bopen\b/.test(line)) return 'ok';
  return '';
}

function updateLineCount() {
  $('#lineCount').textContent = `${state.lines.toLocaleString()} lines`;
}

function updateActions() {
  const running = Boolean(state.scan && state.scan.status === 'running');
  $('#runBtn').disabled = running;
  $('#stopBtn').hidden = !running;
  const output = state.scan && state.scan.output ? state.scan.output.trim() : '';
  $('#analyzeBtn').disabled = !state.scan || running || !output.length;

  const link = $('#exportBtn');
  if (state.scan && !running) {
    link.href = `/api/scans/${state.scan.id}/export`;
    link.classList.remove('is-disabled');
    link.setAttribute('aria-disabled', 'false');
  } else {
    link.href = '#';
    link.classList.add('is-disabled');
    link.setAttribute('aria-disabled', 'true');
  }
}

function renderMeta(scan) {
  const box = $('#scanMeta');
  box.textContent = '';
  if (!scan) return;
  const cells = [
    ['Tool', scan.tool_name || scan.tool],
    ['Status', statusLabel(scan.status)],
    ['Started', fmtTime(scan.started)],
    ['Duration', fmtDuration(scan.duration || (scan.finished ? scan.finished - scan.started : 0))],
    ['Target', scan.target],
    ['Exit', scan.exit_code != null ? String(scan.exit_code) : '—'],
  ];
  for (const [key, value] of cells) {
    const cell = h('div', 'meta-cell');
    cell.append(h('span', 'meta-k', key), h('span', 'meta-v', value));
    cell.title = String(value);
    box.append(cell);
  }
}

function setAnalysis(text) {
  const box = $('#analysis');
  box.textContent = '';
  if (!text) {
    box.append(h('p', 'muted', 'Run a scan, then analyse it. With no AI key set, a local rule-based summary is used.'));
    return;
  }
  box.textContent = text;
}

function startTimer() {
  stopTimer();
  const tick = () => {
    if (!state.scan || state.scan.status !== 'running') return;
    $('#consoleTimer').textContent = fmtDuration((Date.now() / 1000) - state.scan.started);
  };
  tick();
  state.timer = setInterval(tick, 500);
}

function stopTimer() {
  if (state.timer) clearInterval(state.timer);
  state.timer = null;
}

async function startScan(body) {
  try {
    const scan = await api('/api/scans', { method: 'POST', body: JSON.stringify(body) });
    attach(scan);
  } catch (error) {
    if (error.code === 'out_of_scope') { openAuth(body); return; }
    if (error.code === 'not_installed' || error.code === 'wrong_binary') {
      toast(error.message, 'error');
      openSetup();
      return;
    }
    toast(error.message, 'error');
  }
}

function attach(scan) {
  const tool = state.tools.find((item) => item.id === scan.tool);
  if (tool && state.tool && state.tool.id !== tool.id) {
    selectTool(tool, { keepScan: true, target: scan.target });
  }
  state.scan = scan;
  hideHandoff();
  $('#consoleTarget').textContent = targetLine(scan);
  $('#consoleTimer').textContent = '';
  $('#consoleExit').textContent = '';
  setTerm('');
  setStatus(scan.status);
  updateActions();
  startTimer();
  renderMeta(scan);
  setAnalysis('');
  loadRuns();

  if (state.es) state.es.close();
  const source = new EventSource(`/api/scans/${scan.id}/stream`);
  state.es = source;

  source.addEventListener('chunk', (event) => {
    if (!state.scan || state.scan.id !== scan.id) return;
    appendTerm(JSON.parse(event.data).v);
  });

  source.addEventListener('end', (event) => {
    const payload = JSON.parse(event.data);
    source.close();
    if (state.scan && state.scan.id === scan.id) finish(scan.id, payload);
  });

  source.onerror = () => {
    if (source.readyState === EventSource.CLOSED) return;
    source.close();
    resync(scan.id);
  };
}

async function finish(id, payload) {
  stopTimer();
  if (state.scan && state.scan.id === id) {
    state.scan.status = payload.status;
    state.scan.exit_code = payload.exit_code;
  }
  setStatus(payload.status);
  $('#consoleExit').textContent = payload.exit_code != null ? `exit ${payload.exit_code}` : '';

  try {
    const scan = await api(`/api/scans/${id}`);
    if (!state.scan || state.scan.id !== id) return;
    state.scan = scan;
    renderMeta(scan);
    $('#consoleTarget').textContent = targetLine(scan);
    $('#consoleTimer').textContent = fmtDuration(scan.duration || 0);
    $('#consoleExit').textContent = scan.exit_code != null ? `exit ${scan.exit_code}` : '';
    setStatus(scan.status);
    if (scan.analysis) {
      setAnalysis(scan.analysis);
      $('#aiNote').textContent = scan.engine === 'ai' ? `AI · ${state.ai.model}` : 'local rules';
    }
    await loadHandoff(scan.id);
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    updateActions();
    loadRuns();
    loadShots();
  }
}

async function resync(id) {
  if (!state.scan || state.scan.id !== id) return;
  try {
    const scan = await api(`/api/scans/${id}`);
    if (!state.scan || state.scan.id !== id) return;
    state.scan = scan;
    setTerm(scan.output || '');
    renderMeta(scan);
    setStatus(scan.status);
    if (scan.status === 'running') {
      setTimeout(() => resync(id), 1500);
    } else {
      finish(id, { status: scan.status, exit_code: scan.exit_code });
    }
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function loadScan(id) {
  if (state.scan && state.scan.status === 'running') {
    toast('Stop the running scan before opening another one.', 'error');
    return;
  }
  try {
    const scan = await api(`/api/scans/${id}`);
    const tool = state.tools.find((item) => item.id === scan.tool);
    if (tool) selectTool(tool, { keepScan: true, target: scan.target });
    state.scan = scan;
    setTerm(scan.output || '');
    setStatus(scan.status);
    $('#consoleTarget').textContent = targetLine(scan);
    $('#consoleExit').textContent = scan.exit_code != null ? `exit ${scan.exit_code}` : '';
    $('#consoleTimer').textContent = fmtDuration(scan.duration || 0);
    renderMeta(scan);
    setAnalysis(scan.analysis || '');
    $('#aiNote').textContent = scan.analysis
      ? (scan.engine === 'ai' ? `AI · ${state.ai.model}` : 'local rules')
      : (state.ai.enabled ? `AI · ${state.ai.model}` : 'local rules · no API key');
    await loadHandoff(scan.id);
    updateActions();
    loadRuns();
    switchTab('report');
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function loadRuns() {
  const list = $('#runsList');
  try {
    const data = await api('/api/scans');
    list.textContent = '';
    if (!data.scans.length) {
      list.append(h('p', 'muted', 'No runs yet.'));
      return;
    }
    for (const scan of data.scans) {
      const button = h('button', 'run');
      button.type = 'button';
      if (state.scan && state.scan.id === scan.id) button.classList.add('is-current');
      button.append(
        h('span', 'run-tool', scan.tool_name),
        h('span', 'run-time', fmtTime(scan.started)),
        h('span', 'run-target', scan.target),
        h('span', 'run-state', statusLabel(scan.status)),
      );
      button.querySelector('.run-state').dataset.s = scan.status;
      button.title = `${scan.tool_name} · ${scan.target} · ${statusLabel(scan.status)}`;
      button.addEventListener('click', () => loadScan(scan.id));
      list.append(button);
    }
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function loadShots() {
  const grid = $('#shotsGrid');
  try {
    const data = await api('/api/shots');
    grid.textContent = '';
    if (!data.shots.length) {
      grid.append(h('p', 'muted', 'No screenshots yet. Run GoWitness against a live URL.'));
      return;
    }
    for (const shot of data.shots) {
      const link = document.createElement('a');
      link.className = 'shot';
      link.href = shot.url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      const image = document.createElement('img');
      image.src = shot.url;
      image.alt = shot.name;
      image.loading = 'lazy';
      link.append(image, h('span', 'shot-name', shot.name));
      grid.append(link);
    }
  } catch (error) {
    toast(error.message, 'error');
  }
}

/* ---------------------------------------------------------------- handoff */

function hideHandoff() {
  state.handoff = null;
  const box = $('#handoff');
  if (box) box.hidden = true;
}

async function loadHandoff(id) {
  hideHandoff();
  if (!id) return;
  try {
    const data = await api(`/api/scans/${id}/handoff`);
    if (!state.scan || state.scan.id !== id) return;
    state.handoff = data;
    renderHandoff();
  } catch {
    /* scans with no output simply have nothing to hand off */
  }
}

function renderHandoff() {
  const data = state.handoff;
  const box = $('#handoff');
  if (!data || !data.count || !data.tools.length) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  $('#handoffCount').textContent = `${data.count} in scope`;

  const select = $('#handoffTool');
  select.textContent = '';
  for (const tool of data.tools) {
    const option = document.createElement('option');
    option.value = tool.id;
    option.textContent = `${tool.name} (${tool.count})`;
    select.append(option);
  }
  const preferred = data.tools.find((tool) => tool.id === 'httpx') || data.tools[0];
  select.value = preferred.id;
  updateHandoffNote();
}

function updateHandoffNote() {
  const data = state.handoff;
  if (!data) return;
  const selected = data.tools.find((tool) => tool.id === $('#handoffTool').value);
  if (!selected) return;
  const preview = data.preview.slice(0, 3).join(', ');
  const more = data.preview.length > 3 ? '…' : '';
  $('#handoffNote').textContent =
    `${selected.name} will scan ${selected.count} in-scope target${selected.count === 1 ? '' : 's'}. `
    + `Preview: ${preview}${more}`;
}

async function runHandoff() {
  if (!state.scan || !state.handoff) return;
  const button = $('#handoffBtn');
  button.disabled = true;
  try {
    const scan = await api('/api/scans', {
      method: 'POST',
      body: JSON.stringify({
        tool_id: $('#handoffTool').value,
        target: state.scan.target,
        options: {},
        extra_args: '',
        source_id: state.scan.id,
      }),
    });
    toast(`Sent ${scan.input_count || 0} targets to ${scan.tool_name}`);
    attach(scan);
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    button.disabled = false;
  }
}

/* ---------------------------------------------------------------- scope */

function renderScope() {
  const list = $('#scopeList');
  list.textContent = '';
  if (!state.roots.length) {
    const empty = h('li', 'scope-item muted', 'Nothing in scope yet.');
    list.append(empty);
  }
  for (const root of state.roots) {
    const item = h('li', 'scope-item');
    item.append(h('span', '', root));
    const remove = h('button', 'icon-btn', 'remove');
    remove.type = 'button';
    remove.addEventListener('click', async () => {
      try {
        const data = await api(`/api/scope/${encodeURIComponent(root)}`, { method: 'DELETE' });
        state.roots = data.roots;
        renderScope();
        updateFoot();
      } catch (error) {
        toast(error.message, 'error');
      }
    });
    item.append(remove);
    list.append(item);
  }
  updateFoot();
}

async function addScope(root) {
  const data = await api('/api/scope', { method: 'POST', body: JSON.stringify({ root }) });
  state.roots = data.roots;
  renderScope();
  updateFoot();
  return data;
}

function openAuth(body) {
  state.pending = body;
  $('#authHost').textContent = body.target;
  $('#authCheck').checked = false;
  $('#authConfirm').disabled = true;
  $('#authDialog').showModal();
}

async function openSetup() {
  $('#setupList').textContent = 'Checking engines…';
  $('#setupDialog').showModal();
  try {
    const statuses = await api('/api/engines?refresh=1');
    state.tools = state.tools.map((tool) => ({ ...tool, engine: statuses[tool.id] || tool.engine }));
    if (state.tool) state.tool = state.tools.find((tool) => tool.id === state.tool.id) || state.tool;
    updateEngineSummary();
    renderTools();
    renderSetup();
  } catch (error) {
    $('#setupList').textContent = error.message;
    toast(error.message, 'error');
  }
}

function renderSetup() {
  const list = $('#setupList');
  list.textContent = '';
  for (const tool of state.tools) {
    const engine = tool.engine;
    const row = h('div', 'setup-row');

    const name = h('div', 'setup-name');
    name.append(document.createTextNode(tool.name));
    const tag = h('span', 'tag', ENGINE_LABEL[engine.status] || engine.status);
    tag.dataset.s = engine.status;
    name.append(tag);

    const message = h(
      'div', 'setup-msg',
      engine.status === 'ready'
        ? (engine.version || engine.path || 'ready')
        : (engine.message || engine.status),
    );
    row.append(name, message);

    if (engine.status !== 'ready' && tool.install) {
      const command = h('div', 'setup-cmd');
      const code = h('code', '', tool.install);
      const copy = h('button', 'icon-btn', 'copy');
      copy.type = 'button';
      copy.addEventListener('click', () => copyText(tool.install));
      command.append(code, copy);
      row.append(command);
    }

    if (tool.docs) {
      const docs = h('div', 'setup-doc');
      const link = document.createElement('a');
      link.href = tool.docs;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = tool.docs;
      docs.append(link);
      row.append(docs);
    }
    list.append(row);
  }
}

/* ---------------------------------------------------------------- tabs + events */

function switchTab(name) {
  $$('.tab').forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', String(active));
  });
  $$('.rail-panel').forEach((panel) => {
    panel.classList.toggle('is-active', panel.id === `panel-${name}`);
  });
  if (name === 'shots') loadShots();
  if (name === 'runs') loadRuns();
}

$('#runForm').addEventListener('submit', (event) => {
  event.preventDefault();
  const body = buildBody();
  if (body) startScan(body);
});

$('#stopBtn').addEventListener('click', async () => {
  if (!state.scan) return;
  const button = $('#stopBtn');
  button.disabled = true;
  try {
    await api(`/api/scans/${state.scan.id}/stop`, { method: 'POST' });
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    button.disabled = false;
  }
});

$('#analyzeBtn').addEventListener('click', async () => {
  if (!state.scan) return;
  const button = $('#analyzeBtn');
  button.disabled = true;
  button.textContent = 'Analysing…';
  const box = $('#analysis');
  box.textContent = !state.ai.enabled
    ? 'Building a rule-based summary…'
    : (state.ai.local
      ? 'Analysing locally… the first run after idle can take about a minute.'
      : 'Sending the output to the configured model…');
  try {
    const result = await api(`/api/scans/${state.scan.id}/analyze`, { method: 'POST' });
    state.scan.analysis = result.analysis;
    state.scan.engine = result.engine;
    setAnalysis(result.analysis);
    $('#aiNote').textContent = result.engine === 'ai' ? `AI · ${state.ai.model}` : 'local rules';
    loadRuns();
  } catch (error) {
    box.textContent = error.message;
    toast(error.message, 'error');
  } finally {
    button.textContent = 'Analyse';
    updateActions();
  }
});

$('#clearConsole').addEventListener('click', () => setTerm(''));

$('#handoffTool').addEventListener('change', updateHandoffNote);
$('#handoffBtn').addEventListener('click', runHandoff);

$('#copyPreview').addEventListener('click', () => copyText($('#previewText').textContent));

$('#refreshRuns').addEventListener('click', loadRuns);
$('#refreshShots').addEventListener('click', loadShots);
$('#setupBtn').addEventListener('click', openSetup);
$('#scopeBtn').addEventListener('click', () => $('#scopeDialog').showModal());

$('#toolSearch').addEventListener('input', renderTools);
$('#toolSearch').addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    $('#toolSearch').value = '';
    renderTools();
    $('#toolSearch').blur();
  }
});

$('#scopeAdd').addEventListener('click', async () => {
  const input = $('#scopeInput');
  const value = input.value.trim();
  if (!value) { input.focus(); return; }
  try {
    await addScope(value);
    input.value = '';
    toast('Added to scope');
  } catch (error) {
    toast(error.message, 'error');
  }
});

$('#scopeInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    $('#scopeAdd').click();
  }
});

$('#authCheck').addEventListener('change', (event) => {
  $('#authConfirm').disabled = !event.target.checked;
});

$('#authConfirm').addEventListener('click', async () => {
  if (!state.pending) return;
  const body = state.pending;
  try {
    await addScope(body.target);
    $('#authDialog').close();
    state.pending = null;
    await startScan(body);
  } catch (error) {
    toast(error.message, 'error');
  }
});

$$('.tab').forEach((tab) => tab.addEventListener('click', () => switchTab(tab.dataset.tab)));

$$('[data-close]').forEach((button) => {
  button.addEventListener('click', () => {
    const dialog = button.closest('dialog');
    if (dialog) dialog.close();
  });
});

document.addEventListener('keydown', (event) => {
  const active = document.activeElement;
  const typing = active && ['INPUT', 'TEXTAREA', 'SELECT'].includes(active.tagName);
  if (event.key === '/' && !typing && !event.ctrlKey && !event.metaKey) {
    event.preventDefault();
    $('#toolSearch').focus();
  }
  if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    if (!typing) $('#runForm').requestSubmit();
  }
});

/* ---------------------------------------------------------------- go */

init();
