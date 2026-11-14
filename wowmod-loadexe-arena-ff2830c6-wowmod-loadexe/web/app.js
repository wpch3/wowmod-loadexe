/* WoWMod Studio — 与真实 C++ CLI 联动的控制台。SPDX-License-Identifier: MIT */
'use strict';

const S = { config: null, plan: null, scan: null, patterns: [], mappings: [], cli: false, versions: [] };
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = (s, n = 60) => { s = String(s || ''); return s.length > n ? s.slice(0, n) + '…' : s; };

function toast(msg, err) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast show' + (err ? ' err' : '');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.className = 'toast'; }, 2800);
}

async function api(url, method = 'GET', body) {
  const r = await fetch(url, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({ error: '响应不是 JSON' }));
  if (!r.ok || j.error) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}

function planRoot() { return S.plan && S.plan.plan ? S.plan.plan : {}; }
function client() { return (S.plan && S.plan.client) || {}; }
function hooks() { return (S.plan && S.plan.hooks) || {}; }
function diagnostics() { return (S.plan && S.plan.diagnostics) || []; }
function overlays() { return planRoot().overlays || []; }
function stats() { return planRoot().stats || {}; }

async function loadState() {
  try {
    const st = await api('/api/state');
    Object.assign(S, st);
    S.versions = JSON.parse(localStorage.getItem('wowmod_versions') || '[]');
    if (!S.versions.length) { S.versions = ['12.0.7']; localStorage.setItem('wowmod_versions', JSON.stringify(S.versions)); }
    render();
  } catch (e) {
    $('topStatus').textContent = '连接失败';
    toast('无法连接后端: ' + e.message, true);
  }
}

async function refreshPlan(extra) {
  try {
    const r = await api('/api/plan', 'POST', { config: S.config });
    S.plan = r.plan;
    if (extra) Object.assign(S, extra);
    render();
    return true;
  } catch (e) { toast('重新计算失败: ' + e.message, true); return false; }
}

async function changeConfig(mutator, msg) {
  mutator(S.config);
  const ok = await refreshPlan();
  if (ok && msg) toast(msg);
}

/* ---------------- render ---------------- */
function render() {
  if (!S.config) return;
  const c = client(), h = hooks(), st = stats();
  $('topStatus').textContent = S.cli ? 'CLI 已连接 · 实时计划' : 'CLI 未构建';
  $('cliState').textContent = 'CLI: ' + (S.cli ? 'build/wowmod ✓' : '未构建');
  $('heroBuild').textContent = 'build ' + (c.build > 0 ? c.build : '未知');
  $('clientMini').innerHTML = `<div class="client-mini-title">${esc(c.version || '未知版本')}</div>
    <div class="client-mini-sub">${esc(c.arch || '?')} · ${esc(c.storage || '?')} · <span style="color:#4ade80">已支持</span></div>`;

  const cells = [
    ['客户端版本', c.version || '—'], ['架构 / 位数', c.arch || '—'], ['存储格式', c.storage || '—'],
    ['产品 / 分支', (c.product || '—') + ' / ' + (c.branch || '—')], ['游戏目录', c.game_dir || '—'],
    ['私服 portal', c.portal || '—'], ['支持状态', '已支持（无版本白名单）']
  ];
  $('clientGrid').innerHTML = cells.map(([k, v]) =>
    `<div class="cg"><label>${esc(k)}</label><b>${esc(short(v, 60))}</b></div>`).join('');
  $('clientNotes').innerHTML = (c.notes || []).map(n => '· ' + esc(n)).join('<br>') || '· 无版本白名单';

  // 版本 chips
  const chips = [`<div class="chip universal"><span class="ic">∞</span> 任意 build / 私服版本</div>`]
    .concat(S.versions.map(v => `<div class="chip"><span class="ic">W</span> ${esc(v)} <span style="color:#4ade80">✓ 已支持</span></div>`));
  $('versionChips').innerHTML = chips.join('');

  // 选项
  $('optPortalOn').checked = !!S.config.client.portal;
  $('optPortal').value = S.config.client.portal || '';
  $('optPortal').disabled = !S.config.client.portal;
  $('optFallback').checked = S.config.hooks.allowFallback !== false;
  $('optCache').checked = !!S.config.client.clearCache;
  $('optHookMode').value = S.config.hooks.mode || 'auto';

  // 覆盖表
  const q = ($('searchMods').value || '').toLowerCase();
  const rows = overlays().filter(o => !q || (o.key + ' ' + o.pack + ' ' + (o.from || '')).toLowerCase().includes(q));
  $('overlayCount').textContent = `${overlays().length} 条`;
  $('overlayRows').innerHTML = rows.length ? rows.map(o => `<tr>
    <td><span class="key">${esc(o.key)}</span>
      <span class="from">${o.generated ? '<span class="tag gen">内存生成</span> ' : ''}${esc(short(o.from || '(内存生成)', 90))}</span></td>
    <td>${o.fileId ? '<span class="tag">#' + esc(o.fileId) + '</span>' : '—'}</td>
    <td>${esc(o.via || '')}</td><td>${esc(short(o.pack || '', 32))}</td><td>${esc(o.priority)}</td></tr>`).join('')
    : '<tr><td colspan="5" style="color:#777;padding:20px;text-align:center">没有覆盖项</td></tr>';

  // 侧边模组列表
  const packs = S.config.mods || [];
  $('sidePacks').innerHTML = packs.map((p, i) => `<div class="side-pack ${p.enabled ? '' : 'off'} ${i === 0 ? 'active' : ''}" data-jump="mods">
    <span class="ico">◆</span><span class="nm">${esc(p.name)}</span><span style="font-size:10px;color:#777">${esc(p.priority || 0)}</span></div>`).join('') || '<div class="hint">还没有模组包</div>';
  $('modCount').textContent = packs.length + ' 个包';

  // 模组编辑
  $('packList').innerHTML = packs.map((p, i) => `<div class="pack ${p.enabled ? '' : 'off'}">
    <div class="pack-ico">◆</div>
    <div class="pack-body"><b>${esc(p.name)}</b><div class="path">${esc(p.path || '')}</div>
      <div class="hint" style="margin-top:4px">${esc((p.when && (p.when.minBuild || p.when.maxBuild || (p.when.products || []).length)) ? '有适用范围过滤' : '任何版本生效')} · 加载顺序 ${i + 1}</div></div>
    <div class="pack-ctl">
      <button class="mini" data-move="${i}" data-dir="-1" title="上移">↑</button>
      <button class="mini" data-move="${i}" data-dir="1" title="下移">↓</button>
      <input type="number" data-prio="${i}" value="${esc(p.priority || 0)}" title="优先级">
      <input type="checkbox" data-enable="${i}" ${p.enabled ? 'checked' : ''} title="启用">
      <button class="mini danger" data-del="${i}" title="删除">✕</button>
    </div></div>`).join('');

  $('filterList').innerHTML = packs.map((p, i) => {
    const w = p.when || {};
    return `<div class="filter-row"><b>${esc(p.name)}</b>
      <span>build ≥</span><input data-when="${i}" data-k="minBuild" type="number" style="max-width:100px" value="${esc(w.minBuild || 0)}">
      <span>build ≤</span><input data-when="${i}" data-k="maxBuild" type="number" style="max-width:100px" value="${esc(w.maxBuild || 0)}">
      <span>产品</span><input data-when="${i}" data-k="products" style="max-width:150px" value="${esc((w.products || []).join(','))}" placeholder="留空=任意">
      <span>存储</span><input data-when="${i}" data-k="storage" style="max-width:120px" value="${esc((w.storage || []).join(','))}" placeholder="casc,mpq"></div>`;
  }).join('') || '<div class="hint">暂无模组包</div>';

  // 映射文件
  $('mappingList').innerHTML = (S.mappings || []).map(m => `<div class="map-card"><div class="mi">≡</div><div style="flex:1;min-width:0">
    <b>${esc(m.path)}</b> <span class="tag ok">${esc(m.lines)} 条映射</span>
    <div class="hint">由 listfile 提供路径 ↔ FileDataID 关系：换版本只换这个文件</div>
    <pre>${esc(m.sample || '')}</pre></div></div>`).join('') || '<div class="hint">没有映射文件</div>';

  // hook 特征
  const results = (S.scan && S.scan.results) || [];
  $('patternRows').innerHTML = (S.patterns || []).map(p => {
    const r = results.find(x => x.name === p.name) || {};
    const n = r.matches == null ? '—' : r.matches;
    const cls = n === 1 ? 'ok' : n === 0 ? 'warn' : '';
    return `<tr><td><b>${esc(p.name)}</b><span class="from">${esc(short(p.note || '', 70))}</span></td>
      <td><span class="mono" title="${esc(p.pattern)}">${esc(short(p.pattern, 56))}</span></td>
      <td>${esc(p.arch || 'any')} / ${esc(p.idRegister || 'rdx')}</td>
      <td><span class="tag ${cls}">${n === 1 ? '唯一匹配 ✓' : n === 0 ? '无匹配' : n === '—' ? '—' : n + ' 处'}</span></td>
      <td>—</td></tr>`;
  }).join('') || '<tr><td colspan="5" style="color:#777;padding:20px;text-align:center">没有特征条目（纯 VFS 模式）</td></tr>';

  // 启动页
  $('launchOverlays').textContent = overlays().length;
  $('launchHook').textContent = h.mode || '—';
  $('launchBuild').textContent = c.build > 0 ? c.build : '未知';
  $('cmdText').textContent = 'wowmod launch --config examples/demo/wowmod.json';
  $('diagnostics').innerHTML = diagnostics().map(d => `<div class="diag ${esc(d.level)}"><span class="lv">${esc(d.level)}</span><span class="wh">${esc(d.where)}</span><span class="ms">${esc(d.message)}</span></div>`).join('') || '<div class="hint">无诊断信息</div>';
}

/* ---------------- events ---------------- */
$('nav').addEventListener('click', e => {
  const b = e.target.closest('button[data-tab]');
  if (!b) return;
  document.querySelectorAll('#nav button').forEach(x => x.classList.toggle('active', x === b));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === 'panel-' + b.dataset.tab));
});
document.addEventListener('click', e => {
  const j = e.target.closest('[data-jump]');
  if (j) document.querySelector(`#nav button[data-tab="${j.dataset.jump}"]`).click();
});
$('searchMods').addEventListener('input', render);

async function setVersion(v) {
  try {
    const r = await api('/api/version', 'POST', { version: v });
    S.plan = r.plan; S.scan = r.scan;
    if (!S.versions.includes(v)) { S.versions.push(v); localStorage.setItem('wowmod_versions', JSON.stringify(S.versions)); }
    $('versionInput').value = v; $('addVersion').value = '';
    render(); toast('已按 ' + v + ' 重新探测：仍然「已支持」');
  } catch (err) { toast(err.message, true); }
}
$('versionBtn').addEventListener('click', () => setVersion($('versionInput').value.trim()));
$('addVersionBtn').addEventListener('click', () => setVersion($('addVersion').value.trim()));
$('preset1207').addEventListener('click', () => setVersion('12.0.7'));
$('preset335').addEventListener('click', () => setVersion('3.3.5.12340'));

$('optPortalOn').addEventListener('change', e => changeConfig(cfg => {
  cfg.client.portal = e.target.checked ? (cfg.client.portal || $('optPortal').value || '127.0.0.1') : '';
}, 'portal 覆盖已更新'));
$('optPortal').addEventListener('change', e => changeConfig(cfg => { cfg.client.portal = e.target.value.trim(); }, 'portal 已保存'));
$('optFallback').addEventListener('change', e => changeConfig(cfg => { cfg.hooks.allowFallback = e.target.checked; }, '降级策略已更新'));
$('optCache').addEventListener('change', e => changeConfig(cfg => { cfg.client.clearCache = e.target.checked; }, '缓存策略已更新'));
$('optHookMode').addEventListener('change', e => changeConfig(cfg => { cfg.hooks.mode = e.target.value; }, 'hook 模式已更新'));

$('packList').addEventListener('click', e => {
  const t = e.target;
  if (t.dataset.move != null) {
    const i = +t.dataset.move, d = +t.dataset.dir, j = i + d;
    if (j < 0 || j >= S.config.mods.length) return;
    const m = S.config.mods; [m[i], m[j]] = [m[j], m[i]];
    changeConfig(() => {}, '加载顺序已调整');
  }
  if (t.dataset.del != null) {
    const i = +t.dataset.del;
    changeConfig(cfg => cfg.mods.splice(i, 1), '模组包已移除');
  }
});
$('packList').addEventListener('change', e => {
  const t = e.target;
  if (t.dataset.enable != null) changeConfig(cfg => { cfg.mods[+t.dataset.enable].enabled = t.checked; }, '启用状态已更新');
  if (t.dataset.prio != null) changeConfig(cfg => { cfg.mods[+t.dataset.prio].priority = Number(t.value) || 0; }, '优先级已更新');
});
$('filterList').addEventListener('change', e => {
  const t = e.target;
  if (t.dataset.when == null) return;
  const i = +t.dataset.when, k = t.dataset.k;
  changeConfig(cfg => {
    const p = cfg.mods[i]; p.when = p.when || {};
    if (k === 'products' || k === 'storage') p.when[k] = t.value.split(',').map(s => s.trim()).filter(Boolean);
    else p.when[k] = Number(t.value) || 0;
  }, '适用范围已更新');
});
$('addPackBtn').addEventListener('click', () => {
  const name = $('newPackName').value.trim(), p = $('newPackPath').value.trim();
  if (!name || !p) { toast('请填写名称与目录', true); return; }
  changeConfig(cfg => cfg.mods.push({ name, path: p, root: '', enabled: true, priority: 10, when: {} }), '模组包已添加（目录不存在时校验会提示）');
  $('newPackName').value = ''; $('newPackPath').value = '';
});

$('addPatternBtn').addEventListener('click', async () => {
  const name = $('pName').value.trim(), pattern = $('pPattern').value.trim();
  if (!name || !pattern) { toast('请填写名称与特征', true); return; }
  try {
    const r = await api('/api/pattern', 'POST', { pattern: { name, pattern, arch: $('pArch').value.trim(), idRegister: $('pReg').value.trim() } });
    S.patterns = r.patterns; S.plan = r.plan; S.scan = r.scan;
    render(); toast('特征已写入 patterns.json 并重新探测');
    $('pName').value = ''; $('pPattern').value = '';
  } catch (e) { toast(e.message, true); }
});

const DISCOVER_NOTE = '真实 12.0.7 Firestorm 的 exe 磁盘 .text 是加密的（熵 8.00），DLL 字符串被剥光，'
  + '静态扫描必然 xrefCount=0。请在 Windows 启动一次，让 hooks.runtimeScan 转储解密后的内存，'
  + '再用 wowmod discover --exe runtime-dumps/main.exe.img --mapped 分析。';

$('discoverBtn').addEventListener('click', async () => {
  const out = $('discoverOut');
  out.textContent = '正在扫描本地 exe …';
  try {
    const r = await api('/api/discover');
    const lines = [
      'exe: ' + (r.exe || '—') + '  ' + (r.arch || ''),
      '锚点命中: ' + ((r.anchorsFound || []).join(', ') || '无'),
      '目标 ' + (r.targetCount || 0) + ' 个 / 代码引用 ' + (r.xrefCount || 0) + ' 处',
      '候选: ' + (r.candidates || []).length + ' 个'
    ];
    (r.candidates || []).forEach((c, i) => {
      lines.push(`[${i + 1}] ${c.uniqueMatches === 1 ? '唯一匹配 ✓' : c.uniqueMatches + '+ 处'} @ rva 0x${(c.codeRva || 0).toString(16)}  ${c.anchor || ''}`);
      lines.push('    ' + c.pattern);
      lines.push('    ' + c.reason);
    });
    lines.push('', '⚠ ' + (r.note || ''));
    if (!(r.candidates || []).length) lines.push('', '提示: ' + DISCOVER_NOTE);
    out.textContent = lines.join('\n');
    toast('本地自动发现完成');
  } catch (e) { out.textContent = '错误: ' + e.message; toast(e.message, true); }
});

function log(msg) { $('launchLog').textContent = msg; }
$('launchBtn').addEventListener('click', async () => {
  log('正在调用 wowmod launch …');
  try {
    const r = await api('/api/launch');
    log(r.message || JSON.stringify(r, null, 2));
    toast(r.code === 0 ? '客户端已启动' : '见下方输出');
  } catch (e) { log('错误: ' + e.message); toast(e.message, true); }
});
$('saveBtn').addEventListener('click', async () => {
  try {
    const r = await api('/api/save', 'POST', { config: S.config });
    S.plan = r.plan; render(); log('已保存 examples/demo/wowmod.json\n' + JSON.stringify(S.config.client, null, 2));
    toast('配置已保存到工作区');
  } catch (e) { toast(e.message, true); }
});
$('exportBtn').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(S.config, null, 2) + '\n'], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'wowmod.json'; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast('已导出 wowmod.json');
});
$('refreshBtn').addEventListener('click', () => { loadState(); toast('已刷新'); });
$('copyCmd').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('cmdText').textContent); toast('命令已复制'); }
  catch (e) { toast('复制失败: ' + e.message, true); }
});

loadState();
