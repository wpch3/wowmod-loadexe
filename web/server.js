#!/usr/bin/env node
// WoWMod Studio 的零依赖本地服务器。
// 它直接调用真实的 C++ CLI（wowmod plan / detect / scan），不是静态 mock 数据。
// SPDX-License-Identifier: MIT
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { execFile, execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'build', 'wowmod');
const DEMO_DIR = path.join(ROOT, 'examples', 'demo');
const DEMO_CONFIG = path.join(DEMO_DIR, 'wowmod.json');
const PREVIEW_CONFIG = path.join(DEMO_DIR, '.preview.json');
const CLIENT_DIR = path.join(DEMO_DIR, 'client');
const PATTERNS_FILE = path.join(DEMO_DIR, 'hooks', 'patterns.json');
const PORT = Number(process.env.PORT || 3000);

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml' };

function send(res, code, body, type = 'application/json; charset=utf-8') {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 2e6) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

function cli(args) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(CLI)) { reject(new Error('未找到 build/wowmod，请先运行: cmake -S . -B build && cmake --build build')); return; }
    execFile(CLI, args, { cwd: ROOT, maxBuffer: 32 * 1024 * 1024, timeout: 20000 }, (err, stdout, stderr) => {
      if (err && !stdout) { reject(new Error(stderr || err.message)); return; }
      try { resolve(JSON.parse(stdout)); } catch (e) { reject(new Error('CLI 输出不是 JSON: ' + stdout.slice(0, 300))); }
    });
  });
}

function loadConfig() {
  const raw = fs.readFileSync(DEMO_CONFIG, 'utf8');
  // 去掉 // 与 /* */ 注释（配置是 JSONC）
  const stripped = raw.replace(/\/\*[\s\S]*?\*\//g, '').split('\n').map(l => l.replace(/\/\/.*$/, '')).join('\n').replace(/,(\s*[}\]])/g, '$1');
  return JSON.parse(stripped);
}

function writeConfig(cfg, file) {
  fs.writeFileSync(file, JSON.stringify(cfg, null, 2) + '\n', 'utf8');
}

async function planFor(cfg) {
  writeConfig(cfg, PREVIEW_CONFIG);
  return cli(['plan', '--config', PREVIEW_CONFIG, '--json']);
}

function mappingContents(cfg) {
  return (cfg.mappings || []).map(p => {
    const full = path.resolve(DEMO_DIR, p);
    let text = '';
    try { text = fs.readFileSync(full, 'utf8'); } catch (e) { text = '(无法读取)'; }
    const lines = text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
    return { path: p, full, lines: lines.length, sample: lines.slice(0, 6).join('\n') };
  });
}

async function api(req, res, url) {
  const route = url.pathname;
  if (req.method === 'GET' && route === '/api/state') {
    const cfg = loadConfig();
    const plan = await planFor(cfg);
    const scan = await cli(['scan', '--config', PREVIEW_CONFIG, '--json']).catch(e => ({ error: e.message }));
    let patterns = [];
    try { patterns = JSON.parse(fs.readFileSync(PATTERNS_FILE, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').split('\n').map(l => l.replace(/\/\/.*$/, '')).join('\n')).patterns || []; } catch (e) { /* ignore */ }
    return send(res, 200, { config: cfg, plan, scan, patterns, mappings: mappingContents(cfg), cli: fs.existsSync(CLI) });
  }
  if (req.method === 'POST' && route === '/api/plan') {
    const body = await readBody(req);
    if (!body.config) return send(res, 400, { error: '缺少 config' });
    const plan = await planFor(body.config);
    return send(res, 200, { plan });
  }
  if (req.method === 'POST' && route === '/api/save') {
    const body = await readBody(req);
    if (!body.config) return send(res, 400, { error: '缺少 config' });
    writeConfig(body.config, DEMO_CONFIG);
    const plan = await planFor(body.config);
    return send(res, 200, { ok: true, plan });
  }
  if (req.method === 'POST' && route === '/api/version') {
    const body = await readBody(req);
    const v = String(body.version || '').trim();
    if (!/^\d{1,3}(\.\d{1,6}){1,3}$/.test(v)) return send(res, 400, { error: '版本格式应类似 12.1.5.70783' });
    await new Promise((resolve, reject) => {
      execFile('python3', [path.join(ROOT, 'tools', 'make_fake_client.py'), '--dir', CLIENT_DIR, '--version', v],
        { cwd: ROOT }, (err, stdout, stderr) => err ? reject(new Error(stderr || err.message)) : resolve(stdout));
    });
    const cfg = loadConfig();
    const plan = await planFor(cfg);
    const scan = await cli(['scan', '--config', PREVIEW_CONFIG, '--json']).catch(e => ({ error: e.message }));
    return send(res, 200, { ok: true, version: v, plan, scan });
  }
  if (req.method === 'POST' && route === '/api/pattern') {
    const body = await readBody(req);
    const p = body.pattern || {};
    if (!p.pattern || !p.name) return send(res, 400, { error: '需要 name 与 pattern' });
    let doc = { patterns: [] };
    try { doc = JSON.parse(fs.readFileSync(PATTERNS_FILE, 'utf8')); } catch (e) { /* 重建 */ }
    doc.patterns = (doc.patterns || []).filter(x => x.name !== p.name);
    doc.patterns.push({
      name: String(p.name).slice(0, 80), kind: 'fileId', arch: p.arch || 'x64',
      pattern: String(p.pattern).slice(0, 2000), offset: 0, idRegister: p.idRegister || 'rdx',
      result: 'rax=pathPtr', priority: Number(p.priority) || 0,
      note: '在 WoWMod Studio 中添加'
    });
    fs.writeFileSync(PATTERNS_FILE, JSON.stringify(doc, null, 2) + '\n', 'utf8');
    const cfg = loadConfig();
    const plan = await planFor(cfg);
    const scan = await cli(['scan', '--config', PREVIEW_CONFIG, '--json']).catch(e => ({ error: e.message }));
    return send(res, 200, { ok: true, plan, scan, patterns: doc.patterns });
  }
  if (req.method === 'GET' && route === '/api/launch') {
    // 在 Windows 上真正启动；其它平台返回 CLI 的提示。
    const r = await cli(['launch', '--config', DEMO_CONFIG, '--json']).catch(e => ({ error: e.message }));
    return send(res, 200, r);
  }
  return send(res, 404, { error: 'unknown route: ' + route });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    let rel = url.pathname === '/' ? '/index.html' : url.pathname;
    if (rel.includes('..')) return send(res, 400, { error: 'bad path' });
    const file = path.join(__dirname, rel);
    if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return send(res, 404, { error: 'not found' });
    return send(res, 200, fs.readFileSync(file), MIME[path.extname(file)] || 'application/octet-stream');
  } catch (e) {
    return send(res, 500, { error: e.message || String(e) });
  }
});

// 演示用的合成客户端是生成物，不进 Git；首次启动自动补齐。
function ensureDemoClient() {
  if (fs.existsSync(path.join(CLIENT_DIR, 'Wow.exe'))) return;
  try {
    execFileSync('python3', [path.join(ROOT, 'tools', 'make_fake_client.py'), '--dir', CLIENT_DIR, '--version', '3.3.5.12340'],
      { cwd: ROOT, stdio: 'pipe' });
    console.log('已生成演示客户端 (合成 PE，仅用于测试加载器)');
  } catch (e) {
    console.log('警告: 无法生成演示客户端: ' + e.message);
  }
}
ensureDemoClient();

server.listen(PORT, '0.0.0.0', () => {
  console.log(`WoWMod Studio -> http://0.0.0.0:${PORT}`);
  console.log(`CLI: ${CLI} (${fs.existsSync(CLI) ? '已构建' : '未构建'})`);
});
