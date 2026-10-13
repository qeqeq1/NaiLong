#!/usr/bin/env node
/**
 * 域名可访问性批量探测
 *
 * 检测策略：
 * - DNS：优先用 223.5.5.5（可 --dns 指定，逗号分隔，最后兜底系统 DNS）。
 * - 连接：解析出 IP 后直连该 IP，但显式设置 Host 头与 TLS SNI 为原域名（即"绑定 host"）。
 * - 请求头：完整浏览器头（User-Agent / Accept / Accept-Language / Referer / Upgrade-Insecure-Requests）。
 * - 重定向：手动跟随，最多 --max-redirects 跳；跳转时带上一跳的 Referer。
 *   若最终落到别的主机名，标记为 REDI（自动跳转到别的站点，通常是学校官网）。
 * - 拦截重试：遇到 403/503 等 4xx/5xx，按计划轮换 UA（桌面 Chrome / iPhone Safari /
 *   安卓 Chrome）与 Referer（自身 / 百度 / Google）重试，最多 --max-attempts 次；
 *   DNS 解析失败直接跳过后续尝试。TLS 证书不受信任时最后会尝试一次忽略证书。
 *
 * 输出：
 * - 默认开启"实时面板"：先把所有域名按固定行号铺出来（等待中 → 检测中转圈），
 *   每个域名出结果后就地更新自己那一行，不新增行、不互相穿插；
 *   并发时也能一眼看出每条的状态。终端不支持 ANSI 时自动退回逐行追加输出。
 *
 * 用法：
 *   node scripts/check-domains.mjs [选项]
 *
 * 选项：
 *   --timeout <ms>        单次请求超时，默认 5000
 *   --slow-timeout <ms>   超时域名的二次确认超时，默认 15000（0 关闭二次确认）
 *   --dns <servers>       DNS 服务器，默认 223.5.5.5（逗号分隔，最后自动兜底系统 DNS）
 *   --max-attempts <n>    单个域名最多尝试的请求组合数，默认 6
 *   --max-redirects <n>   最多跟随跳转次数，默认 5
 *   --concurrency <n>     并发数，默认 1（顺序执行）；>1 时同样实时更新各自那一行
 *   --limit <n>           只检测前 n 条，默认全部
 *   --filter <关键字>     只检测域名或学校包含该关键字的条目
 *   --update              按检测结果回写 public/data/domains.json 的 status 字段
 *                         （可访问/跳转他站/HTTP异常 -> running，无法连接 -> abnormal）
 *   --dry-run             只打印将要改动的条目，不写文件（配合 --update）
 *   --with-meta           回写时附带 checkedAt / checkStatus / checkRedirect 字段
 *   --no-backup           回写前不生成 domains.json.bak
 *   --out <path>          Markdown 报告输出路径，默认写到系统临时目录
 *   --json <path>         额外把结果导出为 JSON
 *   --no-report           不生成 Markdown 报告
 *   --quiet               面板模式下忽略；追加模式下只输出每个域名的结果
 *   --live / --no-live    强制开启 / 关闭实时面板（默认：终端支持 ANSI 时开启）
 *   --color               强制开启彩色（Windows 默认关闭，避免输出 [0m 之类的转义残片）
 *   --no-color            关闭彩色输出
 *   --no-chcp             Windows 下不自动把控制台切到 UTF-8(65001)
 *
 * Windows 中文乱码：脚本会在 Windows 上自动执行 chcp 65001 并默认关闭颜色；
 * 若仍乱码，先在终端执行 `chcp 65001`，或直接打开 --out 生成的 Markdown 报告（UTF-8）。
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import { execSync } from 'node:child_process';
import { fileURLToPath, domainToUnicode, domainToASCII } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA_PATH = process.env.DOMAINS_JSON
  ? path.resolve(process.env.DOMAINS_JSON)
  : path.join(ROOT, 'public', 'data', 'domains.json');

// ---------- 参数解析 ----------
const argv = process.argv.slice(2);
const flags = new Set();
const opts = {};
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith('--')) {
    const key = a.slice(2);
    const next = argv[i + 1];
    if (key.startsWith('no-')) {
      flags.add('no-' + key.slice(3));
    } else if (next !== undefined && !next.startsWith('--')) {
      opts[key] = next;
      i++;
    } else {
      flags.add(key);
    }
  }
}
const num = (key, def) => {
  const v = Number(opts[key]);
  return Number.isFinite(v) && v > 0 ? v : def;
};

const TIMEOUT = num('timeout', 5000);
// 超时二次确认用的长超时（GitHub Pages / 部分 CDN 在国内很慢，5s 容易误判）；0 表示关闭
const SLOW_TIMEOUT = opts['slow-timeout'] !== undefined ? Math.max(0, Number(opts['slow-timeout']) || 0) : 15000;
const MAX_ATTEMPTS = num('max-attempts', 6);
const MAX_REDIRECTS = num('max-redirects', 5);
const CONCURRENCY = Math.max(1, num('concurrency', 1));
const LIMIT = num('limit', Infinity);
const FILTER = opts.filter || '';
const OUT = opts.out || '';
const JSON_OUT = opts.json || '';
const QUIET = flags.has('quiet');
const NO_REPORT = flags.has('no-report');
const UPDATE = flags.has('update');
const DRY_RUN = flags.has('dry-run');
const WITH_META = flags.has('with-meta');
const NO_BACKUP = flags.has('no-backup');
// 检测结果 -> domains.json 的 status
// 这些状态码通常是 WAF / 反爬 / 限流拦截，站点本身是活的，不算失败
const WAF_STATUS = new Set([401, 403, 405, 406, 412, 429, 503]);
const NEXT_STATUS = { ok: 'running', redirect: 'running', waf: 'running', 'http-error': 'running', unreachable: 'abnormal' };
const DNS_SERVERS = String(opts.dns || '223.5.5.5')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const PROTOS = ['https', 'http'];

// ---------- 系统代理 ----------
const parseProxy = (s) => {
  const m = /^(?:https?:\/\/)?([^:/\s]+):(\d{1,5})\/?$/.exec(String(s || '').trim());
  return m ? { host: m[1], port: Number(m[2]) } : null;
};
function detectSystemProxy() {
  const env =
    process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy ||
    process.env.ALL_PROXY || process.env.all_proxy;
  if (env) {
    const p = parseProxy(env);
    if (p) return { ...p, from: '环境变量' };
  }
  if (process.platform === 'win32') {
    try {
      const out = execSync('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"', {
        encoding: 'latin1',
        stdio: ['ignore', 'pipe', 'ignore'],
        shell: process.env.ComSpec || 'cmd.exe',
      });
      const enabled = /ProxyEnable\s+REG_DWORD\s+0x1\b/i.test(out);
      const m = /ProxyServer\s+REG_SZ\s+(.+)/i.exec(out);
      if (enabled && m) {
        const raw = m[1].trim();
        const httpsPart = /https=([^;]+)/i.exec(raw);
        const httpPart = /http=([^;]+)/i.exec(raw);
        const p = parseProxy(httpsPart ? httpsPart[1] : httpPart ? httpPart[1] : raw);
        if (p) return { ...p, from: '系统设置(注册表)' };
      }
    } catch {
      /* 读不到就当作没有代理 */
    }
  }
  return null;
}
const PROXY = flags.has('no-proxy') ? null : opts.proxy ? { ...parseProxy(opts.proxy), from: '--proxy' } : detectSystemProxy();

// ---------- 输出环境 ----------
// Windows 控制台默认代码页是 936(GBK)，Node 输出的 UTF-8 会被解成乱码，先尝试切到 65001
const WIN = process.platform === 'win32';
if (WIN && !flags.has('no-chcp')) {
  try {
    execSync('chcp 65001 > NUL', { stdio: 'ignore', shell: process.env.ComSpec || 'cmd.exe' });
  } catch {
    /* 切代码页失败不影响检测 */
  }
}
// PowerShell 5.1 默认不解析 ANSI，Windows 上默认不输出颜色，避免出现 [0m 残片
const useColor =
  (flags.has('color') || (!WIN && Boolean(process.stdout.isTTY))) &&
  !flags.has('no-color') &&
  !process.env.NO_COLOR;
const C = useColor
  ? { red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m', cyan: '\x1b[36m', dim: '\x1b[2m', off: '\x1b[0m' }
  : { red: '', yellow: '', green: '', cyan: '', dim: '', off: '' };

function write(line) {
  try {
    fs.writeSync(1, line + '\n');
  } catch {
    console.log(line);
  }
}
function writeRaw(s) {
  try {
    fs.writeSync(1, s);
  } catch {
    process.stdout.write(s);
  }
}

// 实时面板需要 ANSI 光标控制；不支持就退回逐行追加
const ANSI_OK =
  Boolean(process.stdout.isTTY) &&
  (!WIN || Boolean(process.env.WT_SESSION) || process.env.TERM_PROGRAM === 'vscode' || process.env.ConEmuANSI === 'ON');
const LIVE = flags.has('live') ? true : flags.has('no-live') ? false : ANSI_OK;

const WIDE = /[\u1100-\u115F\u2E80-\uA4CF\uAC00-\uD7A3\uF900-\uFAFF\uFE30-\uFE6F\uFF00-\uFF60\uFFE0-\uFFE6]/;
const charW = (ch) => (WIDE.test(ch) ? 2 : 1);
function clip(s, max) {
  let w = 0;
  let out = '';
  for (const ch of s) {
    const cw = charW(ch);
    if (w + cw > max - 1) return out + '…';
    out += ch;
    w += cw;
  }
  return out;
}
const termWidth = () => Math.max(60, Math.min(process.stdout.columns || 120, 200));

// ---------- DNS ----------
const resolvers = [];
for (const s of DNS_SERVERS) {
  try {
    const r = new dns.promises.Resolver();
    r.setServers([s]);
    resolvers.push({ name: s, r });
  } catch {
    /* 忽略无效 DNS 地址 */
  }
}
const dnsCache = new Map();

async function resolveHost(hostname) {
  if (dnsCache.has(hostname)) return dnsCache.get(hostname);
  let out = null;
  // DNS 是 UDP，SERVFAIL/丢包时有发生，整轮失败后再试一轮再判死
  for (let round = 0; round < 2 && !out; round++) {
    for (const { name, r } of resolvers) {
      try {
        const addrs = await Promise.race([
          r.resolve4(hostname),
          new Promise((_, rej) => setTimeout(() => rej(new Error('dns timeout')), 3000)),
        ]);
        if (addrs && addrs.length) {
          out = { ip: addrs[0], via: name };
          break;
        }
      } catch {
        /* 换下一个 DNS */
      }
    }
    if (!out) {
      try {
        const addrs = await dns.promises.resolve4(hostname);
        if (addrs && addrs.length) out = { ip: addrs[0], via: 'system' };
      } catch {
        /* 解析失败，进入下一轮 */
      }
    }
  }
  dnsCache.set(hostname, out);
  return out;
}

// ---------- 请求头方案 ----------
const UA_VARIANTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
];
const REF_BAIDU = 'https://www.baidu.com/';
const REF_GOOGLE = 'https://www.google.com/';

const toAscii = (d) => {
  try {
    return domainToASCII(d);
  } catch {
    return d;
  }
};

/** 展示用：把 xn-- 开头的 punycode 域名还原成中文 */
function prettyUrl(u) {
  if (!u) return '';
  try {
    const url = new URL(u);
    const uni = domainToUnicode(url.hostname);
    if (uni === url.hostname) return u;
    // URL.hostname 的 setter 会把中文再编码回 punycode，只能手工拼字符串
    const auth = url.username ? `${url.username}${url.password ? ':' + url.password : ''}@` : '';
    return `${url.protocol}//${auth}${uni}${url.port ? ':' + url.port : ''}${url.pathname}${url.search}${url.hash}`;
  } catch {
    return u;
  }
}

function flattenError(e) {
  const parts = [];
  let cur = e;
  let depth = 0;
  while (cur && depth++ < 4) {
    for (const k of ['name', 'code', 'message']) {
      const v = cur[k];
      if (v !== undefined && v !== null && v !== '') parts.push(String(v));
    }
    cur = cur.cause;
  }
  return parts.join(' | ');
}

function classify(e) {
  const s = flattenError(e);
  if (!s) return '未知错误';
  if (/ENOTFOUND|EAI_AGAIN/.test(s)) return 'DNS 解析失败';
  if (/ECONNREFUSED/.test(s)) return '连接被拒绝';
  if (/ETIMEDOUT|ESOCKETTIMEDOUT|UND_ERR_|TimeoutError|AbortError|aborted|timeout/i.test(s)) return '超时';
  if (/CERT|SSL|TLS|SELF_SIGNED|ERR_TLS/i.test(s)) return '证书错误';
  if (/ECONNRESET|EPIPE|EHOST|ENET|EADDR|EPROTO|fetch failed|socket hang up/i.test(s)) return '网络不可达';
  if (/ELOOP|重定向次数过多/.test(s)) return '重定向次数过多';
  if (/CONNECT|代理/i.test(s)) return '代理不可用';
  return s.slice(0, 60);
}

// ---------- 原始 socket 请求层：完全掌控 Host 头 / SNI / 代理隧道 ----------
function netConnect(host, port, timeout) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port });
    const timer = setTimeout(() => {
      s.destroy();
      reject(Object.assign(new Error('连接超时'), { code: 'ETIMEDOUT' }));
    }, timeout);
    s.once('connect', () => {
      clearTimeout(timer);
      resolve(s);
    });
    s.once('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

function tlsWrap(socket, servername, insecure, timeout) {
  return new Promise((resolve, reject) => {
    const t = tls.connect({ socket, servername, rejectUnauthorized: !insecure });
    const timer = setTimeout(() => {
      t.destroy();
      reject(Object.assign(new Error('TLS 握手超时'), { code: 'ETIMEDOUT' }));
    }, timeout);
    t.once('secureConnect', () => {
      clearTimeout(timer);
      resolve(t);
    });
    t.once('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

/** HTTP 代理的 CONNECT 隧道 */
function proxyTunnel(socket, host, port, timeout) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => {
      reject(Object.assign(new Error('代理 CONNECT 超时'), { code: 'ETIMEDOUT' }));
    }, timeout);
    const onData = (chunk) => {
      buf += chunk.toString('latin1');
      const idx = buf.indexOf('\r\n\r\n');
      if (idx < 0) return;
      clearTimeout(timer);
      socket.removeListener('data', onData);
      const code = Number(buf.split('\r\n')[0].split(' ')[1]);
      if (code === 200) resolve();
      else reject(Object.assign(new Error(`代理 CONNECT 返回 ${code}`), { code: 'EPROXY' }));
    };
    socket.on('data', onData);
    socket.once('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    socket.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
  });
}

/** 自己写请求行并解析响应头（不下载正文） */
function readHeaders(sock, timeout) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => {
      sock.destroy();
      reject(Object.assign(new Error('读取响应超时'), { code: 'ETIMEDOUT' }));
    }, timeout);
    const onData = (chunk) => {
      buf += chunk.toString('latin1');
      const idx = buf.indexOf('\r\n\r\n');
      if (idx < 0) return;
      clearTimeout(timer);
      sock.removeListener('data', onData);
      const lines = buf.slice(0, idx).split('\r\n');
      const status = Number(lines[0].split(' ')[1]);
      const headers = {};
      for (let i = 1; i < lines.length; i++) {
        const m = /^([^:]+):\s*([\s\S]*)$/.exec(lines[i]);
        if (m) headers[m[1].toLowerCase()] = m[2].trim();
      }
      resolve({ status, headers });
    };
    sock.on('data', onData);
    sock.once('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    sock.once('end', () => {
      clearTimeout(timer);
      reject(Object.assign(new Error('连接提前关闭'), { code: 'ECONNRESET' }));
    });
  });
}

// ---------- 单次请求（绑定 host / 自定义 DNS / 完整浏览器头）----------
async function requestOnce(urlStr, { ua, referer, timeout, insecure, proxy }) {
  const u = new URL(urlStr);
  const host = u.hostname;
  const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
  const useTls = u.protocol === 'https:';

  let sock;
  if (proxy) {
    sock = await netConnect(proxy.host, proxy.port, timeout); // 走代理时域名交给代理服务器解析
    if (useTls) await proxyTunnel(sock, host, port, timeout);
  } else {
    const resolved = await resolveHost(host);
    if (!resolved) {
      const e = new Error('DNS 解析失败');
      e.code = 'ENOTFOUND';
      throw e;
    }
    sock = await netConnect(resolved.ip, port, timeout); // 直连解析到的 IP
  }

  const out = useTls ? await tlsWrap(sock, host, insecure, timeout) : sock;
  // 走明文代理时用绝对 URL 形式；其余情况用相对路径
  const reqPath = proxy && !useTls ? urlStr : (u.pathname || '/') + (u.search || '');
  out.write(
    [
      `GET ${reqPath} HTTP/1.1`,
      `Host: ${host}${u.port ? `:${u.port}` : ''}`, // 无论直连还是代理都绑定原域名
      `User-Agent: ${ua}`,
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language: zh-CN,zh;q=0.9,en;q=0.8',
      'Upgrade-Insecure-Requests: 1',
      `Referer: ${referer}`,
      'Connection: close',
      '',
      '',
    ].join('\r\n')
  );
  const res = await readHeaders(out, timeout);
  out.destroy();
  return res;
}

// ---------- 跟随重定向 ----------
async function fetchFollow(startUrl, { ua, referer, timeout, insecure, proxy }) {
  let url = startUrl;
  const chain = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const res = await requestOnce(url, { ua, referer, timeout, insecure, proxy });
    const loc = res.headers && res.headers.location;
    if (res.status >= 300 && res.status < 400 && loc) {
      const prev = url;
      url = new URL(loc, url).href;
      chain.push(prev);
      referer = prev; // 跳转时带上来源页
      continue;
    }
    return { status: res.status, finalUrl: url, chain };
  }
  const e = new Error('重定向次数过多');
  e.code = 'ELOOP';
  throw e;
}

// ---------- 尝试计划 ----------
function buildPlans(host) {
  const self = (proto) => `${proto}://${host}/`;
  const plans = [];
  const seen = new Set();
  const push = (proto, ua, referer, insecure = false) => {
    const k = `${proto}|${ua}|${referer}|${insecure}`;
    if (seen.has(k)) return;
    seen.add(k);
    plans.push({ proto, ua, referer, insecure });
  };
  for (const proto of PROTOS) push(proto, UA_VARIANTS[0], self(proto)); // 1) 标准浏览器头
  push('https', UA_VARIANTS[0], self('https'), true); // 2) 证书不受信任时的兜底（仅证书错误才走）
  for (const ref of [REF_BAIDU, REF_GOOGLE]) for (const proto of PROTOS) push(proto, UA_VARIANTS[0], ref); // 3) 换 Referer
  for (let i = 1; i < UA_VARIANTS.length; i++) {
    // 4) 换 UA
    push('https', UA_VARIANTS[i], self('https'));
    push('http', UA_VARIANTS[i], self('http'));
  }
  return plans;
}

const pickBetter = (a, b) => {
  if (!a) return b;
  if (!b) return a;
  if (a.state === 'unreachable' && b.state !== 'unreachable') return b;
  if (b.insecure && !a.insecure) return b; // 忽略证书那次的结果信息更完整
  return a;
};

/**
 * 一轮尝试：按计划轮换 UA/Referer，必要时做超时二次确认。
 * proxy 为 null 时直连（走 --dns 指定的 DNS），否则通过代理（域名由代理服务器解析）。
 */
async function ladder(host, { proxy, timeout, maxAttempts, slowTimeout }) {
  const plans = buildPlans(host);
  let best = null;
  let attempts = 0;
  let lastErr = null;
  let sawCert = false;

  for (const plan of plans) {
    if (plan.insecure && !sawCert) continue; // 只有出现过证书错误才值得忽略证书重试
    if (attempts >= maxAttempts) break;
    // 网络层连不上（超时/拒绝/不可达）时，换 UA/Referer 没有意义，https+http 各试一次就收工
    if (attempts >= 2 && lastErr && !sawCert) break;
    attempts++;
    let r;
    try {
      r = await fetchFollow(`${plan.proto}://${host}/`, {
        ua: plan.ua,
        referer: plan.referer,
        timeout,
        insecure: plan.insecure,
        proxy,
      });
    } catch (e) {
      const err = classify(e);
      lastErr = err;
      if (err === '证书错误') sawCert = true;
      best = pickBetter(best, {
        state: 'unreachable',
        status: null,
        finalUrl: null,
        chain: [],
        err,
        proto: plan.proto,
        ua: plan.ua,
        referer: plan.referer,
      });
      continue;
    }

    // 走代理时的 502/504 通常是代理连不上目标，而不是站点真的返回了错误
    if (proxy && (r.status === 502 || r.status === 504)) {
      lastErr = '代理网关错误';
      best = pickBetter(best, {
        state: 'unreachable',
        status: null,
        finalUrl: null,
        chain: [],
        err: `代理网关错误(${r.status})`,
        proto: plan.proto,
        ua: plan.ua,
        referer: plan.referer,
      });
      continue;
    }

    let finalHost = host;
    try {
      finalHost = new URL(r.finalUrl).hostname;
    } catch {
      /* 保持原值 */
    }
    // 只加/去掉 www 前缀算同站，不算"跳转到别的站点"
    const bare = (h) => String(h).replace(/^www\./, '');
    const rec = {
      state:
        r.status < 400
          ? bare(finalHost) === bare(host)
            ? 'ok'
            : 'redirect'
          : WAF_STATUS.has(r.status)
            ? 'waf'
            : 'http-error',
      status: r.status,
      finalUrl: r.finalUrl,
      chain: r.chain,
      err: null,
      proto: plan.proto,
      ua: plan.ua,
      referer: plan.referer,
      insecure: plan.insecure,
      note: plan.insecure ? '证书不受信任' : WAF_STATUS.has(r.status) ? `WAF拦截(${r.status})` : null,
    };
    // WAF 拦截视为站点活着，不再继续轮换 UA/Referer
    if (rec.state === 'ok' || rec.state === 'redirect' || rec.state === 'waf') return { ...rec, attempts };
    best = pickBetter(best, rec);
  }

  // 超时二次确认：https/http 都在 timeout 内无响应时，给一次长超时的机会，避免把慢站判成死站
  if (best && best.state === 'unreachable' && best.err === '超时' && slowTimeout > timeout) {
    for (const proto of PROTOS) {
      attempts++;
      try {
        const r = await fetchFollow(`${proto}://${host}/`, {
          ua: UA_VARIANTS[0],
          referer: `${proto}://${host}/`,
          timeout: slowTimeout,
          insecure: sawCert,
          proxy,
        });
        let finalHost = host;
        try {
          finalHost = new URL(r.finalUrl).hostname;
        } catch {
          /* 保持原值 */
        }
        const bare = (h) => String(h).replace(/^www\./, '');
        return {
          state:
            r.status < 400
              ? bare(finalHost) === bare(host)
                ? 'ok'
                : 'redirect'
              : WAF_STATUS.has(r.status)
                ? 'waf'
                : 'http-error',
          status: r.status,
          finalUrl: r.finalUrl,
          chain: r.chain,
          err: null,
          proto,
          ua: UA_VARIANTS[0],
          referer: `${proto}://${host}/`,
          insecure: sawCert,
          note: `慢速确认(${slowTimeout}ms)`,
          attempts,
        };
      } catch (e) {
        const err = classify(e);
        best.err = err;
        if (err !== '超时') break;
      }
    }
  }

  return {
    ...(best || { state: 'unreachable', status: null, finalUrl: null, chain: [], err: '未知错误', proto: null }),
    attempts,
  };
}

/** 直连测一次，若打不开再走系统代理测一次，任意一次能打开即认为可访问 */
async function probeDomain(domain) {
  const host = toAscii(domain);
  const resolved = await resolveHost(host); // 直连用；代理不需要本地解析
  const started = Date.now();

  const direct = await ladder(host, {
    proxy: null,
    timeout: TIMEOUT,
    maxAttempts: MAX_ATTEMPTS,
    slowTimeout: SLOW_TIMEOUT,
  });
  let chosen = direct;
  let viaProxy = false;
  let attempts = direct.attempts || 0;

  if (direct.state !== 'ok' && direct.state !== 'redirect' && PROXY) {
    const proxied = await ladder(host, {
      proxy: PROXY,
      timeout: TIMEOUT,
      maxAttempts: Math.min(MAX_ATTEMPTS, 2),
      slowTimeout: 0, // 代理通常很快，不再做长超时复测，避免死域名拖太久
    });
    attempts += proxied.attempts || 0;
    if (proxied.state === 'ok' || proxied.state === 'redirect' || pickBetter(direct, proxied) === proxied) {
      chosen = proxied;
      viaProxy = true;
    }
  }

  const notes = [chosen.note, viaProxy ? '走系统代理' : null].filter(Boolean);
  return {
    domain,
    ...chosen,
    note: notes.length ? notes.join('/') : null,
    viaProxy,
    attempts,
    ms: Date.now() - started,
    ip: resolved ? resolved.ip : null,
    dns: resolved ? resolved.via : null,
  };
}

// ---------- 读取待检测列表 ----------
if (!fs.existsSync(DATA_PATH)) {
  write(`${C.red}找不到数据文件：${DATA_PATH}${C.off}`);
  process.exit(1);
}
const allRows = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8')); // 回写时基于完整列表，保持顺序
let rows = allRows.slice();
if (FILTER) rows = rows.filter((r) => r.domain.includes(FILTER) || String(r.school || '').includes(FILTER));
if (LIMIT !== Infinity) rows = rows.slice(0, LIMIT);
if (!rows.length) {
  write(`${C.yellow}没有需要检测的条目（filter=${FILTER || '-'}, limit=${LIMIT === Infinity ? '-' : LIMIT}）${C.off}`);
  process.exit(0);
}

const total = rows.length;
const pad = String(total).length;
const t0 = Date.now();
const results = new Array(total);
const counter = { ok: 0, redirect: 0, waf: 0, 'http-error': 0, unreachable: 0 };
let done = 0;

const fmt = (ms) => (ms === null || ms === undefined ? '-' : `${ms}ms`);
const shortUa = (ua) => (!ua ? '' : /iPhone/.test(ua) ? 'iPhone' : /Android/.test(ua) ? 'Android' : 'Chrome');

function resultText(i, r) {
  const idx = String(i + 1).padStart(pad, ' ');
  const head = `[${idx}/${total}]`;
  const tag =
    r.state === 'ok'
      ? `${C.green}OK  ${C.off}`
      : r.state === 'redirect'
        ? `${C.cyan}REDI${C.off}`
        : r.state === 'waf'
          ? `${C.green}WAF ${C.off}`
          : r.state === 'http-error'
            ? `${C.yellow}WARN${C.off}`
            : `${C.red}FAIL${C.off}`;
  const body =
    r.state === 'ok'
      ? `${r.domain}  ${r.proto} ${r.status}  ${fmt(r.ms)}`
      : r.state === 'redirect'
        ? `${r.domain}  ${r.proto} ${r.status}  -> ${prettyUrl(r.finalUrl)}`
        : r.state === 'waf'
          ? `${r.domain}  ${r.proto} ${r.status}  ${fmt(r.ms)}  ${prettyUrl(r.finalUrl)}`
          : r.state === 'http-error'
            ? `${r.domain}  ${r.proto} ${r.status}  ${fmt(r.ms)}  ${prettyUrl(r.finalUrl)}`
            : `${r.domain}  ${r.err}  ${fmt(r.ms)}`;
  const tail = r.attempts > 1 ? `  ${C.dim}重试${r.attempts}次${r.ua ? '/' + shortUa(r.ua) : ''}${C.off}` : '';
  const note = r.note ? `  ${C.dim}(${r.note})${C.off}` : '';
  return `${head} ${tag} ${body}${tail}${note}`;
}

// ---------- 实时面板：固定行号 + 原地更新 ----------
const SPIN = ['|', '/', '-', '\\'];

class Board {
  constructor(items) {
    this.items = items;
    this.states = items.map(() => ({ phase: 'pending', text: '' }));
    this.rendered = 0;
    this.frame = 0;
    this.timer = null;
  }
  mount() {
    for (let i = 0; i < this.items.length; i++) write(this.lineAt(i));
    this.rendered = this.items.length;
    this.timer = setInterval(() => this.tick(), 200);
    this.timer.unref?.();
  }
  lineAt(i) {
    const st = this.states[i];
    const it = this.items[i];
    const idx = String(i + 1).padStart(pad, ' ');
    if (st.phase === 'pending') return clip(`[${idx}/${total}] ${C.dim}…   等待${C.off}  ${it.domain}`, termWidth());
    if (st.phase === 'running')
      return clip(`[${idx}/${total}] ${C.cyan}${SPIN[this.frame % SPIN.length]}   检测中${C.off}  ${it.domain}`, termWidth());
    return clip(st.text, termWidth());
  }
  draw(i) {
    // 光标当前停在面板下方那一行；回到第 i 行改写后再回到底部
    const up = this.rendered - i;
    writeRaw(`\x1b[${up}A\r\x1b[2K${this.lineAt(i)}\x1b[${up}B\r`);
  }
  setRunning(i) {
    this.states[i] = { phase: 'running', text: '' };
    this.draw(i);
  }
  setResult(i, text) {
    this.states[i] = { phase: 'done', text };
    this.draw(i);
  }
  tick() {
    this.frame++;
    for (let i = 0; i < this.states.length; i++) if (this.states[i].phase === 'running') this.draw(i);
  }
  foot(line) {
    // 在面板下方那一行写一行状态（会随光标下移留出空间）
    writeRaw(`\x1b[2K${clip(line, termWidth())}\n`);
  }
  close() {
    if (this.timer) clearInterval(this.timer);
  }
}

const board = LIVE ? new Board(rows) : null;

function onStart(i) {
  if (board) board.setRunning(i);
  else if (!QUIET) write(`-> [${String(i + 1).padStart(pad, ' ')}/${total}] ${C.cyan}检测中${C.off} ${rows[i].domain}`);
}

function onDone(i, r) {
  results[i] = r;
  counter[r.state]++;
  done++;
  const text = resultText(i, r);
  if (board) {
    board.setResult(i, text);
    board.foot(
      `进度 ${done}/${total}   累计 OK:${counter.ok} REDI:${counter.redirect} WAF:${counter.waf} WARN:${counter['http-error']} FAIL:${counter.unreachable}   已用时:${((Date.now() - t0) / 1000).toFixed(1)}s`
    );
  } else {
    write(text);
    write(
      `          ${C.dim}累计 OK:${counter.ok} REDI:${counter.redirect} WAF:${counter.waf} WARN:${counter['http-error']} FAIL:${counter.unreachable} 已用时:${((Date.now() - t0) / 1000).toFixed(1)}s${C.off}`
    );
  }
}

async function runSequential() {
  for (let i = 0; i < total; i++) {
    onStart(i);
    const r = await probeDomain(rows[i].domain);
    onDone(i, r);
  }
}

async function runPool(limit) {
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, total) }, async () => {
    for (;;) {
      const i = cursor++;
      if (i >= total) return;
      onStart(i);
      const r = await probeDomain(rows[i].domain);
      onDone(i, r);
    }
  });
  await Promise.all(workers);
}

/** 失败复核：网络/DNS 偶发抖动会把活站判死，收尾时把这些条目再测一遍 */
async function recheckFailures() {
  const idxs = [];
  for (let i = 0; i < total; i++) if (results[i] && results[i].state === 'unreachable') idxs.push(i);
  if (!idxs.length) return;
  write('');
  write(`${C.cyan}失败复核${C.off} 对 ${idxs.length} 条"无法连接"再测一次…`);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(3, idxs.length) }, async () => {
    for (;;) {
      const k = cursor++;
      if (k >= idxs.length) return;
      const i = idxs[k];
      const r = await probeDomain(rows[i].domain);
      if (r.state !== 'unreachable') {
        counter.unreachable--;
        counter[r.state]++;
        results[i] = { ...r, note: [r.note, '复核转活'].filter(Boolean).join('/') };
        write(`  复核转活 [${i + 1}/${total}] ${r.domain}  ${r.state} ${r.proto} ${r.status}  ${r.note || ''}`);
      }
    }
  });
  await Promise.all(workers);
}

let interrupted = false;
process.on('SIGINT', () => {
  if (interrupted) process.exit(130);
  interrupted = true;
  board?.close();
  write(`\n${C.yellow}收到中断信号，已检测 ${done}/${total}，输出当前汇总…${C.off}`);
  finish().finally(() => process.exit(130));
});

function finish() {
  board?.close();
  const merged = [];
  for (let i = 0; i < total; i++) if (results[i]) merged.push({ ...rows[i], check: results[i] });

  const grouped = { ok: [], redirect: [], waf: [], 'http-error': [], unreachable: [] };
  for (const m of merged) (grouped[m.check.state] || (grouped[m.check.state] = [])).push(m);

  const sec = ((Date.now() - t0) / 1000).toFixed(1);
  write('');
  write('================ 汇总 ================');
  write(`检测时间：${new Date().toISOString()}`);
  write(`条目：${merged.length}/${total}    耗时：${sec}s    并发：${CONCURRENCY}    超时：${TIMEOUT}ms`);
  write(`DNS：${DNS_SERVERS.join(',')}（失败兜底系统 DNS）    最多尝试：${MAX_ATTEMPTS} 次/域名`);
  write(
    `可访问：${grouped.ok.length}    跳转他站：${grouped.redirect.length}    WAF拦截(视为可访问)：${grouped.waf.length}    HTTP异常：${grouped['http-error'].length}    无法连接：${grouped.unreachable.length}`
  );

  write('');
  write('--- 跳转到其他站点（疑似自动跳转学校官网）---');
  for (const m of grouped.redirect) write(`${m.domain}  [${m.school}]  ${m.check.proto} ${m.check.status}  ->  ${prettyUrl(m.check.finalUrl)}`);
  write('');
  write('--- WAF/反爬拦截（站点活着，不算失败）---');
  for (const m of grouped.waf) write(`${m.domain}  [${m.school}]  ${m.check.proto} ${m.check.status}  ${prettyUrl(m.check.finalUrl)}`);
  write('');
  write('--- 无法连接 ---');
  for (const m of grouped.unreachable) write(`${m.domain}  [${m.school}]  数据状态:${m.status}  ->  ${m.check.err}`);
  write('');
  write('--- HTTP 异常 ---');
  for (const m of grouped['http-error'])
    write(`${m.domain}  [${m.school}]  数据状态:${m.status}  ->  ${m.check.proto} ${m.check.status}  ${prettyUrl(m.check.finalUrl) || ''}`);
  write('');
  write('--- 可访问 ---');
  for (const m of grouped.ok) write(`${m.domain}  [${m.school}]  数据状态:${m.status}  ->  ${m.check.proto} ${m.check.status}`);

  if (UPDATE) {
    const byDomain = new Map(merged.map((m) => [m.domain, m]));
    const changes = [];
    let metaTouched = 0;
    for (const row of allRows) {
      const m = byDomain.get(row.domain);
      if (!m) continue; // 本次没检测的条目保持原样
      if (WITH_META) {
        row.checkedAt = new Date().toISOString().slice(0, 10);
        row.checkStatus = m.check.status !== null && m.check.status !== undefined ? m.check.status : m.check.err;
        if (m.check.state === 'redirect') row.checkRedirect = prettyUrl(m.check.finalUrl);
        else delete row.checkRedirect;
        metaTouched++;
      }
      const next = NEXT_STATUS[m.check.state];
      if (next && row.status !== next) {
        changes.push({
          domain: row.domain,
          from: row.status,
          to: next,
          why: m.check.state === 'unreachable' ? m.check.err : `${m.check.state} ${m.check.proto} ${m.check.status}`,
        });
        row.status = next;
      }
    }
    write('');
    write(`--- domains.json 状态变更（${changes.length} 条）---`);
    for (const c of changes) write(`${c.domain}  ${c.from} -> ${c.to}   ${c.why}`);
    if (!changes.length) write('无状态变化');
    if (changes.length || metaTouched) {
      if (DRY_RUN) {
        write(`(dry-run：未写入文件${WITH_META ? `，将附加 ${metaTouched} 条检测元信息` : ''})`);
      } else {
        if (!NO_BACKUP) {
          let bak = `${DATA_PATH}.bak`;
          if (fs.existsSync(bak)) bak = `${DATA_PATH}.${new Date().toISOString().slice(0, 16).replace(/[:-T]/g, '')}.bak`;
          fs.copyFileSync(DATA_PATH, bak);
          write(`已备份原文件：${bak}`);
        }
        // 保持原格式：一行一条记录，仅改动的行产生 diff
        fs.writeFileSync(DATA_PATH, `[\n${allRows.map((r) => JSON.stringify(r)).join(',\n')}\n]\n`, 'utf8');
        write(`已回写：${DATA_PATH}（状态 ${changes.length} 条${WITH_META ? `，元信息 ${metaTouched} 条` : ''}）`);
      }
    }
  }

  if (JSON_OUT) {
    fs.writeFileSync(path.resolve(JSON_OUT), JSON.stringify(merged, null, 2), 'utf8');
    write(`\nJSON 结果：${path.resolve(JSON_OUT)}`);
  }

  if (NO_REPORT || !merged.length) return Promise.resolve();

  const stamp = new Date().toISOString().slice(0, 10);
  const lines = [];
  lines.push('# 域名可访问性检查报告', '');
  lines.push(`- 检查时间：${stamp}`);
  lines.push(`- 检查条目：${merged.length}/${total}`);
  lines.push(`- DNS：${DNS_SERVERS.join(',')}（失败兜底系统 DNS）`);
  lines.push(`- 可访问：${grouped.ok.length}`);
  lines.push(`- 跳转到其他站点：${grouped.redirect.length}`);
  lines.push(`- WAF/反爬拦截（视为可访问）：${grouped.waf.length}`);
  lines.push(`- HTTP 异常（4xx/5xx，已轮换 UA/Referer 重试）：${grouped['http-error'].length}`);
  lines.push(`- 无法连接（DNS/超时/拒绝等）：${grouped.unreachable.length}`);
  lines.push('', '## 跳转到其他站点', '', '| 域名 | 学校 | 数据状态 | 协议 | 状态码 | 最终地址 |', '| --- | --- | --- | --- | --- | --- |');
  for (const m of grouped.redirect)
    lines.push(`| ${m.domain} | ${m.school} | ${m.status} | ${m.check.proto} | ${m.check.status} | ${prettyUrl(m.check.finalUrl)} |`);
  lines.push(
    '',
    '## WAF/反爬拦截（站点活着，状态记 running）',
    '',
    '| 域名 | 学校 | 数据状态 | 协议 | 状态码 | 地址 |',
    '| --- | --- | --- | --- | --- | --- |'
  );
  for (const m of grouped.waf)
    lines.push(
      `| ${m.domain} | ${m.school} | ${m.status} | ${m.check.proto} | ${m.check.status} | ${prettyUrl(m.check.finalUrl) || '-'} |`
    );
  lines.push('', '## 无法连接', '', '| 域名 | 学校 | 数据状态 | 结果 |', '| --- | --- | --- | --- |');
  for (const m of grouped.unreachable) lines.push(`| ${m.domain} | ${m.school} | ${m.status} | ${m.check.err} |`);
  lines.push('', '## HTTP 异常', '', '| 域名 | 学校 | 数据状态 | 协议 | 状态码 | 最终地址 |', '| --- | --- | --- | --- | --- | --- |');
  for (const m of grouped['http-error'])
    lines.push(`| ${m.domain} | ${m.school} | ${m.status} | ${m.check.proto} | ${m.check.status} | ${prettyUrl(m.check.finalUrl) || '-'} |`);
  lines.push('', '## 可访问', '', '| 域名 | 学校 | 数据状态 | 协议 | 状态码 | IP | DNS |', '| --- | --- | --- | --- | --- | --- | --- |');
  for (const m of grouped.ok)
    lines.push(`| ${m.domain} | ${m.school} | ${m.status} | ${m.check.proto} | ${m.check.status} | ${m.check.ip || '-'} | ${m.check.dns || '-'} |`);
  lines.push('');

  const reportPath = OUT ? path.resolve(OUT) : path.join(os.tmpdir(), 'domains-access-report.md');
  fs.writeFileSync(reportPath, lines.join('\n'), 'utf8');
  write(`Markdown 报告：${reportPath}`);
  return Promise.resolve();
}

write(
  `${C.cyan}开始检测${C.off} 共 ${total} 条  超时 ${TIMEOUT}ms(慢站复测 ${SLOW_TIMEOUT}ms)  DNS ${DNS_SERVERS.join(',')}  最多 ${MAX_ATTEMPTS} 次/域名  并发 ${CONCURRENCY}  面板:${LIVE ? '开' : '关(终端不支持 ANSI)'}`
);
write(`代理：${PROXY ? `${PROXY.host}:${PROXY.port}（${PROXY.from}），直连失败后自动再走代理测一次` : '未启用（--proxy host:port 可指定）'}`);
write(`数据源：${DATA_PATH}`);
write('');

board?.mount();
if (CONCURRENCY === 1) await runSequential();
else await runPool(CONCURRENCY);

await recheckFailures();
await finish();
