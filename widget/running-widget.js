// Variables used by Scriptable.
// These must be at the top of the file. Do not edit.
// icon-color: blue; icon-glyph: running;

// 跑步承廷 · Scriptable 桌面小工具
// 讀取 GitHub Actions 每天同步的 data/widget.enc.json（AES-256-GCM 加密），在手機上解密後顯示。
// 第一次請在 Scriptable App 裡直接執行這個腳本，輸入資料密碼（DATA_PASSWORD）。
// 支援尺寸：小、中、大，以及鎖定畫面（長方形、圓形、單行）。
// 週目標：在桌面小工具的設定裡把 Parameter 填數字（例如 40），或在 App 裡選「設定週目標」；都沒設就用近 4 週平均。

const DATA_URL = "https://raw.githubusercontent.com/Eastsheep/Running-Channing/main/data/widget.enc.json";
const APP_URL = "https://eastsheep.github.io/Running-Channing/";
const KEY_NAME = "running-channing.widget.key";
const SALT = "running-channing/widget/v1"; // 要和 scripts/sync_garmin.py 的 WIDGET_SALT 一樣
const ITER = 250000;
const VERSION = "2026-11-22.5"; // 每次改版就更新，App 選單會顯示，方便確認手機上是不是最新版

const GOAL_NAME = "running-channing.widget.goal";

// ---------- 品牌配色：深藍漸層底、橘色重點、白字（不隨淺色／深色模式改變，像一般運動 App 的小工具） ----------
const C = {
  bgTop: new Color("#0B1426"),
  bgBottom: new Color("#16325C"),
  fg: Color.white(),
  muted: new Color("#ffffff", 0.62),
  faint: new Color("#ffffff", 0.14),
  card: new Color("#ffffff", 0.08),
  accent: new Color("#FF6A2B"),
  accent2: new Color("#FFB347"),
  blue: new Color("#5AB0FF"),
  up: new Color("#3DDC97"),
  down: new Color("#FF8A80"),
};

// =====================================================================
// 純 JavaScript 的 SHA-256 / PBKDF2 / AES-GCM 解密（Scriptable 沒有 WebCrypto）
// =====================================================================
const K256 = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const W = new Int32Array(64);

// 壓縮一個 64 bytes 的區塊；block 是 16 個 32-bit 整數
function compress(st, block) {
  for (let i = 0; i < 16; i++) W[i] = block[i];
  for (let i = 16; i < 64; i++) {
    const a = W[i - 15], b = W[i - 2];
    const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
    const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  let a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K256[i] + W[i]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  st[0] = (st[0] + a) | 0; st[1] = (st[1] + b) | 0; st[2] = (st[2] + c) | 0; st[3] = (st[3] + d) | 0;
  st[4] = (st[4] + e) | 0; st[5] = (st[5] + f) | 0; st[6] = (st[6] + g) | 0; st[7] = (st[7] + h) | 0;
}

function bytesToWords(bytes) {
  const w = new Int32Array(bytes.length >> 2);
  for (let i = 0; i < w.length; i++) w[i] = (bytes[i * 4] << 24) | (bytes[i * 4 + 1] << 16) | (bytes[i * 4 + 2] << 8) | bytes[i * 4 + 3];
  return w;
}

function sha256(bytes) {
  const len = bytes.length, padLen = ((len + 9 + 63) >> 6) << 6;
  const p = new Uint8Array(padLen);
  p.set(bytes); p[len] = 0x80;
  const bits = len * 8;
  p[padLen - 4] = (bits >>> 24) & 255; p[padLen - 3] = (bits >>> 16) & 255; p[padLen - 2] = (bits >>> 8) & 255; p[padLen - 1] = bits & 255;
  p[padLen - 5] = Math.floor(bits / 4294967296) & 255;
  const st = new Int32Array(H0), w = bytesToWords(p);
  for (let i = 0; i < w.length; i += 16) compress(st, w.subarray(i, i + 16));
  return st;
}

function wordsToBytes(w) {
  const b = new Uint8Array(w.length * 4);
  for (let i = 0; i < w.length; i++) { b[i * 4] = w[i] >>> 24; b[i * 4 + 1] = (w[i] >>> 16) & 255; b[i * 4 + 2] = (w[i] >>> 8) & 255; b[i * 4 + 3] = w[i] & 255; }
  return b;
}

// PBKDF2-HMAC-SHA256，輸出 32 bytes。HMAC 的內外層狀態先算好，每次迭代只要壓縮兩個區塊。
function pbkdf2(password, salt, iter) {
  let key = utf8Encode(password);
  if (key.length > 64) key = wordsToBytes(sha256(key));
  const ipad = new Uint8Array(64), opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) { ipad[i] = (key[i] || 0) ^ 0x36; opad[i] = (key[i] || 0) ^ 0x5c; }
  const ist = new Int32Array(H0), ost = new Int32Array(H0);
  compress(ist, bytesToWords(ipad)); compress(ost, bytesToWords(opad));

  // 第一輪：HMAC(salt || INT(1))，salt 長度不固定，直接照一般方式算
  const msg = new Uint8Array(64 + salt.length + 4);
  msg.set(ipad); msg.set(salt, 64); msg[msg.length - 1] = 1;
  const inner = sha256(msg);
  const msg2 = new Uint8Array(96); msg2.set(opad); msg2.set(wordsToBytes(inner), 64);
  const u = sha256(msg2);
  const t = new Int32Array(u);

  // 之後每輪的訊息都是 32 bytes，事先填好補位
  const blk = new Int32Array(16);
  blk[8] = 0x80000000; blk[15] = (64 + 32) * 8;
  const s = new Int32Array(8);
  for (let n = 1; n < iter; n++) {
    blk.set(u, 0); s.set(ist); compress(s, blk);
    blk.set(s, 0); s.set(ost); compress(s, blk);
    for (let i = 0; i < 8; i++) t[i] ^= s[i];
    u.set(s);
  }
  return wordsToBytes(t);
}

// AES-256：只需要加密方向（GCM 是 CTR 模式）
const SBOX = (() => {
  const s = new Uint8Array(256); let p = 1, q = 1;
  do {
    p = p ^ ((p << 1) & 0xff) ^ (p & 0x80 ? 0x1b : 0);
    q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff; if (q & 0x80) q ^= 0x09;
    const x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));
    s[p] = (x ^ 0x63) & 0xff;
  } while (p !== 1);
  s[0] = 0x63; return s;
})();
const xt = b => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff;

function expandKey(key) {
  const w = new Uint8Array(240); w.set(key);
  let rcon = 1;
  for (let i = 32; i < 240; i += 4) {
    let a = w[i - 4], b = w[i - 3], c = w[i - 2], d = w[i - 1];
    if (i % 32 === 0) { const t = a; a = SBOX[b] ^ rcon; b = SBOX[c]; c = SBOX[d]; d = SBOX[t]; rcon = xt(rcon); }
    else if (i % 32 === 16) { a = SBOX[a]; b = SBOX[b]; c = SBOX[c]; d = SBOX[d]; }
    w[i] = w[i - 32] ^ a; w[i + 1] = w[i - 31] ^ b; w[i + 2] = w[i - 30] ^ c; w[i + 3] = w[i - 29] ^ d;
  }
  return w;
}

function aesBlock(w, inp) {
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = inp[i] ^ w[i];
  for (let r = 1; r <= 14; r++) {
    const t = new Uint8Array(16);
    for (let c = 0; c < 4; c++) for (let row = 0; row < 4; row++) t[c * 4 + row] = SBOX[s[((c + row) % 4) * 4 + row]];
    if (r < 14) {
      for (let c = 0; c < 4; c++) {
        const a0 = t[c * 4], a1 = t[c * 4 + 1], a2 = t[c * 4 + 2], a3 = t[c * 4 + 3], x = a0 ^ a1 ^ a2 ^ a3;
        t[c * 4] ^= x ^ xt(a0 ^ a1); t[c * 4 + 1] ^= x ^ xt(a1 ^ a2); t[c * 4 + 2] ^= x ^ xt(a2 ^ a3); t[c * 4 + 3] ^= x ^ xt(a3 ^ a0);
      }
    }
    for (let i = 0; i < 16; i++) s[i] = t[i] ^ w[r * 16 + i];
  }
  return s;
}

// AES-GCM 解密。最後 16 bytes 是驗證標籤，這裡不驗證，改由 JSON 解析成功與否判斷密碼對不對。
function gcmDecrypt(key, iv, data) {
  const w = expandKey(key), ct = data.subarray(0, data.length - 16), out = new Uint8Array(ct.length);
  const ctr = new Uint8Array(16); ctr.set(iv);
  let n = 2;
  for (let off = 0; off < ct.length; off += 16, n++) {
    ctr[12] = n >>> 24; ctr[13] = (n >>> 16) & 255; ctr[14] = (n >>> 8) & 255; ctr[15] = n & 255;
    const ks = aesBlock(w, ctr);
    for (let i = 0; i < 16 && off + i < ct.length; i++) out[off + i] = ct[off + i] ^ ks[i];
  }
  return out;
}

function utf8Encode(str) {
  const out = [];
  for (const ch of str) {
    let c = ch.codePointAt(0);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}

function utf8Decode(b) {
  let s = "";
  for (let i = 0; i < b.length;) {
    const c = b[i++];
    let cp;
    if (c < 0x80) cp = c;
    else if (c < 0xe0) cp = ((c & 31) << 6) | (b[i++] & 63);
    else if (c < 0xf0) cp = ((c & 15) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63);
    else cp = ((c & 7) << 18) | ((b[i++] & 63) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63);
    s += String.fromCodePoint(cp);
  }
  return s;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64decode(str) {
  str = str.replace(/[^A-Za-z0-9+/]/g, "");
  const out = new Uint8Array(Math.floor(str.length * 3 / 4));
  let bits = 0, val = 0, j = 0;
  for (const ch of str) {
    val = (val << 6) | B64.indexOf(ch); bits += 6;
    if (bits >= 8) { bits -= 8; out[j++] = (val >> bits) & 255; }
  }
  return out.subarray(0, j);
}
const toHex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
const fromHex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));

class WrongKey extends Error {}
function decryptBlob(blob, keyBytes) {
  const plain = gcmDecrypt(keyBytes, b64decode(blob.iv), b64decode(blob.ct));
  try { return JSON.parse(utf8Decode(plain)); } // 密碼錯誤時解出來是亂碼，解析會失敗
  catch (e) { throw new WrongKey("密碼不對"); }
}

// =====================================================================
// 資料與統計
// =====================================================================
const DAY = 86400000;
const parseDate = s => { const m = s.match(/(\d+)-(\d+)-(\d+)[ T](\d+):(\d+)/); return new Date(+m[1], m[2] - 1, +m[3], +m[4], +m[5]); };
const startOfDay = d => new Date(d.getFullYear(), d.getMonth(), d.getDate());
const monday = d => { const x = startOfDay(d); x.setDate(x.getDate() - ((x.getDay() + 6) % 7)); return x; };
const sumKm = rs => rs.reduce((a, r) => a + (r.dist || 0), 0);
const sumSec = rs => rs.reduce((a, r) => a + (r.secs || 0), 0);
const WD = ["日", "一", "二", "三", "四", "五", "六"];
const WD_MON = ["一", "二", "三", "四", "五", "六", "日"];
const fmtPace = s => { const t = Math.round(s); return `${Math.floor(t / 60)}'${String(t % 60).padStart(2, "0")}"`; };
const fmtDur = s => { s = Math.round(s); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return h ? `${h}:${String(m).padStart(2, "0")}:${String(x).padStart(2, "0")}` : `${m}:${String(x).padStart(2, "0")}`; };
const fmtHM = s => { const h = Math.floor(s / 3600), m = Math.round(s % 3600 / 60); return h ? `${h}h${String(m).padStart(2, "0")}` : `${m}m`; };
const fmtMD = d => `${d.getMonth() + 1}/${d.getDate()}`;
const fmtKm = v => v >= 100 ? v.toFixed(0) : v.toFixed(1);

// 週目標：桌面小工具的「Parameter」填數字優先，其次是 App 裡設定的，最後用近 4 週平均（取整到 5 km）
function weeklyGoal(avg4) {
  const p = parseFloat(typeof args !== "undefined" && args.widgetParameter);
  if (p > 0) return p;
  if (Keychain.contains(GOAL_NAME)) { const g = parseFloat(Keychain.get(GOAL_NAME)); if (g > 0) return g; }
  return Math.max(10, Math.ceil(avg4 / 5) * 5);
}

function stats(data, now = new Date()) {
  const runs = data.runs.map(r => ({ ...r, d: parseDate(r.date) })).sort((a, b) => a.d - b.d);
  const wk = monday(now), elapsed = now - wk;
  const lastWk = new Date(wk.getTime() - 7 * DAY);
  const thisWeek = runs.filter(r => r.d >= wk);
  // 上週同期：上週一到「上週的這個時間點」，比較才公平
  const lastSame = runs.filter(r => r.d >= lastWk && r.d - lastWk <= elapsed);
  const weeks = [];
  for (let i = 7; i >= 0; i--) {
    const a = new Date(wk.getTime() - i * 7 * DAY), b = new Date(a.getTime() + 7 * DAY);
    weeks.push({ t: a, km: sumKm(runs.filter(r => r.d >= a && r.d < b)) });
  }
  const days = [];
  for (let i = 0; i < 7; i++) {
    const a = new Date(wk.getTime() + i * DAY), b = new Date(a.getTime() + DAY);
    days.push({ km: sumKm(runs.filter(r => r.d >= a && r.d < b)), today: startOfDay(now).getTime() === a.getTime(), future: a > now });
  }
  const mStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const month = runs.filter(r => r.d >= mStart);
  const weekKm = sumKm(thisWeek), lastKm = sumKm(lastSame), weekSec = sumSec(thisWeek);
  const avg4 = weeks.slice(3, 7).reduce((a, w) => a + w.km, 0) / 4;
  const goal = weeklyGoal(avg4);
  return {
    weekKm, weekN: thisWeek.length, weekSec, weekPace: weekKm ? weekSec / weekKm : null,
    delta: weekKm - lastKm, deltaPct: lastKm > 0 ? (weekKm - lastKm) / lastKm : null,
    goal, pct: weekKm / goal, avg4, weeks, days,
    monthKm: sumKm(month), monthN: month.length,
    longest: thisWeek.reduce((m, r) => Math.max(m, r.dist), 0),
    last: runs[runs.length - 1], recent: runs.slice(-4).reverse(),
    headline: data.headline, updated: data.updated ? new Date(data.updated) : null,
  };
}

// =====================================================================
// 讀取（失敗時用上一次的快取）
// =====================================================================
const fm = FileManager.local();
const CACHE = fm.joinPath(fm.cacheDirectory(), "running-channing-widget.json");

async function fetchBlob() {
  const req = new Request(DATA_URL + "?t=" + Math.floor(Date.now() / 600000)); // 每 10 分鐘換一次，避開 CDN 舊快取
  req.timeoutInterval = 15;
  const blob = await req.loadJSON();
  if (!blob || !blob.ct) throw new Error(req.response && req.response.statusCode === 404 ? "還沒有小工具資料檔，請先跑一次同步" : "資料格式不對");
  return blob;
}

async function loadData() {
  if (!Keychain.contains(KEY_NAME)) return { error: "請先在 Scriptable 打開這個腳本，輸入資料密碼" };
  const key = fromHex(Keychain.get(KEY_NAME));
  try {
    const data = decryptBlob(await fetchBlob(), key);
    fm.writeString(CACHE, JSON.stringify(data));
    return { data };
  } catch (e) {
    if (fm.fileExists(CACHE)) return { data: JSON.parse(fm.readString(CACHE)), stale: true };
    return { error: e instanceof WrongKey ? "密碼不對，請在 Scriptable 重新設定" : String(e.message || e) };
  }
}

// =====================================================================
// 畫面
// =====================================================================
const F = {
  hero: s => Font.heavyRoundedSystemFont(s),
  num: s => Font.boldRoundedSystemFont(s),
  semi: s => Font.semiboldRoundedSystemFont(s),
  label: s => Font.mediumSystemFont(s),
  body: s => Font.systemFont(s),
};

function text(stack, str, font, color = C.fg) {
  const t = stack.addText(str);
  t.font = font; t.textColor = color; t.lineLimit = 1; t.minimumScaleFactor = 0.5;
  return t;
}

function newCtx(w, h) {
  const dc = new DrawContext();
  dc.size = new Size(w, h); dc.opaque = false; dc.respectScreenScale = true;
  return dc;
}

// 畫一段圓弧（Scriptable 沒有 arc，用折線近似），兩端補圓頭
function arc(dc, cx, cy, r, from, to, width, color) {
  if (to - from < 0.002) return;
  const p = new Path(), steps = Math.max(8, Math.ceil((to - from) * 120));
  for (let i = 0; i <= steps; i++) {
    const a = (from + (to - from) * i / steps) * 2 * Math.PI - Math.PI / 2;
    const pt = new Point(cx + r * Math.cos(a), cy + r * Math.sin(a));
    if (i === 0) p.move(pt); else p.addLine(pt);
  }
  dc.addPath(p); dc.setStrokeColor(color); dc.setLineWidth(width); dc.strokePath();
  dc.setFillColor(color);
  for (const t of [from, to]) {
    const a = t * 2 * Math.PI - Math.PI / 2;
    dc.fillEllipse(new Rect(cx + r * Math.cos(a) - width / 2, cy + r * Math.sin(a) - width / 2, width, width));
  }
}

// 週目標進度環；lines 是環中央要顯示的文字 [{t, font, color}]
function ringImage(s, size, width, lines) {
  const dc = newCtx(size, size), c = size / 2, r = c - width / 2 - 1;
  arc(dc, c, c, r, 0, 0.9999, width, C.faint);
  arc(dc, c, c, r, 0, Math.min(1, s.pct), width, C.accent);
  if (s.pct > 1) arc(dc, c, c, r, 0, Math.min(1, s.pct - 1), width, C.accent2); // 超過目標的部分疊第二圈
  const total = lines.reduce((a, l) => a + l.h, 0);
  let y = c - total / 2;
  for (const l of lines) {
    dc.setFont(l.font); dc.setTextColor(l.color || C.fg); dc.setTextAlignedCenter();
    dc.drawTextInRect(l.t, new Rect(0, y, size, l.h + 2));
    y += l.h;
  }
  return dc.getImage();
}

// 本週一到日的每日跑量；今天的標籤用橘色
function dayStrip(s, w, h) {
  const dc = newCtx(w, h), n = 7, colW = w / n, labelH = 12, barMax = h - labelH - 3;
  const max = Math.max(1, ...s.days.map(d => d.km));
  s.days.forEach((d, i) => {
    const bw = Math.min(14, colW * 0.5), x = i * colW + (colW - bw) / 2;
    if (d.km > 0) {
      const bh = Math.max(4, d.km / max * barMax);
      const p = new Path(); p.addRoundedRect(new Rect(x, barMax - bh, bw, bh), bw / 2.5, bw / 2.5);
      dc.addPath(p); dc.setFillColor(C.accent); dc.fillPath();
    } else {
      dc.setFillColor(d.future ? new Color("#ffffff", 0.08) : C.faint);
      dc.fillEllipse(new Rect(i * colW + colW / 2 - 2, barMax - 4, 4, 4));
    }
    dc.setFont(d.today ? F.semi(9) : F.label(9)); dc.setTextColor(d.today ? C.accent : C.muted); dc.setTextAlignedCenter();
    dc.drawTextInRect(WD_MON[i], new Rect(i * colW, barMax + 2, colW, labelH));
  });
  return dc.getImage();
}

// 近 8 週跑量：本週橘色，其他白色半透明，虛線是週目標
function weekChart(s, w, h) {
  const dc = newCtx(w, h), labelH = 12, top = 4, ch = h - labelH - top - 2, n = s.weeks.length;
  const max = Math.max(1, ...s.weeks.map(x => x.km), s.goal) * 1.08, colW = w / n, bw = Math.min(18, colW * 0.55);
  const y = v => top + ch - v / max * ch;
  for (let x = 0; x < w; x += 7) { dc.setFillColor(new Color("#ffffff", 0.35)); dc.fillRect(new Rect(x, y(s.goal) - 0.5, 4, 1)); }
  s.weeks.forEach((wk, i) => {
    const x = i * colW + (colW - bw) / 2, bh = Math.max(3, wk.km / max * ch);
    const p = new Path(); p.addRoundedRect(new Rect(x, top + ch - bh, bw, bh), 4, 4);
    dc.addPath(p); dc.setFillColor(i === n - 1 ? C.accent : new Color("#ffffff", 0.28)); dc.fillPath();
    if (i === n - 1 || i === 0) {
      dc.setFont(F.label(9)); dc.setTextColor(i === n - 1 ? C.accent : C.muted); dc.setTextAlignedCenter();
      dc.drawTextInRect(i === n - 1 ? "本週" : fmtMD(wk.t), new Rect(i * colW - 6, h - labelH, colW + 12, labelH));
    }
  });
  return dc.getImage();
}

function header(w, right) {
  const h = w.addStack(); h.centerAlignContent();
  const sym = SFSymbol.named("figure.run"); sym.applyFont(Font.boldSystemFont(11));
  const img = h.addImage(sym.image); img.imageSize = new Size(13, 13); img.tintColor = C.accent;
  h.addSpacer(4);
  text(h, "跑步承廷", F.semi(11), C.fg);
  h.addSpacer();
  if (right) text(h, right, F.label(10), C.muted);
  return h;
}

function pill(stack, s, size = 10) {
  if (s.deltaPct == null && Math.abs(s.delta) < 0.05) return;
  const up = s.delta >= 0, p = stack.addStack();
  p.backgroundColor = new Color(up ? "#3DDC97" : "#FF8A80", 0.18); p.cornerRadius = 7; p.setPadding(2, 6, 2, 6);
  const v = s.deltaPct != null ? `${Math.round(Math.abs(s.deltaPct) * 100)}%` : `${Math.abs(s.delta).toFixed(1)} km`;
  text(p, `${up ? "▲" : "▼"} ${v}`, F.semi(size), up ? C.up : C.down);
}

function tile(stack, label, value, unit, width) {
  const t = stack.addStack(); t.layoutVertically();
  if (width) t.size = new Size(width, 0); // 固定欄寬，兩列的數字才會對齊
  text(t, label, F.label(9), C.muted);
  t.addSpacer(1);
  const r = t.addStack(); r.bottomAlignContent();
  text(r, value, F.num(15), C.fg);
  if (unit) { r.addSpacer(2); text(r, unit, F.label(9), C.muted); }
  return t;
}

// 各機型的小工具寬度（pt）。圖片是固定像素，太寬會把版面擠歪，所以依手機算出內容可用寬度。
const PAD = 14;
function widgetWidth(family) {
  const sz = Device.screenSize(), W = Math.min(sz.width, sz.height), H = Math.max(sz.width, sz.height);
  const table = [ // [螢幕寬, 螢幕高, 小, 中/大寬]
    [430, 932, 170, 364], [428, 926, 170, 364], [440, 956, 170, 364], [414, 896, 169, 360], [402, 874, 164, 348],
    [414, 736, 159, 348], [393, 852, 158, 338], [390, 844, 158, 338], [375, 812, 155, 329], [375, 667, 148, 321], [320, 568, 141, 292],
  ];
  const hit = table.find(t => t[0] === W && t[1] === H) || table.find(t => t[0] === W);
  const small = hit ? hit[2] : Math.round(W * 0.4), wide = hit ? hit[3] : Math.round(W * 0.86);
  return family === "small" ? small : wide;
}
const innerWidth = family => widgetWidth(family) - PAD * 2;

function buildSmall(w, s) {
  header(w, "本週");
  w.addSpacer(8);
  const row = w.addStack(); row.centerAlignContent();
  row.addSpacer();
  const rs = innerWidth("small") < 136 ? 56 : 62;
  const ring = row.addImage(ringImage(s, rs, 7, [{ t: `${Math.round(s.pct * 100)}%`, font: F.num(13), h: 16 }]));
  ring.imageSize = new Size(rs, rs);
  row.addSpacer(8);
  const col = row.addStack(); col.layoutVertically();
  text(col, fmtKm(s.weekKm), F.hero(28), C.fg);
  text(col, `/ ${fmtKm(s.goal)} km`, F.label(10), C.muted);
  row.addSpacer();
  w.addSpacer();
  const sr = w.addStack(); sr.addSpacer();
  const sw = innerWidth("small");
  const strip = sr.addImage(dayStrip(s, sw, 30)); strip.imageSize = new Size(sw, 30);
  sr.addSpacer();
  w.addSpacer(5);
  // 底列左右內縮到和每日長條的第一、最後一根對齊，不要貼著邊
  const inset = Math.max(4, Math.round(sw / 14) - 4);
  const f = w.addStack(); f.centerAlignContent(); f.setPadding(0, inset, 0, inset);
  text(f, `${s.weekN} 次`, F.semi(10), C.fg);
  f.addSpacer();
  pill(f, s, 9);
}

function buildMedium(w, s) {
  const row = w.addStack(); row.centerAlignContent();
  const iw = innerWidth("medium"), rs = Math.min(122, Math.round(iw * 0.37)), rw = iw - rs - 14;
  const ring = row.addImage(ringImage(s, rs, 11, [
    { t: fmtKm(s.weekKm), font: F.hero(30), h: 34 },
    { t: `/ ${fmtKm(s.goal)} km`, font: F.label(10), color: C.muted, h: 13 },
    { t: `${Math.round(s.pct * 100)}%`, font: F.semi(10), color: C.accent, h: 14 },
  ]));
  ring.imageSize = new Size(rs, rs);
  row.addSpacer(14);
  const R = row.addStack(); R.layoutVertically();
  const h = header(R, null); pill(h, s, 9);
  R.addSpacer(8);
  const g1 = R.addStack();
  tile(g1, "跑步次數", String(s.weekN), "次", Math.floor(rw * 0.47)); g1.addSpacer();
  tile(g1, "平均配速", s.weekPace ? fmtPace(s.weekPace) : "—", "/km", Math.floor(rw * 0.47));
  R.addSpacer(6);
  const g2 = R.addStack();
  tile(g2, "本週時間", s.weekSec ? fmtHM(s.weekSec) : "—", null, Math.floor(rw * 0.47)); g2.addSpacer();
  tile(g2, "本月跑量", fmtKm(s.monthKm), "km", Math.floor(rw * 0.47));
  R.addSpacer();
  const sr = R.addStack(); sr.addSpacer();
  const strip = sr.addImage(dayStrip(s, rw, 28)); strip.imageSize = new Size(rw, 28);
  sr.addSpacer();
}

function buildLarge(w, s) {
  const now = new Date();
  header(w, `${fmtMD(now)}（${WD[now.getDay()]}）`);
  w.addSpacer(10);
  const hero = w.addStack(); hero.centerAlignContent();
  const ring = hero.addImage(ringImage(s, 96, 10, [
    { t: `${Math.round(s.pct * 100)}%`, font: F.num(20), h: 24 },
    { t: "週目標", font: F.label(9), color: C.muted, h: 12 },
  ]));
  ring.imageSize = new Size(96, 96);
  hero.addSpacer(16);
  const hc = hero.addStack(); hc.layoutVertically();
  text(hc, "本週跑量", F.label(10), C.muted);
  const kr = hc.addStack(); kr.bottomAlignContent();
  text(kr, fmtKm(s.weekKm), F.hero(38), C.fg); kr.addSpacer(3); text(kr, `/ ${fmtKm(s.goal)} km`, F.label(11), C.muted);
  const pr = hc.addStack(); pr.centerAlignContent();
  pill(pr, s, 10); pr.addSpacer(6); text(pr, "比上週同期", F.label(10), C.muted);
  if (s.headline) { hc.addSpacer(4); const t = text(hc, s.headline, F.body(10), C.muted); t.lineLimit = 2; }
  w.addSpacer(12);
  const tiles = w.addStack();
  tile(tiles, "次數", String(s.weekN), "次"); tiles.addSpacer();
  tile(tiles, "平均配速", s.weekPace ? fmtPace(s.weekPace) : "—", "/km"); tiles.addSpacer();
  tile(tiles, "時間", s.weekSec ? fmtHM(s.weekSec) : "—"); tiles.addSpacer();
  tile(tiles, "最長", s.longest ? s.longest.toFixed(1) : "—", "km");
  w.addSpacer(12);
  const chart = w.addStack(); chart.layoutVertically(); chart.backgroundColor = C.card; chart.cornerRadius = 14; chart.setPadding(10, 12, 8, 12);
  const ct = chart.addStack(); text(ct, "近 8 週跑量", F.semi(10), C.fg); ct.addSpacer(); text(ct, `本月 ${fmtKm(s.monthKm)} km`, F.label(10), C.muted);
  chart.addSpacer(6);
  const cw = innerWidth("large") - 24;
  const ci = chart.addImage(weekChart(s, cw, 58)); ci.imageSize = new Size(cw, 58);
  w.addSpacer(8);
  if (s.last) {
    const r = s.last, card = w.addStack(); card.backgroundColor = C.card; card.cornerRadius = 14; card.setPadding(9, 12, 9, 12); card.centerAlignContent();
    const l = card.addStack(); l.layoutVertically();
    text(l, `最近一次 · ${fmtMD(r.d)}（${WD[r.d.getDay()]}）`, F.label(9), C.muted);
    const tt = text(l, r.title, F.semi(12), C.fg); tt.lineLimit = 1;
    card.addSpacer();
    tile(card, "距離", r.dist.toFixed(2), "km"); card.addSpacer(10);
    tile(card, "配速", fmtPace(r.secs / r.dist));
    if (r.avgHr) { card.addSpacer(10); tile(card, "心率", String(r.avgHr)); }
  }
}

function buildAccessory(w, s, family) {
  if (family === "accessoryInline") {
    text(w, `本週 ${fmtKm(s.weekKm)}/${fmtKm(s.goal)} km`, F.semi(12), C.fg);
  } else if (family === "accessoryCircular") {
    const img = w.addImage(ringImage(s, 60, 6, [
      { t: fmtKm(s.weekKm), font: F.num(15), color: Color.white(), h: 17 },
      { t: "km", font: F.label(8), color: Color.white(), h: 10 },
    ]));
    img.imageSize = new Size(60, 60);
  } else {
    text(w, `本週 ${fmtKm(s.weekKm)} / ${fmtKm(s.goal)} km`, F.num(14), Color.white());
    text(w, `${s.weekN} 次 · 完成 ${Math.round(s.pct * 100)}%`, F.label(12), Color.white());
    if (s.last) text(w, `最近 ${fmtMD(s.last.d)} ${s.last.dist.toFixed(1)} km ${fmtPace(s.last.secs / s.last.dist)}`, F.label(12), Color.white());
  }
}

function background(w) {
  const g = new LinearGradient();
  g.colors = [C.bgTop, C.bgBottom]; g.locations = [0, 1];
  g.startPoint = new Point(0, 0); g.endPoint = new Point(1, 1);
  w.backgroundGradient = g;
}

async function buildWidget(family) {
  const w = new ListWidget();
  w.url = APP_URL;
  w.refreshAfterDate = new Date(Date.now() + 60 * 60 * 1000); // iOS 大約每小時更新一次
  const acc = family && family.startsWith("accessory");
  if (!acc) { background(w); w.setPadding(PAD, PAD, PAD, PAD); }
  const { data, stale, error } = await loadData();
  if (error) {
    if (!acc) header(w, null);
    w.addSpacer(6);
    const t = text(w, error, F.label(11), acc ? Color.white() : C.muted); t.lineLimit = 4;
    if (!acc) w.addSpacer();
    return w;
  }
  const s = stats(data);
  if (acc) buildAccessory(w, s, family);
  else if (family === "large") buildLarge(w, s);
  else if (family === "medium") buildMedium(w, s);
  else buildSmall(w, s);
  if (stale && !acc) { w.addSpacer(2); text(w, "離線 · 顯示上次的資料", F.label(8), C.muted); }
  return w;
}

// =====================================================================
// 在 App 裡執行：設定密碼、預覽
// =====================================================================
// 推導金鑰：先用 WebView 的 WebCrypto（快），不行再用純 JS（iPhone 上約十幾秒）
async function deriveKey(password) {
  try {
    const wv = new WebView();
    await wv.loadHTML("<html></html>", "https://localhost/");
    const hex = await wv.evaluateJavaScript(`
      (async () => {
        const enc = new TextEncoder();
        const k = await crypto.subtle.importKey("raw", enc.encode(${JSON.stringify(password)}), "PBKDF2", false, ["deriveBits"]);
        const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(${JSON.stringify(SALT)}), iterations: ${ITER} }, k, 256);
        completion(Array.from(new Uint8Array(bits), x => x.toString(16).padStart(2, "0")).join(""));
      })().catch(() => completion(""));
    `, true);
    if (/^[0-9a-f]{64}$/.test(hex)) return fromHex(hex);
  } catch (e) { /* 改用純 JS */ }
  return pbkdf2(password, utf8Encode(SALT), ITER);
}

async function setup() {
  const a = new Alert();
  a.title = "輸入資料密碼";
  a.message = "就是 GitHub Secret 裡的 DATA_PASSWORD，和打開看板時輸入的密碼相同。密碼只用來在這支手機推導金鑰，金鑰存在 iOS 鑰匙圈。";
  a.addSecureTextField("DATA_PASSWORD", "");
  a.addAction("確定"); a.addCancelAction("取消");
  if (await a.present() === -1) return false;
  const pw = a.textFieldValue(0);
  if (!pw) return false;
  const key = await deriveKey(pw);
  let blob;
  try { blob = await fetchBlob(); } catch (e) { return notify("讀不到資料", String(e.message || e)); }
  try { decryptBlob(blob, key); } catch (e) { return notify("密碼不對", "解不開資料，請再試一次。"); }
  Keychain.set(KEY_NAME, toHex(key));
  return true;
}

// 從 GitHub 下載最新版覆蓋這支腳本本身
async function selfUpdate() {
  try {
    const url = "https://raw.githubusercontent.com/Eastsheep/Running-Channing/main/widget/running-widget.js?t=" + Date.now();
    const code = await new Request(url).loadString();
    if (!code.includes("buildWidget")) throw new Error("下載的內容不對");
    FileManager.local().writeString(module.filename, code);
    await notify("已更新", "關掉後再點一次這支腳本，就是最新版。");
  } catch (e) { await notify("更新失敗", String(e.message || e)); }
}

async function setGoal() {
  const a = new Alert();
  a.title = "每週跑量目標（km）";
  a.message = "留白就用近 4 週平均。每個小工具也可以在 Parameter 欄位填數字，覆蓋這個設定。";
  a.addTextField("例如 40", Keychain.contains(GOAL_NAME) ? Keychain.get(GOAL_NAME) : "");
  a.addAction("儲存"); a.addCancelAction("取消");
  if (await a.present() === -1) return;
  const v = parseFloat(a.textFieldValue(0));
  if (v > 0) Keychain.set(GOAL_NAME, String(v)); else if (Keychain.contains(GOAL_NAME)) Keychain.remove(GOAL_NAME);
}

async function notify(title, message) {
  const a = new Alert(); a.title = title; a.message = message; a.addAction("好"); await a.present();
  return false;
}

async function menu() {
  const has = Keychain.contains(KEY_NAME);
  const a = new Alert();
  a.title = `跑步承廷小工具 · 版本 ${VERSION}`;
  a.message = has ? "密碼已設定。長按桌面 → 編輯 → 加入 Scriptable 小工具，Script 選這支。" : "第一次使用，請先設定資料密碼。";
  const opts = has ? ["預覽小", "預覽中", "預覽大", "設定週目標", "更新到最新版", "重新設定密碼", "清除密碼"] : ["設定密碼"];
  opts.forEach(o => a.addAction(o)); a.addCancelAction("關閉");
  const i = await a.present();
  if (i === -1) return;
  const o = opts[i];
  if (o === "設定密碼" || o === "重新設定密碼") { if (await setup()) await (await buildWidget("medium")).presentMedium(); }
  else if (o === "更新到最新版") await selfUpdate();
  else if (o === "設定週目標") { await setGoal(); await (await buildWidget("medium")).presentMedium(); }
  else if (o === "清除密碼") { Keychain.remove(KEY_NAME); if (fm.fileExists(CACHE)) fm.remove(CACHE); }
  else {
    const fam = { "預覽小": "small", "預覽中": "medium", "預覽大": "large" }[o];
    const w = await buildWidget(fam);
    if (fam === "small") await w.presentSmall(); else if (fam === "large") await w.presentLarge(); else await w.presentMedium();
  }
}

if (config.runsInWidget) {
  Script.setWidget(await buildWidget(config.widgetFamily));
  Script.complete();
} else {
  await menu();
  Script.complete();
}
