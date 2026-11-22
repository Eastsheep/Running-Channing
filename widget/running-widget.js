// Variables used by Scriptable.
// These must be at the top of the file. Do not edit.
// icon-color: blue; icon-glyph: running;

// 跑步承廷 · Scriptable 桌面小工具
// 讀取 GitHub Actions 每天同步的 data/widget.enc.json（AES-256-GCM 加密），在手機上解密後顯示。
// 第一次請在 Scriptable App 裡直接執行這個腳本，輸入資料密碼（DATA_PASSWORD）。
// 支援尺寸：小、中、大，以及鎖定畫面（長方形、圓形、單行）。

const DATA_URL = "https://raw.githubusercontent.com/Eastsheep/Running-Channing/main/data/widget.enc.json";
const APP_URL = "https://eastsheep.github.io/Running-Channing/";
const KEY_NAME = "running-channing.widget.key";
const SALT = "running-channing/widget/v1"; // 要和 scripts/sync_garmin.py 的 WIDGET_SALT 一樣
const ITER = 250000;

// ---------- 顏色（跟著系統淺色／深色切換） ----------
const C = {
  bg: Color.dynamic(new Color("#ffffff"), new Color("#151a21")),
  fg: Color.dynamic(new Color("#101828"), new Color("#eef1f5")),
  muted: Color.dynamic(new Color("#5d6676"), new Color("#9aa5b1")),
  grid: Color.dynamic(new Color("#eceff3"), new Color("#252c35")),
  s1: Color.dynamic(new Color("#2a78d6"), new Color("#3987e5")),
  s2: Color.dynamic(new Color("#eb6834"), new Color("#d95926")),
  ok: Color.dynamic(new Color("#16794a"), new Color("#43b874")),
  bad: Color.dynamic(new Color("#c3372c"), new Color("#ec6a5e")),
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
const WD = ["日", "一", "二", "三", "四", "五", "六"];
const fmtPace = s => { const t = Math.round(s); return `${Math.floor(t / 60)}'${String(t % 60).padStart(2, "0")}"`; };
const fmtDur = s => { s = Math.round(s); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return h ? `${h}:${String(m).padStart(2, "0")}:${String(x).padStart(2, "0")}` : `${m}:${String(x).padStart(2, "0")}`; };
const fmtMD = d => `${d.getMonth() + 1}/${d.getDate()}`;
const fmtKm = v => v >= 100 ? v.toFixed(0) : v.toFixed(1);

function stats(data, now = new Date()) {
  const runs = data.runs.map(r => ({ ...r, d: parseDate(r.date) })).sort((a, b) => a.d - b.d);
  const wk = monday(now), elapsed = now - wk;
  const lastWk = new Date(wk.getTime() - 7 * DAY);
  const thisWeek = runs.filter(r => r.d >= wk);
  // 上週同期：上週一到「上週的這個時間點」，比較才公平
  const lastSame = runs.filter(r => r.d >= lastWk && r.d - lastWk <= elapsed);
  const lastFull = runs.filter(r => r.d >= lastWk && r.d < wk);
  const weeks = [];
  for (let i = 7; i >= 0; i--) {
    const a = new Date(wk.getTime() - i * 7 * DAY), b = new Date(a.getTime() + 7 * DAY);
    weeks.push({ t: a, km: sumKm(runs.filter(r => r.d >= a && r.d < b)) });
  }
  const mStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const month = runs.filter(r => r.d >= mStart);
  return {
    weekKm: sumKm(thisWeek), weekN: thisWeek.length,
    delta: sumKm(thisWeek) - sumKm(lastSame), lastWeekKm: sumKm(lastFull),
    avg4: weeks.slice(3, 7).reduce((a, w) => a + w.km, 0) / 4,
    weeks, monthKm: sumKm(month), monthN: month.length,
    last: runs[runs.length - 1], recent: runs.slice(-5).reverse(),
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
function text(stack, str, size, color = C.fg, weight = "regular") {
  const t = stack.addText(str);
  t.font = weight === "bold" ? Font.boldRoundedSystemFont(size) : weight === "semibold" ? Font.semiboldSystemFont(size) : Font.systemFont(size);
  t.textColor = color; t.lineLimit = 1; t.minimumScaleFactor = 0.6;
  return t;
}

// 近 8 週跑量長條圖，最後一根（本週）用藍色，虛線是近 4 週平均
function weekBars(s, w, h) {
  const dc = new DrawContext();
  dc.size = new Size(w, h); dc.opaque = false; dc.respectScreenScale = true;
  const max = Math.max(1, ...s.weeks.map(x => x.km), s.avg4), n = s.weeks.length, gap = 4;
  const bw = (w - gap * (n - 1)) / n;
  s.weeks.forEach((x, i) => {
    const bh = Math.max(2, x.km / max * (h - 2));
    const p = new Path(); p.addRoundedRect(new Rect(i * (bw + gap), h - bh, bw, bh), 2, 2);
    dc.addPath(p); dc.setFillColor(i === n - 1 ? C.s1 : C.grid); dc.fillPath();
  });
  if (s.avg4 > 0) {
    const y = h - s.avg4 / max * (h - 2);
    for (let x = 0; x < w; x += 6) { dc.setFillColor(C.s2); dc.fillRect(new Rect(x, y - 0.5, 3, 1.5)); }
  }
  return dc.getImage();
}

function deltaText(s) {
  if (Math.abs(s.delta) < 0.05) return "和上週同期持平";
  return `比上週同期 ${s.delta > 0 ? "+" : "−"}${Math.abs(s.delta).toFixed(1)} km`;
}

function lastRunBlock(stack, r, big) {
  text(stack, `最近一次 · ${fmtMD(r.d)}（${WD[r.d.getDay()]}）`, 11, C.muted, "semibold");
  stack.addSpacer(2);
  const row = stack.addStack(); row.bottomAlignContent();
  text(row, r.dist.toFixed(2), big ? 26 : 22, C.fg, "bold");
  row.addSpacer(3);
  text(row, "km", 12, C.muted, "semibold");
  stack.addSpacer(2);
  text(stack, `${fmtPace(r.secs / r.dist)}/km · ${fmtDur(r.secs)}`, 12, C.fg);
  if (r.avgHr) text(stack, `平均心率 ${r.avgHr}`, 12, C.muted);
}

function footer(w, s, stale) {
  w.addSpacer();
  const f = w.addStack();
  const when = s.updated ? `${fmtMD(s.updated)} ${String(s.updated.getHours()).padStart(2, "0")}:${String(s.updated.getMinutes()).padStart(2, "0")}` : "";
  text(f, `${stale ? "離線 · " : ""}Garmin 同步 ${when}`, 9, C.muted);
}

function buildSmall(w, s, stale) {
  text(w, "本週跑量", 11, C.muted, "semibold");
  const row = w.addStack(); row.bottomAlignContent();
  text(row, fmtKm(s.weekKm), 30, C.fg, "bold"); row.addSpacer(3); text(row, "km", 12, C.muted, "semibold");
  text(w, `${s.weekN} 次 · ${s.delta >= 0 ? "+" : "−"}${Math.abs(s.delta).toFixed(1)} vs 上週`, 11, s.delta >= 0 ? C.ok : C.muted);
  w.addSpacer(6);
  const img = w.addImage(weekBars(s, 130, 26)); img.imageSize = new Size(130, 26);
  w.addSpacer(6);
  if (s.last) text(w, `${fmtMD(s.last.d)} ${s.last.dist.toFixed(1)} km · ${fmtPace(s.last.secs / s.last.dist)}`, 11, C.fg);
  footer(w, s, stale);
}

function buildMedium(w, s, stale) {
  buildTop(w, s, false);
  footer(w, s, stale);
}

function buildLarge(w, s, stale) {
  buildTop(w, s, true);
  w.addSpacer(10);
  if (s.headline) {
    const h = w.addStack(); h.backgroundColor = C.grid; h.cornerRadius = 10; h.setPadding(8, 10, 8, 10);
    const t = text(h, `教練：${s.headline}`, 12, C.fg); t.lineLimit = 3;
    w.addSpacer(10);
  }
  text(w, "最近跑步", 11, C.muted, "semibold");
  w.addSpacer(4);
  for (const r of s.recent) {
    const row = w.addStack(); row.centerAlignContent();
    text(row, `${fmtMD(r.d)}（${WD[r.d.getDay()]}）`, 12, C.muted).font = Font.monospacedDigitSystemFont(12);
    row.addSpacer(8);
    const t = text(row, r.title, 12, C.fg); t.lineLimit = 1;
    row.addSpacer();
    text(row, `${r.dist.toFixed(1)} km · ${fmtPace(r.secs / r.dist)}`, 12, C.fg, "semibold");
    w.addSpacer(3);
  }
  footer(w, s, stale);
}

// 中、大尺寸共用的上半部：左邊本週跑量和近 8 週長條，右邊最近一次跑步
function buildTop(w, s, big) {
  const top = w.addStack();
  const L = top.addStack(); L.layoutVertically();
  text(L, "本週跑量", 11, C.muted, "semibold");
  const row = L.addStack(); row.bottomAlignContent();
  text(row, fmtKm(s.weekKm), big ? 34 : 32, C.fg, "bold"); row.addSpacer(3); text(row, "km", 13, C.muted, "semibold");
  text(L, `${s.weekN} 次 · ${deltaText(s)}`, 11, s.delta >= 0 ? C.ok : C.muted);
  L.addSpacer(6);
  const bw = big ? 150 : 140, bh = big ? 34 : 30;
  const img = L.addImage(weekBars(s, bw, bh)); img.imageSize = new Size(bw, bh);
  L.addSpacer(3);
  text(L, `近 8 週 · 本月 ${fmtKm(s.monthKm)} km${big ? ` · ${s.monthN} 次` : ""}`, 10, C.muted);
  top.addSpacer();
  const R = top.addStack(); R.layoutVertically();
  if (s.last) lastRunBlock(R, s.last, big);
}

function buildAccessory(w, s, family) {
  if (family === "accessoryInline") {
    text(w, `本週 ${fmtKm(s.weekKm)} km · ${s.weekN} 次`, 12);
  } else if (family === "accessoryCircular") {
    w.addAccessoryWidgetBackground = true;
    const t1 = text(w, fmtKm(s.weekKm), 16, Color.white(), "bold"); t1.centerAlignText();
    const t2 = text(w, "本週km", 9, Color.white()); t2.centerAlignText();
  } else {
    text(w, `本週 ${fmtKm(s.weekKm)} km · ${s.weekN} 次`, 14, Color.white(), "semibold");
    text(w, deltaText(s), 12, Color.white());
    if (s.last) text(w, `${fmtMD(s.last.d)} ${s.last.dist.toFixed(1)} km ${fmtPace(s.last.secs / s.last.dist)}`, 12, Color.white());
  }
}

async function buildWidget(family) {
  const w = new ListWidget();
  w.url = APP_URL;
  w.refreshAfterDate = new Date(Date.now() + 60 * 60 * 1000); // iOS 大約每小時更新一次
  const acc = family && family.startsWith("accessory");
  if (!acc) { w.backgroundColor = C.bg; w.setPadding(14, 14, 12, 14); }
  const { data, stale, error } = await loadData();
  if (error) {
    text(w, "跑步承廷", 13, acc ? Color.white() : C.s1, "bold");
    const t = text(w, error, 11, acc ? Color.white() : C.muted); t.lineLimit = 4;
    return w;
  }
  const s = stats(data);
  if (acc) buildAccessory(w, s, family);
  else if (family === "large") buildLarge(w, s, stale);
  else if (family === "medium") buildMedium(w, s, stale);
  else buildSmall(w, s, stale);
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

async function notify(title, message) {
  const a = new Alert(); a.title = title; a.message = message; a.addAction("好"); await a.present();
  return false;
}

async function menu() {
  const has = Keychain.contains(KEY_NAME);
  const a = new Alert();
  a.title = "跑步承廷小工具";
  a.message = has ? "密碼已設定。長按桌面 → 編輯 → 加入 Scriptable 小工具，Script 選這支。" : "第一次使用，請先設定資料密碼。";
  const opts = has ? ["預覽小", "預覽中", "預覽大", "重新設定密碼", "清除密碼"] : ["設定密碼"];
  opts.forEach(o => a.addAction(o)); a.addCancelAction("關閉");
  const i = await a.present();
  if (i === -1) return;
  const o = opts[i];
  if (o === "設定密碼" || o === "重新設定密碼") { if (await setup()) await (await buildWidget("medium")).presentMedium(); }
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
