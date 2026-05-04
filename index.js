 "use strict";
process.env.UV_THREADPOOL_SIZE = "128";
process.env.NODE_NO_WARNINGS = "1";
try { require("v8").setFlagsFromString("--always-turbofan --no-lazy --max-semi-space-size=256 --max-old-space-size=4096 --turbo-fast-api-calls"); } catch {}

Buffer.poolSize = 32768;

const net = require("net");
const tls = require("tls");
const http2 = require("http2");
const fs = require("fs");
const dns = require("dns");
const _path = require("path");
function _resolveModule(name) {
    const sib = _path.join(__dirname, name);
    const nm = _path.join(__dirname, "node_modules", name);
    if (fs.existsSync(_path.join(sib, "index.js")) || fs.existsSync(_path.join(sib, "package.json"))) return sib;
    if (fs.existsSync(_path.join(nm, "index.js")) || fs.existsSync(_path.join(nm, "package.json"))) return nm;
    return null;
}
function _ensureModule(name) {
    let p = _resolveModule(name);
    if (!p) {
        console.log(`[!] ${name} bulunamadı, yükleniyor...`);
        try { require("child_process").execSync(`npm install ${name}`, { cwd: __dirname, stdio: "inherit" }); } catch (_e) {}
        p = _resolveModule(name);
    }
    if (!p) { console.log(`[!] ${name} yüklenemedi. Kapatılıyor.`); process.exit(1); }
    const _saved = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    try { return require(p); }
    finally { if (_saved !== undefined) process.env.NODE_TLS_REJECT_UNAUTHORIZED = _saved; }
}
const WebSocket = _ensureModule("ws");
const initMFA = _ensureModule("ozturk-mfa");
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const NOOP = () => {};
process.on("warning", NOOP);

dns.setDefaultResultOrder("ipv4first");
dns.setServers(["1.1.1.1", "1.0.0.1", "162.159.36.1", "162.159.46.1"]);
try { net.setDefaultAutoSelectFamily(false); } catch {}
try {
    require("os").setPriority(process.pid, -20);
    if (process.platform === "win32")
        require("child_process").execSync(`powershell "Get-Process -Id ${process.pid} | ForEach-Object { $_.PriorityClass='RealTime' }"`, { stdio: "ignore" });
} catch {}

const config = (() => {
    try { return JSON.parse(fs.readFileSync(__dirname + "/config.json", "utf8")); }
    catch (e) { console.error("[FATAL] config.json load failed:", e.message); process.exit(1); }
})();

const API_HOST = "canary.discord.com";
const API_ENDPOINT = "https://canary.discord.com";
const GW_URL = "wss://gateway-us-east1-b.discord.gg/?v=10&encoding=json";

let _resolvedIPs = [];
let _ipIdx = 0;
function resolveHost() {
    dns.resolve4(API_HOST, (err, addrs) => {
        if (!err && addrs?.length) _resolvedIPs = addrs;
    });
}
resolveHost();
setInterval(resolveHost, 30000);

const B_OP10 = Buffer.from('"op":10');
const B_D_OPEN = Buffer.from('"d":{');
const B_ID = Buffer.from('"id":"');
const B_VUC_KEY = Buffer.from('"vanity_url_code":');
const B_HBI = Buffer.from('"heartbeat_interval":');
const B_OP_KEY = Buffer.from('"op":');

const _lenCache = new Array(64);
for (let i = 0; i < 64; i++) _lenCache[i] = Buffer.from(String(i));

class Kingdom {
    constructor() {
        this.token = config.token;
        this.guildId = config.guildId;
        this.mfaToken = null;
        this.targetVanity = null;
        this._targetBuf = null;
        this.vanityCode = null;
        this.fired = false;
        this.connectionPoolSize = config.maxSockets;
        this.h2PoolSize = config.h2PoolSize;
        this.tlsConns = new Array(config.maxSockets);
        this.tlsCount = 0;
        this.tlsSess = null;
        this.h2Clients = new Array(config.h2PoolSize);
        this.guilds = new Map();
        this._vanityBufs = new Map();
        this.ws = null;
        this.hbInterval = null;
        this._lastMfa = null;
        this._mfaBuf = null;
        this._fH1 = new Array(config.maxSockets);
        this._h1c = 0;
        this._afterFire = this._handleResponses.bind(this);
        this._resetFired = () => { this.fired = false; };
        this._targetIdBuf = Buffer.from('"id":"' + this.guildId + '"');
        this._kaReq = Buffer.from("GET /api/v9/gateway HTTP/1.1\r\nHost: canary.discord.com\r\nConnection: keep-alive\r\n\r\n");

        this._staticHdr = null;
        this._staticHdrMfa = null;
        this._sep = Buffer.from("\r\n\r\n");
        this._bd1 = Buffer.from('{"code":"');
        this._bd2 = Buffer.from('"}');
        this._mfaHdr = Buffer.from("X-Discord-MFA-Authorization: ");
        this._crlf = Buffer.from("\r\n");
        this._baseHdr = Buffer.concat([
            Buffer.from("PATCH /api/v9/guilds/"),
            Buffer.from(this.guildId),
            Buffer.from("/vanity-url HTTP/1.1\r\nHost: canary.discord.com\r\nAuthorization: "),
            Buffer.from(this.token),
            Buffer.from("\r\n"),
            Buffer.from(
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0\r\n" +
                "X-Super-Properties: eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU1NjI0fQ==\r\n" +
                "Content-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: "
            )
        ]);
        this._rebuildStaticHeaders();

        this._hbBuf = Buffer.from('{"op":1,"d":null}');
        this._wsAuthBuf = Buffer.from(JSON.stringify({
            op: 2, d: { token: this.token, intents: 1, properties: { os: "Windows", browser: "Firefox", device: "" }, large_threshold: 50 }
        }));
        this._wsMsgHandler = data => this._handleWsMsg(data);
        this._wsOpts = { perMessageDeflate: false, skipUTF8Validation: true, handshakeTimeout: 3000, maxPayload: 268435456 };
        this._tlsTemplate = {
            servername: API_HOST,
            ALPNProtocols: ["http/1.1"],
            rejectUnauthorized: false,
            minVersion: "TLSv1.3",
            maxVersion: "TLSv1.3",
            ciphers: "TLS_AES_128_GCM_SHA256",
            ecdhCurve: "X25519",
            requestOCSP: false,
            checkServerIdentity: NOOP,
            socket: null,
            session: null
        };
        this._h2BaseHeaders = {
            ":method": "PATCH",
            ":path": `/api/v9/guilds/${this.guildId}/vanity-url`,
            "authorization": this.token,
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "x-super-properties": "eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU1NjI0fQ==",
            "content-type": "application/json"
        };
        this._h2Headers = this._h2BaseHeaders;
        this._h2HeadersMfa = null;
        this._h2Priority = { priority: { weight: 255, exclusive: true } };
        this._h2Opts = {
            settings: { enablePush: false, initialWindowSize: 4194304, maxFrameSize: 131072 },
            maxSessionMemory: 512,
            rejectUnauthorized: false,
            minVersion: "TLSv1.3",
            maxVersion: "TLSv1.3",
            highWaterMark: 65536,
            keepAlive: true,
            keepAliveInitialDelay: 0,
            ALPNProtocols: ["h2"],
            ciphers: "TLS_AES_128_GCM_SHA256",
            ecdhCurve: "X25519",
            requestOCSP: false,
            checkServerIdentity: NOOP
        };
    }

    _rebuildStaticHeaders() {
        this._staticHdr = this._baseHdr;
        if (this._mfaBuf) {
            this._staticHdrMfa = Buffer.concat([
                Buffer.from("PATCH /api/v9/guilds/"),
                Buffer.from(this.guildId),
                Buffer.from("/vanity-url HTTP/1.1\r\nHost: canary.discord.com\r\nAuthorization: "),
                Buffer.from(this.token),
                this._crlf,
                this._mfaHdr,
                this._mfaBuf,
                this._crlf,
                Buffer.from(
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0\r\n" +
                    "X-Super-Properties: eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU1NjI0fQ==\r\n" +
                    "Content-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: "
                )
            ]);
        } else {
            this._staticHdrMfa = null;
        }
        if (this.mfaToken) {
            this._h2HeadersMfa = { ...this._h2BaseHeaders, "x-discord-mfa-authorization": this.mfaToken };
        } else {
            this._h2HeadersMfa = null;
        }
    }

    _extractId(buf, from) {
        const idx = buf.indexOf(B_ID, from);
        if (idx === -1) return null;
        const s = idx + 6;
        let e = s;
        while (e < buf.length && buf[e] !== 34) e++;
        return buf.toString("latin1", s, e);
    }

    _extractVanity(buf, from) {
        const idx = buf.indexOf(B_VUC_KEY, from);
        if (idx === -1) return undefined;
        const v = buf[idx + 18];
        if (v === 110) return null;
        if (v !== 34) return undefined;
        const s = idx + 19;
        let e = s;
        while (e < buf.length && buf[e] !== 34) e++;
        if (e === s) return null;
        return buf.toString("latin1", s, e);
    }

    _buildRaw(code) {
        const hdr = this._mfaBuf ? this._staticHdrMfa : this._staticHdr;
        const bodyLen = this._bd1.length + code.length + this._bd2.length;
        const bLen = bodyLen < 64 ? _lenCache[bodyLen] : Buffer.from(String(bodyLen));
        const cap = hdr.length + bLen.length + this._sep.length + bodyLen;
        const out = Buffer.allocUnsafe(cap);
        let o = 0;
        o += hdr.copy(out, o);
        o += bLen.copy(out, o);
        o += this._sep.copy(out, o);
        o += this._bd1.copy(out, o);
        out.write(code, o, "latin1");
        o += code.length;
        this._bd2.copy(out, o);
        return out;
    }

    preWarmAll() {
        this._vanityBufs.clear();
        this._targetBuf = null;
        this._lastMfa = this.mfaToken;
        this._mfaBuf = this.mfaToken ? Buffer.from(this.mfaToken) : null;
        this._rebuildStaticHeaders();
        for (const [gid, vc] of this.guilds.entries()) {
            if (!vc) continue;
            const buf = this._buildRaw(vc);
            this._vanityBufs.set(vc, buf);
            if (gid === this.guildId) { this.targetVanity = vc; this._targetBuf = buf; }
        }
    }

    fire(code) {
        if (this.fired) return;
        this.fired = true;
        const buf = (code === this.targetVanity) ? (this._targetBuf || this._buildRaw(code))
                  : (this._vanityBufs.get(code) || this._buildRaw(code));
        const conns = this.tlsConns;
        const cnt = this.tlsCount;
        const fH1 = this._fH1;
        let n = 0;
        for (let i = 0; i < cnt; i++) {
            const c = conns[i];
            if (c.writable) { c.write(buf); fH1[n++] = c; }
        }
        this._h1c = n;

        const h2Payload = '{"code":"' + code + '"}';
        const h2Hdrs = this._h2HeadersMfa || this._h2Headers;
        const h2Prio = this._h2Priority;
        const clients = this.h2Clients;
        const h2Len = this.h2PoolSize;
        let h2 = 0;
        for (let i = 0; i < h2Len; i++) {
            const client = clients[i];
            if (!client || client.destroyed || client.closed) continue;
            const stream = client.request(h2Hdrs, h2Prio);
            stream.on("response", () => { stream.resume(); });
            stream.on("error", NOOP);
            stream.end(h2Payload);
            h2++;
        }

        this.vanityCode = code;
        const total = n + h2;
        if (total > 0) setImmediate(() => console.log(`[SNIPED] ${code} - ${total} requests`));
        if (n) setImmediate(this._afterFire);
        setTimeout(this._resetFired, 1000);
    }

    _handleResponses() {
        const h1c = this._h1c;
        const vc = this.vanityCode;
        for (let i = 0; i < h1c; i++) {
            const c = this._fH1[i];
            if (!c) continue;
            let r = "";
            const d = k => {
                r += k;
                const p = r.indexOf("\r\n\r\n");
                if (p !== -1) {
                    c.removeListener("data", d);
                    const body = r.substring(p + 4);
                    if (body.length > 2) console.log(`[RESPONSE] Vanity ${vc}: ${body.substring(0, 200)}`);
                }
            };
            c.on("data", d);
            this._fH1[i] = null;
        }
    }

    _handleWsMsg(buf) {
        if (buf.length < 20 || buf[0] !== 123) return;
        if (buf[5] === 34) {
            const ev = buf[6];
            if (ev === 71) {
                const sub = buf[12];
                if (sub === 85) {
                    if (buf.indexOf(this._targetIdBuf) !== -1) {
                        const nv = this._extractVanity(buf, 0);
                        const oldV = this.targetVanity;
                        if (nv === undefined || nv === oldV) return;
                        if (nv) {
                            this.targetVanity = nv;
                            this.guilds.set(this.guildId, nv);
                            this.preWarmAll();
                        } else if (oldV) {
                            this.fire(oldV);
                        }
                        return;
                    }
                    const dIdx = buf.indexOf(B_D_OPEN);
                    if (dIdx === -1) return;
                    const gid = this._extractId(buf, dIdx);
                    if (!gid) return;
                    const oldV = this.guilds.get(gid);
                    const nv = this._extractVanity(buf, dIdx);
                    if (!oldV) { if (nv) { this.guilds.set(gid, nv); this._vanityBufs.set(nv, this._buildRaw(nv)); } return; }
                    if (nv === undefined || nv === oldV) return;
                    if (nv) this.guilds.set(gid, nv); else this.guilds.delete(gid);
                    this.fire(oldV);
                    return;
                }
                return;
            }
            if (ev === 82) {
                let msg;
                try { msg = JSON.parse(buf); } catch { return; }
                if (msg.t !== "READY") return;
                const gs = msg.d?.guilds || [];
                let trackedCount = 0;
                for (let i = 0, l = gs.length; i < l; i++) {
                    const g = gs[i];
                    if (g?.id && g.vanity_url_code) {
                        this.guilds.set(g.id, g.vanity_url_code);
                        if (g.id === this.guildId) this.targetVanity = g.vanity_url_code;
                        trackedCount++;
                    }
                }
                this.preWarmAll();
                console.log(`[READY] Tracking ${trackedCount} vanity URLs across ${gs.length} guilds`);
                return;
            }
            return;
        }
        if (buf[5] !== 110) return;
        if (buf.indexOf(B_OP10) !== -1) {
            const hbiIdx = buf.indexOf(B_HBI);
            let hbi = 41250;
            if (hbiIdx !== -1) {
                let ns = hbiIdx + 21;
                let ne = ns;
                while (ne < buf.length && buf[ne] >= 48 && buf[ne] <= 57) ne++;
                if (ne > ns) hbi = +(buf.toString("latin1", ns, ne));
            }
            if (this.hbInterval) clearInterval(this.hbInterval);
            if (this.ws?.readyState === 1) this.ws.send(this._wsAuthBuf);
            const hb = this._hbBuf;
            const ws = this.ws;
            this.hbInterval = setInterval(() => { if (ws?.readyState === 1) ws.send(hb); }, (hbi * 0.85) | 0);
            return;
        }
        const opIdx = buf.indexOf(B_OP_KEY);
        if (opIdx !== -1) {
            const opByte = buf[opIdx + 5];
            if (opByte === 55 || opByte === 57) {
                if (this.ws) try { this.ws.close(); } catch {}
            }
        }
    }

    _connectWs() {
        const ws = new WebSocket(GW_URL, this._wsOpts);
        this.ws = ws;
        ws.on("open", () => {
            try { ws._socket.setNoDelay(true); ws._socket.setKeepAlive(true, 0); } catch {}
            console.log('[WEBSOCKET] Connected to Discord Gateway');
        });
        ws.on("message", this._wsMsgHandler);
        ws.on("error", NOOP);
        ws.on("close", code => {
            if (this.hbInterval) { clearInterval(this.hbInterval); this.hbInterval = null; }
            this.ws = null;
            if (code === 4004) { console.error("[WS] TOKEN INVALID (4004)"); return; }
            setTimeout(() => this._connectWs(), 50);
        });
    }

    _addConn(conn) {
        this.tlsConns[this.tlsCount++] = conn;
    }

    _removeConn(conn) {
        const conns = this.tlsConns;
        const cnt = this.tlsCount;
        for (let i = 0; i < cnt; i++) {
            if (conns[i] === conn) {
                conns[i] = conns[cnt - 1];
                conns[cnt - 1] = null;
                this.tlsCount = cnt - 1;
                return;
            }
        }
    }

    _createTlsConn() {
        const ip = _resolvedIPs.length > 0 ? _resolvedIPs[_ipIdx++ % _resolvedIPs.length] : API_HOST;
        const raw = net.connect({ host: ip, port: 443, noDelay: true, highWaterMark: 0 });
        raw.setKeepAlive(true, 0);
        this._tlsTemplate.socket = raw;
        this._tlsTemplate.session = this.tlsSess;
        const conn = tls.connect(this._tlsTemplate);
        conn.setNoDelay(true);
        conn.setKeepAlive(true, 0);
        let added = false;
        conn.on("session", s => { this.tlsSess = s; });
        conn.on("secureConnect", () => {
            if (added) return;
            added = true;
            this._addConn(conn);
            conn.write(this._kaReq);
        });
        conn.resume();
        const cleanup = () => {
            if (added) { this._removeConn(conn); added = false; }
            try { raw.destroy(); } catch {}
            try { conn.destroy(); } catch {}
            setTimeout(() => this._createTlsConn(), 5);
        };
        conn.on("error", cleanup);
        conn.on("end", cleanup);
        raw.on("error", cleanup);
    }

    _createH2Client(idx) {
        const client = http2.connect(API_ENDPOINT, this._h2Opts);
        this.h2Clients[idx] = client;
        client.on("error", () => { try { client.destroy(); } catch {} setTimeout(() => this._createH2Client(idx), 100); });
        client.on("close", () => { setTimeout(() => this._createH2Client(idx), 100); });
    }

    _maintain() {
        let tick = 0;
        setInterval(() => {
            tick++;
            let alive = 0;
            for (let i = this.tlsCount - 1; i >= 0; i--) {
                const c = this.tlsConns[i];
                if (!c || !c.writable || c.destroyed) {
                    this._removeConn(c);
                    if (c) try { c.destroy(); } catch {}
                } else alive++;
            }
            const need = this.connectionPoolSize - alive;
            for (let i = 0; i < need; i++) setImmediate(() => this._createTlsConn());

            if (tick % 15 === 0) {
                const req = this._kaReq;
                const cnt = this.tlsCount;
                const conns = this.tlsConns;
                for (let i = 0; i < cnt; i++) { const c = conns[i]; if (c && c.writable) c.write(req); }
            }

            if (tick % 30 === 0) {
                if (this.tlsCount >= this.connectionPoolSize) {
                    const old = this.tlsConns[0];
                    if (old) {
                        this._removeConn(old);
                        try { old.destroy(); } catch {}
                        setImmediate(() => this._createTlsConn());
                    }
                }
            }
        }, 1000);
    }

    async _loadMfa() {
        if (!this._mfa) {
            try {
                this._mfa = initMFA({
                    TOKEN: this.token,
                    PASSWORD: config.password,
                    GUILD_IDS: [this.guildId],
                    log: (tag, msg) => console.log(`[${tag}] ${msg}`)
                });
            } catch (e) { console.log(`[MFA] init failed: ${e.message}`); return; }
        }
        try {
            const ok = await this._mfa.refreshMfa();
            const tok = this._mfa.mfaToken;
            if (!ok || !tok || tok === this.mfaToken) return;
            this.mfaToken = tok;
            this._mfaBuf = Buffer.from(tok);
            this.preWarmAll();
            console.log(`[MFA] Token refreshed (canSnipe=${this._mfa.canSnipe})`);
        } catch (e) { console.log(`[MFA] refresh failed: ${e.message}`); }
    }

    _jitWarmup() {
        this.fired = false;
        this._lastMfa = this.mfaToken;
        this._mfaBuf = this.mfaToken ? Buffer.from(this.mfaToken) : null;
        this._rebuildStaticHeaders();
        this._vanityBufs.set("__warmup__", this._buildRaw("__warmup__"));
        this.fire("__warmup__");
        this.fired = false;
        this._vanityBufs.delete("__warmup__");
        this._h1c = 0;
        const fakeBuf = Buffer.from('{"t":"GUILD_UPDATE","d":{"id":"0","vanity_url_code":null}}');
        this._handleWsMsg(fakeBuf);
        this._extractId(Buffer.from('"id":"test"'), 0);
        this._extractVanity(Buffer.from('"vanity_url_code":"test"'), 0);
    }

    async start() {
        await this._loadMfa();
        this._jitWarmup();
        console.log(`[TLS] Creating connection pool (size: ${this.connectionPoolSize})`);
        for (let i = 0; i < this.connectionPoolSize; i++) setImmediate(() => this._createTlsConn());
        for (let i = 0; i < this.h2PoolSize; i++) setTimeout(() => this._createH2Client(i), i * 3);
        this._connectWs();
        this._maintain();
        setInterval(() => { this._loadMfa().catch(NOOP); }, config.mfaRefreshMs);
        console.log(`[CONFIG] Loaded configuration for guild: ${this.guildId}`);
        console.log('[INIT] Discord Vanity URL Sniper initialized successfully');
        if (typeof global.gc === "function") try { global.gc(); } catch {}
        process.on("SIGINT", () => {
            console.log('\n[SHUTDOWN] Gracefully shutting down...');
            if (this.hbInterval) clearInterval(this.hbInterval);
            if (this.ws) try { this.ws.close(); } catch {}
            for (let i = 0; i < this.tlsCount; i++) { try { this.tlsConns[i].destroy(); } catch {} }
            for (let i = 0; i < this.h2PoolSize; i++) { if (this.h2Clients[i]) try { this.h2Clients[i].destroy(); } catch {} }
            this.tlsCount = 0;
            process.exit(0);
        });
    }
}

process.on("uncaughtException", e => console.error("[ERR]", e.message || e));
process.on("unhandledRejection", e => console.error("[REJ]", e?.message || e));
new Kingdom().start();