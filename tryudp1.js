import { connect } from 'cloudflare:sockets';

// ========== 配置 ==========
const CLIENT_TOKEN   = '93bf61d9-3796-44c2-9b3a-49210ece2585';
const DNS_PORT       = 53;
const DEFAULT_PORT   = 443;
const MAX_HDR_SIZE   = 8192;
const TUNNEL_TIMEOUT = 10000;
let   gatewayAddr    = '';

// ========== 工具函数 ==========

function buildUUID(buf, start = 0) {
    const h = [...buf.slice(start, start + 16)]
        .map(b => b.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

function decodeBase64(str) {
    if (!str) return { error: null };
    try {
        const raw = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
        const arr = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
        return { earlyData: arr.buffer, error: null };
    } catch (err) {
        return { error: err };
    }
}

function safeCloseWS(ws) {
    try {
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CLOSING)
            ws.close();
    } catch (_) {}
}

function resolveGank(raw) {
    if (!raw) return null;
    raw = raw.trim();

    if (raw.startsWith('sst://') || raw.startsWith('sst5://')) {
        try {
            const u = new URL(raw.replace(/^sst:\/\//, 'sst5://'));
            return { kind: 'sst5', host: u.hostname, port: parseInt(u.port) || 1080 };
        } catch { return null; }
    }

    if (raw.startsWith('http://') || raw.startsWith('https://')) {
        try {
            const u = new URL(raw);
            return { kind: 'http', host: u.hostname,
                port: parseInt(u.port) || (raw.startsWith('https://') ? 443 : 80) };
        } catch { return null; }
    }

    if (raw.startsWith('[')) {
        const end = raw.indexOf(']');
        if (end > 0) {
            const host = raw.substring(1, end);
            const rest = raw.substring(end + 1);
            if (rest.startsWith(':')) {
                const p = parseInt(rest.substring(1), 10);
                if (!isNaN(p) && p > 0 && p <= 65535) return { kind: 'direct', host, port: p };
            }
            return { kind: 'direct', host, port: DEFAULT_PORT };
        }
    }

    const idx = raw.lastIndexOf(':');
    if (idx > 0) {
        const host = raw.substring(0, idx);
        const p    = parseInt(raw.substring(idx + 1), 10);
        if (!isNaN(p) && p > 0 && p <= 65535) return { kind: 'direct', host, port: p };
    }

    return { kind: 'direct', host: raw, port: DEFAULT_PORT };
}

// ========== 协议解析 ==========

function parseHeader(buf, token) {
    if (buf.byteLength < 24) return { hasError: true, message: 'Invalid data' };

    const ver  = new Uint8Array(buf.slice(0, 1));
    const uuid = buildUUID(new Uint8Array(buf.slice(1, 17)));
    if (uuid !== token) return { hasError: true, message: 'Invalid uuid' };

    const optLen = new Uint8Array(buf.slice(17, 18))[0];
    const cmd    = new Uint8Array(buf.slice(18 + optLen, 19 + optLen))[0];
    let udpMode  = false;
    if      (cmd === 1) {}
    else if (cmd === 2) { udpMode = true; }
    else return { hasError: true, message: 'Invalid cmd' };

    const portOff = 19 + optLen;
    const dstPort = new DataView(buf.slice(portOff, portOff + 2)).getUint16(0);

    let aIdx = portOff + 2, aLen = 0, aValIdx = aIdx + 1, dstHost = '';
    const aType = new Uint8Array(buf.slice(aIdx, aValIdx))[0];

    switch (aType) {
        case 1:
            aLen    = 4;
            dstHost = new Uint8Array(buf.slice(aValIdx, aValIdx + aLen)).join('.');
            break;
        case 2:
            aLen    = new Uint8Array(buf.slice(aValIdx, aValIdx + 1))[0];
            aValIdx += 1;
            dstHost = new TextDecoder().decode(buf.slice(aValIdx, aValIdx + aLen));
            break;
        case 3: {
            aLen = 16;
            const segs = [];
            const dv   = new DataView(buf.slice(aValIdx, aValIdx + aLen));
            for (let i = 0; i < 8; i++) segs.push(dv.getUint16(i * 2).toString(16));
            dstHost = segs.join(':');
            break;
        }
        default:
            return { hasError: true, message: `Invalid address type: ${aType}` };
    }

    if (!dstHost) return { hasError: true, message: `Invalid address: ${aType}` };

    return {
        hasError:    false,
        addressType: aType,
        port:        dstPort,
        hostname:    dstHost,
        isUDP:       udpMode,
        rawIndex:    aValIdx + aLen,
        version:     ver,
    };
}

function buildReadableWS(ws, initHeader) {
    let stopped = false;
    return new ReadableStream({
        start(ctrl) {
            ws.addEventListener('message', ev => { if (!stopped) ctrl.enqueue(ev.data); });
            ws.addEventListener('close',   () => {
                if (!stopped) { safeCloseWS(ws); ctrl.close(); }
            });
            ws.addEventListener('error', err => ctrl.error(err));

            const { earlyData, error } = decodeBase64(initHeader);
            if (error)          ctrl.error(error);
            else if (earlyData) ctrl.enqueue(earlyData);
        },
        cancel() { stopped = true; safeCloseWS(ws); },
    });
}

// ========== 连接函数 ==========

async function directConnect(addr, port, data) {
    const sock = connect({ hostname: addr, port });
    const w    = sock.writable.getWriter();
    await w.write(data);
    w.releaseLock();
    return sock;
}

async function sst5Connect(cfg, tHost, tPort, initData) {
    const { host, port } = cfg;
    let sock;
    try {
        sock    = connect({ hostname: host, port });
        const w = sock.writable.getWriter();
        const r = sock.readable.getReader();
        try {
            await w.write(new Uint8Array([0x05, 0x01, 0x00]));
            const mResp  = await r.read();
            if (mResp.done || mResp.value.byteLength < 2) throw new Error('S5 method selection failed');
            const chosen = new Uint8Array(mResp.value)[1];
            if (chosen !== 0x00) throw new Error(`S5 unexpected method: ${chosen}`);

            const hB      = new TextEncoder().encode(tHost);
            const connPkt = new Uint8Array(7 + hB.length);
            connPkt[0] = 0x05; connPkt[1] = 0x01; connPkt[2] = 0x00; connPkt[3] = 0x03;
            connPkt[4] = hB.length;
            connPkt.set(hB, 5);
            new DataView(connPkt.buffer).setUint16(5 + hB.length, tPort, false);
            await w.write(connPkt);

            const cResp = await r.read();
            if (cResp.done || new Uint8Array(cResp.value)[1] !== 0x00) throw new Error('S5 connection failed');

            await w.write(initData);
            w.releaseLock(); r.releaseLock();
            return sock;
        } catch (e) { w.releaseLock(); r.releaseLock(); throw e; }
    } catch (e) {
        if (sock) try { sock.close(); } catch (_) {}
        throw e;
    }
}

async function httpTunnelConnect(cfg, tHost, tPort, initData) {
    const { host, port } = cfg;
    let sock;
    try {
        sock    = connect({ hostname: host, port });
        const w = sock.writable.getWriter();
        const r = sock.readable.getReader();
        try {
            const req = `CONNECT ${tHost}:${tPort} HTTP/1.1\r\nHost: ${tHost}:${tPort}\r\nConnection: keep-alive\r\n\r\n`;
            await w.write(new TextEncoder().encode(req));

            let buf = new Uint8Array(0), endIdx = -1, read = 0;
            const t0 = Date.now();
            while (endIdx === -1 && read < MAX_HDR_SIZE) {
                if (Date.now() - t0 > TUNNEL_TIMEOUT) throw new Error('Connection timeout');
                const { done, value } = await r.read();
                if (done) throw new Error('Connection closed before HTTP response');
                const nb = new Uint8Array(buf.length + value.length);
                nb.set(buf); nb.set(value, buf.length);
                buf = nb; read = buf.length;
                for (let i = 0; i < buf.length - 3; i++) {
                    if (buf[i]===0x0d && buf[i+1]===0x0a && buf[i+2]===0x0d && buf[i+3]===0x0a) {
                        endIdx = i + 4; break;
                    }
                }
            }
            if (endIdx === -1) throw new Error('Invalid HTTP response or too large');

            const statusLine = new TextDecoder().decode(buf.slice(0, endIdx)).split('\r\n')[0];
            const m          = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
            if (!m) throw new Error(`Bad response: ${statusLine}`);
            const code = parseInt(m[1]);
            if (code < 200 || code >= 300) throw new Error(`Tunnel error ${code}: ${statusLine}`);

            await w.write(initData);
            w.releaseLock(); r.releaseLock();
            return sock;
        } catch (e) {
            try { w.releaseLock(); } catch (_) {}
            try { r.releaseLock(); } catch (_) {}
            throw e;
        }
    } catch (e) {
        if (sock) try { sock.close(); } catch (_) {}
        throw e;
    }
}

async function bridgeStreams(remoteSock, ws, initBuf, retryFn) {
    let hdr = initBuf, gotData = false;
    await remoteSock.readable.pipeTo(new WritableStream({
        async write(chunk, ctrl) {
            gotData = true;
            if (ws.readyState !== WebSocket.OPEN) { ctrl.error('ws closed'); return; }
            if (hdr) {
                const out = new Uint8Array(hdr.length + chunk.byteLength);
                out.set(hdr, 0); out.set(chunk, hdr.length);
                ws.send(out.buffer); hdr = null;
            } else {
                ws.send(chunk);
            }
        },
        abort() {},
    })).catch(() => safeCloseWS(ws));
    if (!gotData && retryFn) await retryFn();
}

async function routeTCP(aType, host, port, payload, ws, respHdr, connRef, gankOverride) {
    let gankCfg = null, useGank = false;

    if (gankOverride) {
        gankCfg = resolveGank(gankOverride);
        if (gankCfg && (gankCfg.kind === 'sst5' || gankCfg.kind === 'http')) useGank = true;
        else if (!gankCfg) gankCfg = resolveGank(gatewayAddr) || { kind: 'direct', host: gatewayAddr, port: DEFAULT_PORT };
    } else {
        gankCfg = resolveGank(gatewayAddr) || { kind: 'direct', host: gatewayAddr, port: DEFAULT_PORT };
        if (gankCfg.kind === 'sst5' || gankCfg.kind === 'http') useGank = true;
    }

    async function viaGank() {
        let s;
        if      (gankCfg.kind === 'sst5') s = await sst5Connect(gankCfg, host, port, payload);
        else if (gankCfg.kind === 'http') s = await httpTunnelConnect(gankCfg, host, port, payload);
        else                              s = await directConnect(gankCfg.host, gankCfg.port, payload);
        connRef.socket = s;
        s.closed.catch(() => {}).finally(() => safeCloseWS(ws));
        bridgeStreams(s, ws, respHdr, null);
    }

    if (useGank) {
        await viaGank();
    } else {
        try {
            const s = await directConnect(host, port, payload);
            connRef.socket = s;
            bridgeStreams(s, ws, respHdr, viaGank);
        } catch {
            await viaGank();
        }
    }
}

// ========== UDP 转发 ==========
//
// CF Workers 的 connect() 仅支持 TCP，因此所有 UDP 均以 TCP 封装转发。
//
// 策略：
//   port 53  → DNS over TCP，转发至客户端请求的实际目标地址
//   其他端口 → TCP 封装转发至目标地址（best-effort，适用于可降级协议）
//
// 注意：纯 UDP 协议（如 QUIC/WireGuard）在 TCP 封装下可能无法正常工作，
//       取决于对端服务器是否同时监听 TCP。

async function relayUDP(udpData, ws, hdr, targetHost, targetPort) {
    try {
        const remote  = connect({ hostname: targetHost, port: targetPort });
        let   outHdr  = hdr;
        const w       = remote.writable.getWriter();
        await w.write(udpData);
        w.releaseLock();

        await remote.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (ws.readyState !== WebSocket.OPEN) return;
                if (outHdr) {
                    const pkt = new Uint8Array(outHdr.length + chunk.byteLength);
                    pkt.set(outHdr, 0); pkt.set(chunk, outHdr.length);
                    ws.send(pkt.buffer); outHdr = null;
                } else {
                    ws.send(chunk);
                }
            },
        }));
    } catch (_) {}
}

// ========== 请求处理 ==========

async function processWsRequest(request, gankOverride) {
    const pair             = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    // UDP 会话状态：记录目标地址，一旦确定后续复用
    let connRef    = { socket: null };
    let udpTarget  = null;   // { host, port } — 非 null 表示当前连接为 UDP 模式

    const stream = buildReadableWS(server, request.headers.get('sec-websocket-protocol') || '');
    stream.pipeTo(new WritableStream({
        async write(chunk) {

            // UDP 模式：直接转发至已确定的目标，跳过头解析
            if (udpTarget) {
                await relayUDP(chunk, server, null, udpTarget.host, udpTarget.port);
                return;
            }

            // TCP 模式：复用已建立的 socket
            if (connRef.socket) {
                const w = connRef.socket.writable.getWriter();
                await w.write(chunk); w.releaseLock();
                return;
            }

            // 首包：解析 VLESS 头
            const parsed = parseHeader(chunk, CLIENT_TOKEN);
            if (parsed.hasError) throw new Error(parsed.message);

            const ackHdr = new Uint8Array([parsed.version[0], 0]);
            const body   = chunk.slice(parsed.rawIndex);

            if (parsed.isUDP) {
                // 锁定 UDP 目标，后续所有包复用同一目标地址
                udpTarget = { host: parsed.hostname, port: parsed.port };
                relayUDP(body, server, ackHdr, udpTarget.host, udpTarget.port);
                return;
            }

            // 普通 TCP 流量
            await routeTCP(
                parsed.addressType, parsed.hostname, parsed.port,
                body, server, ackHdr, connRef, gankOverride
            );
        },
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: client });
}

// ========== 主入口 ==========

export default {
    async fetch(request, env, ctx) {
        try {
            const url  = new URL(request.url);
            const path = url.pathname;

            if (path.startsWith('/gankip=') && !request.headers.get('Upgrade')) {
                try { gatewayAddr = decodeURIComponent(path.substring(8)).trim(); } catch (_) {}
                return new Response(`set gateway to: ${gatewayAddr}\n`, {
                    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
                });
            }

            if (request.headers.get('Upgrade') === 'websocket') {
                let gankOverride = null;
                if (path.startsWith('/gankip='))
                    try { gankOverride = decodeURIComponent(path.substring(8)).trim(); } catch (_) {}
                gankOverride = gankOverride
                    || url.searchParams.get('gankip')
                    || request.headers.get('gankip');
                return await processWsRequest(request, gankOverride);
            }

            return new Response('Not Found', { status: 404 });
        } catch (_) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};
