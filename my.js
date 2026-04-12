import { connect } from 'cloudflare:sockets';

let gatewayAddr = '';
let clientToken = '93bf61d9-3796-44c2-9b3a-49210ece2585';

let cdnNodeList = [
    'e'
];

// ========== 工具函数 ==========

function buildUUID(buf, start = 0) {
    const h = [...buf.slice(start, start + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${h.substring(0,8)}-${h.substring(8,12)}-${h.substring(12,16)}-${h.substring(16,20)}-${h.substring(20)}`;
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
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CLOSING) ws.close();
    } catch (_) {}
}

function resolveGank(raw) {
    if (!raw) return null;
    raw = raw.trim();

    if (raw.startsWith('sst://') || raw.startsWith('sst5://')) {
        const normalized = raw.replace(/^sst:\/\//, 'sst5://');
        try {
            const u = new URL(normalized);
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
            return { kind: 'direct', host, port: 443 };
        }
    }

    const idx = raw.lastIndexOf(':');
    if (idx > 0) {
        const host = raw.substring(0, idx);
        const p = parseInt(raw.substring(idx + 1), 10);
        if (!isNaN(p) && p > 0 && p <= 65535) return { kind: 'direct', host, port: p };
    }

    return { kind: 'direct', host: raw, port: 443 };
}

// ========== 协议解析 ==========

function parseHeader(buf, token) {
    if (buf.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    const ver = new Uint8Array(buf.slice(0, 1));
    if (buildUUID(new Uint8Array(buf.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
    const optLen = new Uint8Array(buf.slice(17, 18))[0];
    const cmd = new Uint8Array(buf.slice(18 + optLen, 19 + optLen))[0];
    let udpMode = false;
    if (cmd === 1) {} else if (cmd === 2) { udpMode = true; } else return { hasError: true, message: 'Invalid cmd' };
    const portOff = 19 + optLen;
    const dstPort = new DataView(buf.slice(portOff, portOff + 2)).getUint16(0);
    let aIdx = portOff + 2, aLen = 0, aValIdx = aIdx + 1, dstHost = '';
    const aType = new Uint8Array(buf.slice(aIdx, aValIdx))[0];
    switch (aType) {
        case 1: aLen = 4; dstHost = new Uint8Array(buf.slice(aValIdx, aValIdx + aLen)).join('.'); break;
        case 2: aLen = new Uint8Array(buf.slice(aValIdx, aValIdx + 1))[0]; aValIdx += 1; dstHost = new TextDecoder().decode(buf.slice(aValIdx, aValIdx + aLen)); break;
        case 3:
            aLen = 16;
            const segs = [];
            const dv = new DataView(buf.slice(aValIdx, aValIdx + aLen));
            for (let i = 0; i < 8; i++) segs.push(dv.getUint16(i * 2).toString(16));
            dstHost = segs.join(':');
            break;
        default: return { hasError: true, message: `Invalid address type: ${aType}` };
    }
    if (!dstHost) return { hasError: true, message: `Invalid address: ${aType}` };
    return { hasError: false, addressType: aType, port: dstPort, hostname: dstHost, isUDP: udpMode, rawIndex: aValIdx + aLen, version: ver };
}

function buildReadableWS(ws, initHeader) {
    let stopped = false;
    return new ReadableStream({
        start(ctrl) {
            ws.addEventListener('message', ev => { if (!stopped) ctrl.enqueue(ev.data); });
            ws.addEventListener('close', () => { if (!stopped) { safeCloseWS(ws); ctrl.close(); } });
            ws.addEventListener('error', err => ctrl.error(err));
            const { earlyData, error } = decodeBase64(initHeader);
            if (error) ctrl.error(error);
            else if (earlyData) ctrl.enqueue(earlyData);
        },
        cancel() { stopped = true; safeCloseWS(ws); }
    });
}

// ========== 连接函数 ==========

async function directConnect(addr, port, data) {
    const sock = connect({ hostname: addr, port });
    const w = sock.writable.getWriter();
    await w.write(data);
    w.releaseLock();
    return sock;
}

async function sst5Connect(cfg, tHost, tPort, initData) {
    const { host, port } = cfg;
    let sock;
    try {
        sock = connect({ hostname: host, port });
        const w = sock.writable.getWriter();
        const r = sock.readable.getReader();
        try {
            await w.write(new Uint8Array([0x05, 0x01, 0x00]));
            const mResp = await r.read();
            if (mResp.done || mResp.value.byteLength < 2) throw new Error('S5 method selection failed');
            const chosen = new Uint8Array(mResp.value)[1];
            if (chosen !== 0x00) throw new Error(`S5 unexpected method: ${chosen}`);
            const hB = new TextEncoder().encode(tHost);
            const connPkt = new Uint8Array(7 + hB.length);
            connPkt[0] = 0x05; connPkt[1] = 0x01; connPkt[2] = 0x00; connPkt[3] = 0x03;
            connPkt[4] = hB.length; connPkt.set(hB, 5);
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
        sock = connect({ hostname: host, port });
        const w = sock.writable.getWriter();
        const r = sock.readable.getReader();
        try {
            const req = `CONNECT ${tHost}:${tPort} HTTP/1.1\r\nHost: ${tHost}:${tPort}\r\nConnection: keep-alive\r\n\r\n`;
            await w.write(new TextEncoder().encode(req));
            let buf = new Uint8Array(0), endIdx = -1, read = 0;
            const maxSz = 8192, t0 = Date.now();
            while (endIdx === -1 && read < maxSz) {
                if (Date.now() - t0 > 10000) throw new Error('connection timeout');
                const { done, value } = await r.read();
                if (done) throw new Error('Connection closed before HTTP response');
                const nb = new Uint8Array(buf.length + value.length);
                nb.set(buf); nb.set(value, buf.length);
                buf = nb; read = buf.length;
                for (let i = 0; i < buf.length - 3; i++) {
                    if (buf[i] === 0x0d && buf[i+1] === 0x0a && buf[i+2] === 0x0d && buf[i+3] === 0x0a) {
                        endIdx = i + 4; break;
                    }
                }
            }
            if (endIdx === -1) throw new Error('Invalid HTTP response or too large');
            const statusLine = new TextDecoder().decode(buf.slice(0, endIdx)).split('\r\n')[0];
            const m = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
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
            if (ws.readyState !== WebSocket.OPEN) ctrl.error('ws closed');
            if (hdr) {
                const combined = new Uint8Array(hdr.length + chunk.byteLength);
                combined.set(hdr, 0); combined.set(chunk, hdr.length);
                ws.send(combined.buffer); hdr = null;
            } else {
                ws.send(chunk);
            }
        },
        abort() {}
    })).catch(() => safeCloseWS(ws));
    if (!gotData && retryFn) await retryFn();
}

async function routeTCP(aType, host, port, payload, ws, respHdr, connRef, gankOverride) {
    let gankCfg = null, useGank = false;
    if (gankOverride) {
        gankCfg = resolveGank(gankOverride);
        if (gankCfg && (gankCfg.kind === 'sst5' || gankCfg.kind === 'http')) useGank = true;
        else if (!gankCfg) gankCfg = resolveGank(gatewayAddr) || { kind: 'direct', host: gatewayAddr, port: 443 };
    } else {
        gankCfg = resolveGank(gatewayAddr) || { kind: 'direct', host: gatewayAddr, port: 443 };
        if (gankCfg.kind === 'sst5' || gankCfg.kind === 'http') useGank = true;
    }

    async function viaGank() {
        let s;
        if (gankCfg.kind === 'sst5') s = await sst5Connect(gankCfg, host, port, payload);
        else if (gankCfg.kind === 'http') s = await httpTunnelConnect(gankCfg, host, port, payload);
        else s = await directConnect(gankCfg.host, gankCfg.port, payload);
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

async function relayUDP(udpData, ws, hdr) {
    try {
        const dnsSock = connect({ hostname: '8.8.4.4', port: 53 });
        let outHdr = hdr;
        const w = dnsSock.writable.getWriter();
        await w.write(udpData);
        w.releaseLock();
        await dnsSock.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (ws.readyState === WebSocket.OPEN) {
                    if (outHdr) {
                        const pkt = new Uint8Array(outHdr.length + chunk.byteLength);
                        pkt.set(outHdr, 0); pkt.set(chunk, outHdr.length);
                        ws.send(pkt.buffer); outHdr = null;
                    } else ws.send(chunk);
                }
            }
        }));
    } catch (_) {}
}

// ========== 页面生成 ==========

function renderHomePage() {
    return 'ok';
}

function renderSubPage() {
    return 'ok';
}

// ========== 请求处理 ==========

async function processWsRequest(request, gankOverride) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    let connRef = { socket: null };
    let dnsMode = false;
    const earlyHdr = request.headers.get('sec-websocket-protocol') || '';
    const stream = buildReadableWS(server, earlyHdr);
    stream.pipeTo(new WritableStream({
        async write(chunk) {
            if (dnsMode) return await relayUDP(chunk, server, null);
            if (connRef.socket) {
                const w = connRef.socket.writable.getWriter();
                await w.write(chunk); w.releaseLock();
                return;
            }
            const parsed = parseHeader(chunk, clientToken);
            if (parsed.hasError) throw new Error(parsed.message);
            if (parsed.isUDP) {
                if (parsed.port === 53) dnsMode = true;
                else throw new Error('UDP not supported');
            }
            const ackHdr = new Uint8Array([parsed.version[0], 0]);
            const body = chunk.slice(parsed.rawIndex);
            if (dnsMode) return relayUDP(body, server, ackHdr);
            await routeTCP(parsed.addressType, parsed.hostname, parsed.port, body, server, ackHdr, connRef, gankOverride);
        }
    })).catch(() => {});
    return new Response(null, { status: 101, webSocket: client });
}

// ========== 主入口 ==========

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const path = url.pathname;
            let pathGank = null;

            if (path.startsWith('/gankip=')) {
                try { pathGank = decodeURIComponent(path.substring(8)).trim(); } catch (_) {}
                if (pathGank && !request.headers.get('Upgrade')) {
                    gatewayAddr = pathGank;
                    return new Response(`set gateway to: ${gatewayAddr}\n\n`, {
                        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
                    });
                }
            }

            if (request.headers.get('Upgrade') === 'websocket') {
                let wsGank = null;
                if (path.startsWith('/gankip=')) {
                    try { wsGank = decodeURIComponent(path.substring(8)).trim(); } catch (_) {}
                }
                const activeGank = wsGank || url.searchParams.get('gankip') || request.headers.get('gankip');
                return await processWsRequest(request, activeGank);
            }

            if (request.method === 'GET') {
                const domain = url.hostname;

                if (path === '/') return new Response(renderHomePage(), {
                    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
                });

                if (path === `/${clientToken}`) return new Response(renderSubPage(), {
                    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
                });

                if (path.toLowerCase().includes(`/sub/${clientToken}`)) {
                    const proto = 'v' + 'l' + 'e' + 's' + 's';
                    const links = cdnNodeList.map(item => {
                        let nodeHost, nodePort = 443, nodeTag = '';
                        if (item.includes('#')) { const p = item.split('#'); item = p[0]; nodeTag = p[1]; }
                        if (item.startsWith('[') && item.includes(']:')) {
                            const e = item.indexOf(']:');
                            nodeHost = item.substring(0, e + 1);
                            nodePort = parseInt(item.substring(e + 2)) || 443;
                        } else if (item.includes(':')) {
                            const p = item.split(':'); nodeHost = p[0]; nodePort = parseInt(p[1]) || 443;
                        } else { nodeHost = item; }
                        if (!nodeTag) nodeTag = `Snippets-${proto}`;
                        return `oi`;
                    });
                    return new Response(btoa(unescape(encodeURIComponent(links.join('\n')))), {
                        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
                    });
                }
            }

            return new Response('Not Found', { status: 404 });
        } catch (_) {
            return new Response('Internal Server Error', { status: 500 });
        }
    }
};
