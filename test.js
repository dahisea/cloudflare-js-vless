import { connect } from 'cloudflare:sockets';

// =====================================================================
// 核心配置
// =====================================================================
const CLIENT_AUTH_TOKEN    = '93bf61d9-3796-44c2-9b3a-49210ece2585';
const DNS_TCP_PORT         = 53;
const DEFAULT_PROXY_PORT   = 443;
const HTTP_HEADER_MAX_SIZE = 8192;
const TUNNEL_HANDSHAKE_TIMEOUT_MS = 10000;

// WebSocket 保活：QIANG 对超过约 60s 空闲的连接发 RST，每 25s ping 一次规避
const WS_KEEPALIVE_INTERVAL_MS = 25000;

// 全局网关地址，可通过 /gateway= 路径在运行时覆盖
let globalGatewayAddress = '';

// 伪装首页内容：非 WebSocket 请求返回正常页面，规避 QIANG 主动探测
const DECOY_PAGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Cloudflare Worker</title></head>
<body><h2>Service Unavailable</h2><p>Please try again later.</p></body>
</html>`;

// =====================================================================
// 工具函数
// =====================================================================

/**
 * 从字节缓冲区的指定偏移位置解析出标准 UUID 字符串。
 */
function parseUUIDFromBuffer(buffer, offset = 0) {
    const hexParts = [...buffer.slice(offset, offset + 16)]
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
    return [
        hexParts.slice(0, 8),
        hexParts.slice(8, 12),
        hexParts.slice(12, 16),
        hexParts.slice(16, 20),
        hexParts.slice(20),
    ].join('-');
}

/**
 * 解码 WebSocket 早期数据（Early Data），用于 0-RTT 场景。
 * Sec-WebSocket-Protocol 头中可携带 base64url 编码的初始数据。
 */
function decodeEarlyData(base64UrlString) {
    if (!base64UrlString) return { earlyData: null, error: null };
    try {
        const base64Standard = base64UrlString.replace(/-/g, '+').replace(/_/g, '/');
        const rawBinary       = atob(base64Standard);
        const byteArray       = new Uint8Array(rawBinary.length);
        for (let i = 0; i < rawBinary.length; i++) byteArray[i] = rawBinary.charCodeAt(i);
        return { earlyData: byteArray.buffer, error: null };
    } catch (decodeError) {
        return { earlyData: null, error: decodeError };
    }
}

/**
 * 安全关闭 WebSocket，忽略已关闭状态下的错误。
 */
function safeCloseWebSocket(ws) {
    try {
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CLOSING) {
            ws.close();
        }
    } catch (_) {}
}

/**
 * 解析代理网关地址字符串，支持 SST（sst://）、HTTP CONNECT、直连三种模式。
 * 返回结构：{ kind: 'sst'|'http'|'direct', host: string, port: number }
 */
function parseGatewayAddress(rawAddress) {
    if (!rawAddress) return null;
    const trimmed = rawAddress.trim();

    // SST 代理
    if (trimmed.startsWith('sst://') || trimmed.startsWith('sst5://')) {
        try {
            const normalized = trimmed.replace(/^sst:\/\//, 'sst://');
            const parsed     = new URL(normalized);
            return { kind: 'sst', host: parsed.hostname, port: parseInt(parsed.port) || 1080 };
        } catch { return null; }
    }

    // HTTP/HTTPS CONNECT 代理
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
        try {
            const parsed       = new URL(trimmed);
            const defaultPort  = trimmed.startsWith('https://') ? 443 : 80;
            return { kind: 'http', host: parsed.hostname, port: parseInt(parsed.port) || defaultPort };
        } catch { return null; }
    }

    // IPv6 字面量，如 [::1]:1080
    if (trimmed.startsWith('[')) {
        const closingBracket = trimmed.indexOf(']');
        if (closingBracket > 0) {
            const host      = trimmed.substring(1, closingBracket);
            const remainder = trimmed.substring(closingBracket + 1);
            const port      = remainder.startsWith(':') ? parseInt(remainder.substring(1), 10) : DEFAULT_PROXY_PORT;
            return { kind: 'direct', host, port: (port > 0 && port <= 65535) ? port : DEFAULT_PROXY_PORT };
        }
    }

    // host:port 或纯主机名
    const lastColonIndex = trimmed.lastIndexOf(':');
    if (lastColonIndex > 0) {
        const host = trimmed.substring(0, lastColonIndex);
        const port = parseInt(trimmed.substring(lastColonIndex + 1), 10);
        if (!isNaN(port) && port > 0 && port <= 65535) return { kind: 'direct', host, port };
    }

    return { kind: 'direct', host: trimmed, port: DEFAULT_PROXY_PORT };
}

// =====================================================================
// MAGIC 协议头解析
// =====================================================================

/**
 * 解析 MAGIC v0 协议头，验证 UUID Token，提取目标地址、端口及协议类型。
 * 返回解析结果，hasError=true 时附带 message 说明原因。
 */
function parseMAGICHeader(rawBuffer, expectedToken) {
    if (rawBuffer.byteLength < 24) {
        return { hasError: true, message: 'Packet too short to be a valid MAGIC header' };
    }

    const versionByte = new Uint8Array(rawBuffer.slice(0, 1));
    const tokenUUID   = parseUUIDFromBuffer(new Uint8Array(rawBuffer.slice(1, 17)));

    if (tokenUUID !== expectedToken) {
        return { hasError: true, message: 'UUID authentication failed' };
    }

    const optionLength    = new Uint8Array(rawBuffer.slice(17, 18))[0];
    const commandByte     = new Uint8Array(rawBuffer.slice(18 + optionLength, 19 + optionLength))[0];
    let   isUDPMode       = false;

    if      (commandByte === 1) { /* TCP */ }
    else if (commandByte === 2) { isUDPMode = true; }
    else { return { hasError: true, message: `Unsupported MAGIC command: ${commandByte}` }; }

    const portOffset      = 19 + optionLength;
    const destinationPort = new DataView(rawBuffer.slice(portOffset, portOffset + 2)).getUint16(0);

    let addressTypeIndex  = portOffset + 2;
    let addressValueIndex = addressTypeIndex + 1;
    let addressLength     = 0;
    let destinationHost   = '';

    const addressType = new Uint8Array(rawBuffer.slice(addressTypeIndex, addressValueIndex))[0];

    switch (addressType) {
        case 1: // IPv4
            addressLength   = 4;
            destinationHost = new Uint8Array(rawBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
            break;
        case 2: // 域名，前一字节为长度
            addressLength   = new Uint8Array(rawBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            destinationHost = new TextDecoder().decode(rawBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3: { // IPv6
            addressLength     = 16;
            const segments    = [];
            const dataView    = new DataView(rawBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            for (let i = 0; i < 8; i++) segments.push(dataView.getUint16(i * 2).toString(16));
            destinationHost   = segments.join(':');
            break;
        }
        default:
            return { hasError: true, message: `Unknown address type: ${addressType}` };
    }

    if (!destinationHost) {
        return { hasError: true, message: 'Destination host is empty after parsing' };
    }

    return {
        hasError:      false,
        addressType:   addressType,
        hostname:      destinationHost,
        port:          destinationPort,
        isUDP:         isUDPMode,
        payloadOffset: addressValueIndex + addressLength, // 实际数据起始位置
        versionByte:   versionByte,
    };
}

// =====================================================================
// WebSocket 可读流封装 + 保活
// =====================================================================

/**
 * 将 WebSocket 的 message 事件封装为 ReadableStream，
 * 支持注入早期数据（Early Data）。
 * 同时启动保活心跳，每 WS_KEEPALIVE_INTERVAL_MS 发送一个空 ping 帧，
 * 防止 QIANG 因空闲超时主动重置连接。
 */
function createWebSocketReadableStream(ws, earlyDataHeader) {
    let isCancelled       = false;
    let keepaliveTimerId  = null;

    return new ReadableStream({
        start(controller) {
            // 启动保活心跳
            keepaliveTimerId = setInterval(() => {
                if (ws.readyState === WebSocket.OPEN) {
                    // 发送一个 1 字节的空 payload，接收端忽略即可
                    try { ws.send(new Uint8Array([0x00]).buffer); } catch (_) {}
                } else {
                    clearInterval(keepaliveTimerId);
                }
            }, WS_KEEPALIVE_INTERVAL_MS);

            ws.addEventListener('message', event => {
                if (!isCancelled) controller.enqueue(event.data);
            });

            ws.addEventListener('close', () => {
                clearInterval(keepaliveTimerId);
                if (!isCancelled) { safeCloseWebSocket(ws); controller.close(); }
            });

            ws.addEventListener('error', err => {
                clearInterval(keepaliveTimerId);
                controller.error(err);
            });

            // 注入早期数据
            const { earlyData, error } = decodeEarlyData(earlyDataHeader);
            if (error)     { controller.error(error); }
            else if (earlyData) { controller.enqueue(earlyData); }
        },
        cancel() {
            isCancelled = true;
            clearInterval(keepaliveTimerId);
            safeCloseWebSocket(ws);
        },
    });
}

// =====================================================================
// 底层连接函数
// =====================================================================

/**
 * 直连目标地址，发送初始数据，返回 CF Socket。
 */
async function connectDirect(targetHost, targetPort, initialPayload) {
    const socket = connect({ hostname: targetHost, port: targetPort });
    const writer = socket.writable.getWriter();
    await writer.write(initialPayload);
    writer.releaseLock();
    return socket;
}

/**
 * 通过 SST 代理连接目标，完成握手后发送初始数据，返回 CF Socket。
 */
async function connectViasst(gatewayCfg, targetHost, targetPort, initialPayload) {
    const socket = connect({ hostname: gatewayCfg.host, port: gatewayCfg.port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
        // SST 握手：发送方法协商（无认证）
        await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
        const methodResponse = await reader.read();
        if (methodResponse.done || methodResponse.value.byteLength < 2) {
            throw new Error('SST method negotiation failed: no response');
        }
        if (new Uint8Array(methodResponse.value)[1] !== 0x00) {
            throw new Error(`SST server rejected no-auth method`);
        }

        // SST CONNECT 请求
        const hostBytes     = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket[0] = 0x05; // VER
        connectPacket[1] = 0x01; // CMD: CONNECT
        connectPacket[2] = 0x00; // RSV
        connectPacket[3] = 0x03; // ATYP: domain name
        connectPacket[4] = hostBytes.length;
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        await writer.write(connectPacket);

        const connectResponse = await reader.read();
        if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
            throw new Error('SST CONNECT failed: server returned error');
        }

        await writer.write(initialPayload);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (err) {
        writer.releaseLock();
        reader.releaseLock();
        try { socket.close(); } catch (_) {}
        throw err;
    }
}

/**
 * 通过 HTTP CONNECT 隧道连接目标，解析 2xx 响应后发送初始数据，返回 CF Socket。
 */
async function connectViaHttpTunnel(gatewayCfg, targetHost, targetPort, initialPayload) {
    const socket = connect({ hostname: gatewayCfg.host, port: gatewayCfg.port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
        const connectRequest = [
            `CONNECT ${targetHost}:${targetPort} HTTP/1.1`,
            `Host: ${targetHost}:${targetPort}`,
            `User-Agent: Mozilla/5.0 (compatible; Cloudflare-Worker)`,
            `Proxy-Connection: keep-alive`,
            `\r\n`,
        ].join('\r\n');
        await writer.write(new TextEncoder().encode(connectRequest));

        // 读取 HTTP 响应头，直到找到 \r\n\r\n
        let responseBuffer    = new Uint8Array(0);
        let headerEndIndex    = -1;
        let totalBytesRead    = 0;
        const startTime       = Date.now();

        while (headerEndIndex === -1 && totalBytesRead < HTTP_HEADER_MAX_SIZE) {
            if (Date.now() - startTime > TUNNEL_HANDSHAKE_TIMEOUT_MS) {
                throw new Error('HTTP CONNECT tunnel handshake timed out');
            }
            const { done, value } = await reader.read();
            if (done) throw new Error('HTTP CONNECT tunnel connection closed prematurely');

            const merged = new Uint8Array(responseBuffer.length + value.length);
            merged.set(responseBuffer);
            merged.set(value, responseBuffer.length);
            responseBuffer = merged;
            totalBytesRead = responseBuffer.length;

            for (let i = 0; i < responseBuffer.length - 3; i++) {
                if (responseBuffer[i] === 0x0d && responseBuffer[i+1] === 0x0a &&
                    responseBuffer[i+2] === 0x0d && responseBuffer[i+3] === 0x0a) {
                    headerEndIndex = i + 4;
                    break;
                }
            }
        }

        if (headerEndIndex === -1) throw new Error('HTTP CONNECT response header too large or malformed');

        const statusLine    = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0];
        const statusMatch   = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        if (!statusMatch)   throw new Error(`HTTP CONNECT bad status line: ${statusLine}`);
        const statusCode    = parseInt(statusMatch[1]);
        if (statusCode < 200 || statusCode >= 300) {
            throw new Error(`HTTP CONNECT tunnel refused with status ${statusCode}`);
        }

        await writer.write(initialPayload);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (err) {
        try { writer.releaseLock(); } catch (_) {}
        try { reader.releaseLock(); } catch (_) {}
        try { socket.close(); } catch (_) {}
        throw err;
    }
}

// =====================================================================
// 双向流桥接
// =====================================================================

/**
 * 将远端 Socket 的响应流桥接回客户端 WebSocket。
 * firstResponseHeader 是 MAGIC 的 ACK 头（2字节），随第一个数据包一起发出。
 * onNoDataFallback 在远端未返回任何数据时触发，用于切换备用通路。
 */
async function bridgeRemoteToWebSocket(remoteSocket, clientWs, firstResponseHeader, onNoDataFallback) {
    let responseHeaderSent = firstResponseHeader;
    let receivedAnyData    = false;

    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            receivedAnyData = true;
            if (clientWs.readyState !== WebSocket.OPEN) {
                controller.error('WebSocket closed before data could be forwarded');
                return;
            }
            if (responseHeaderSent) {
                const combined = new Uint8Array(responseHeaderSent.length + chunk.byteLength);
                combined.set(responseHeaderSent, 0);
                combined.set(new Uint8Array(chunk instanceof ArrayBuffer ? chunk : chunk.buffer), responseHeaderSent.length);
                clientWs.send(combined.buffer);
                responseHeaderSent = null;
            } else {
                clientWs.send(chunk);
            }
        },
        abort() {},
    })).catch(() => safeCloseWebSocket(clientWs));

    if (!receivedAnyData && onNoDataFallback) {
        await onNoDataFallback();
    }
}

// =====================================================================
// TCP 路由（含 QIANG 规避：直连失败自动切网关）
// =====================================================================

/**
 * 建立到目标的 TCP 连接，优先直连，失败后通过配置的网关中转。
 * 这是对抗 QIANG IP 封锁的核心逻辑：Worker 出口 IP 被封时，
 * 通过备用网关中转即可绕过封锁。
 *
 * perRequestGatewayOverride 允许单请求级别覆盖全局网关配置。
 */
async function routeTCPWithFallback(
    addressType, targetHost, targetPort,
    initialPayload, clientWs, MAGICAckHeader,
    socketRef, perRequestGatewayOverride
) {
    // 解析本次请求应使用的网关配置
    const effectiveGatewayCfg = resolveEffectiveGateway(perRequestGatewayOverride);
    const useGatewayDirectly  = effectiveGatewayCfg.kind === 'sst' || effectiveGatewayCfg.kind === 'http';

    /**
     * 通过网关（SST/HTTP/直连转发）建立连接。
     */
    async function connectViaGateway() {
        let remoteSocket;
        if      (effectiveGatewayCfg.kind === 'sst') {
            remoteSocket = await connectViasst(effectiveGatewayCfg, targetHost, targetPort, initialPayload);
        } else if (effectiveGatewayCfg.kind === 'http') {
            remoteSocket = await connectViaHttpTunnel(effectiveGatewayCfg, targetHost, targetPort, initialPayload);
        } else {
            remoteSocket = await connectDirect(effectiveGatewayCfg.host, effectiveGatewayCfg.port, initialPayload);
        }
        socketRef.current = remoteSocket;
        remoteSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(clientWs));
        bridgeRemoteToWebSocket(remoteSocket, clientWs, MAGICAckHeader, null);
    }

    if (useGatewayDirectly) {
        // 配置了明确的代理网关，直接走代理
        await connectViaGateway();
    } else {
        // 先尝试直连目标，若无响应则自动回落到网关
        try {
            const directSocket    = await connectDirect(targetHost, targetPort, initialPayload);
            socketRef.current     = directSocket;
            directSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(clientWs));
            // onNoDataFallback：目标无响应时（可能被 QIANG 封锁），切换网关
            await bridgeRemoteToWebSocket(directSocket, clientWs, MAGICAckHeader, connectViaGateway);
        } catch (_directConnectError) {
            // 直连异常（连接拒绝、超时等），立即切网关
            await connectViaGateway();
        }
    }
}

/**
 * 综合全局配置与单请求覆盖，返回最终生效的网关配置。
 */
function resolveEffectiveGateway(perRequestOverride) {
    if (perRequestOverride) {
        const parsed = parseGatewayAddress(perRequestOverride);
        if (parsed) return parsed;
    }
    const globalParsed = parseGatewayAddress(globalGatewayAddress);
    return globalParsed || { kind: 'direct', host: globalGatewayAddress, port: DEFAULT_PROXY_PORT };
}

// =====================================================================
// UDP 转发（DNS 专项优化）
// =====================================================================

/**
 * 将 UDP 数据通过 TCP 隧道转发至目标。
 * 针对 DNS（端口 53）：DNS-over-TCP 要求报文前加 2 字节大端长度前缀，
 * 否则目标 DNS 服务器无法识别请求，这是原版代码的关键 bug。
 *
 * 其他 UDP 端口：直接 TCP 封装（best-effort，取决于目标是否同时监听 TCP）。
 */
async function relayUDPOverTCP(udpPayload, clientWs, firstResponseHeader, targetHost, targetPort) {
    try {
        const isDNS = (targetPort === DNS_TCP_PORT);
        let   wirePayload;

        if (isDNS) {
            // DNS-over-TCP 封装：2字节长度前缀 + DNS 报文
            const dnsPayloadBytes = udpPayload instanceof ArrayBuffer
                ? new Uint8Array(udpPayload)
                : new Uint8Array(udpPayload.buffer, udpPayload.byteOffset, udpPayload.byteLength);
            wirePayload           = new Uint8Array(2 + dnsPayloadBytes.length);
            wirePayload[0]        = (dnsPayloadBytes.length >> 8) & 0xff;
            wirePayload[1]        = dnsPayloadBytes.length & 0xff;
            wirePayload.set(dnsPayloadBytes, 2);
        } else {
            wirePayload = udpPayload;
        }

        const remoteSocket    = connect({ hostname: targetHost, port: targetPort });
        let   headerRemaining = firstResponseHeader;
        const writer          = remoteSocket.writable.getWriter();
        await writer.write(wirePayload);
        writer.releaseLock();

        await remoteSocket.readable.pipeTo(new WritableStream({
            async write(responseChunk) {
                if (clientWs.readyState !== WebSocket.OPEN) return;

                let dataToForward = responseChunk;

                if (isDNS) {
                    // 去掉 DNS-over-TCP 的 2 字节长度前缀再返回给客户端
                    const responseBytes = responseChunk instanceof ArrayBuffer
                        ? new Uint8Array(responseChunk)
                        : responseChunk;
                    if (responseBytes.length > 2) {
                        dataToForward = responseBytes.slice(2).buffer;
                    } else {
                        return; // 长度前缀不完整，丢弃
                    }
                }

                if (headerRemaining) {
                    const combined = new Uint8Array(headerRemaining.length + dataToForward.byteLength);
                    combined.set(headerRemaining, 0);
                    combined.set(new Uint8Array(dataToForward instanceof ArrayBuffer
                        ? dataToForward : dataToForward.buffer), headerRemaining.length);
                    clientWs.send(combined.buffer);
                    headerRemaining = null;
                } else {
                    clientWs.send(dataToForward);
                }
            },
        }));
    } catch (_udpRelayError) {
        // UDP 转发失败静默处理，不影响其他会话
    }
}

// =====================================================================
// WebSocket 请求处理核心
// =====================================================================

/**
 * 处理一个 WebSocket 升级请求，建立 MAGIC 代理会话。
 */
async function handleWebSocketUpgrade(incomingRequest, perRequestGatewayOverride) {
    const { 0: clientSideSocket, 1: serverSideSocket } = Object.values(new WebSocketPair());
    serverSideSocket.accept();

    // socketRef 用于持有已建立的 TCP 连接引用，实现多帧复用
    const socketRef  = { current: null };
    // udpSession 一旦确定，后续所有数据包直接转发，无需重新解析头
    let udpSession   = null;

    const earlyDataHeader = incomingRequest.headers.get('sec-websocket-protocol') || '';
    const wsReadableStream = createWebSocketReadableStream(serverSideSocket, earlyDataHeader);

    wsReadableStream.pipeTo(new WritableStream({
        async write(rawChunk) {

            // UDP 模式：会话已建立，直接转发后续数据包
            if (udpSession) {
                await relayUDPOverTCP(rawChunk, serverSideSocket, null, udpSession.host, udpSession.port);
                return;
            }

            // TCP 模式：已建立连接，将数据写入远端 Socket
            if (socketRef.current) {
                const writer = socketRef.current.writable.getWriter();
                await writer.write(rawChunk);
                writer.releaseLock();
                return;
            }

            // 首包：解析 MAGIC 协议头，建立连接
            const parseResult = parseMAGICHeader(rawChunk, CLIENT_AUTH_TOKEN);
            if (parseResult.hasError) {
                throw new Error(`MAGIC header parse error: ${parseResult.message}`);
            }

            const MAGICAckHeader  = new Uint8Array([parseResult.versionByte[0], 0]);
            const applicationData = rawChunk.slice(parseResult.payloadOffset);

            if (parseResult.isUDP) {
                udpSession = { host: parseResult.hostname, port: parseResult.port };
                relayUDPOverTCP(
                    applicationData, serverSideSocket,
                    MAGICAckHeader, udpSession.host, udpSession.port
                );
                return;
            }

            // 普通 TCP 流量，含 QIANG 规避回退逻辑
            await routeTCPWithFallback(
                parseResult.addressType,
                parseResult.hostname,
                parseResult.port,
                applicationData,
                serverSideSocket,
                MAGICAckHeader,
                socketRef,
                perRequestGatewayOverride,
            );
        },
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: clientSideSocket });
}

// =====================================================================
// 主入口
// =====================================================================

export default {
    async fetch(request, env, _ctx) {
        try {
            const requestUrl  = new URL(request.url);
            const requestPath = requestUrl.pathname;
            const isWebSocket = request.headers.get('Upgrade') === 'websocket';

            // 管理接口：运行时更新全局网关地址（仅非 WS 请求）
            if (requestPath.startsWith('/gateway=') && !isWebSocket) {
                try {
                    globalGatewayAddress = decodeURIComponent(requestPath.substring(9)).trim();
                } catch (_) {}
                return new Response(
                    `Gateway address updated to: ${globalGatewayAddress || '(direct)'}\n`,
                    { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } }
                );
            }

            // WebSocket 代理请求
            if (isWebSocket) {
                // 支持三种方式传入单请求网关覆盖：路径、查询参数、请求头
                let perRequestGateway = null;
                if (requestPath.startsWith('/gateway=')) {
                    try { perRequestGateway = decodeURIComponent(requestPath.substring(9)).trim(); } catch (_) {}
                }
                perRequestGateway = perRequestGateway
                    || requestUrl.searchParams.get('gateway')
                    || request.headers.get('X-Proxy-Gateway');

                return await handleWebSocketUpgrade(request, perRequestGateway);
            }

            // 非 WS 普通请求：返回伪装页面，规避 QIANG 主动探测和特征识别
            // QIANG 的主动探测器会对可疑端点发 HTTP GET，返回 404 会暴露代理特征
            return new Response(DECOY_PAGE_HTML, {
                status: 200,
                headers: {
                    'Content-Type':  'text/html; charset=utf-8',
                    'Cache-Control': 'no-store',
                    'Server':        'cloudflare',
                },
            });

        } catch (_unexpectedError) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};
