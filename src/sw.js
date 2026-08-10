/*
 * Dill Share streaming-preview service worker.
 *
 * Intercepts URLs of the form:
 *     /preview-stream/<uuid>/<fileId>
 * and returns decrypted plaintext byte ranges on demand, so a <video>/<audio>
 * element can begin playback immediately while the rest of the file is still
 * being fetched and decrypted from the server.
 *
 * The page supplies the decryption key, file metadata (size, chunked flag,
 * content type) and the upstream encrypted file URL via postMessage before
 * loading the media element's src. This works for ANY media container
 * (mp4, mkv, webm, mov, mp3, wav, flac, opus, aac, m4a, ...) because the
 * browser's media engine performs standard HTTP range requests against this
 * virtual URL; the SW transparently decrypts the requested byte range.
 *
 * Encryption formats supported (mirrors the page crypto):
 *   - Chunked AES-GCM: file is N chunks. Each chunk = IV(12) || ct+tag.
 *     Chunk i covers plaintext [i*CHUNK_SIZE, min((i+1)*CHUNK_SIZE, totalSize)).
 *     Ciphertext chunk boundaries are derived from the known total plaintext
 *     size, so a plaintext byte range maps to a known set of ciphertext chunks.
 *   - Legacy single-block AES-GCM: IV(12) || ct+tag for the whole file.
 *     For this format we decrypt the entire file once (caching it) the first
 *     time a range is requested, because individual byte ranges cannot be
 *     decrypted independently of the surrounding GCM tag.
 */

const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB plaintext per chunk (matches page)
const STREAM_PREFIX = '/preview-stream/';
const DOWNLOAD_PREFIX = '/sw-download/';

// Map<fileKey, { key, size, chunked, ctSize, contentType, url, cached: Uint8Array|null }>
const files = new Map();
const downloadStreams = new Map();

function ctSizeFor(totalPlain, chunked) {
    if (!chunked) return null; // unknown without fetching; handled lazily
    const n = Math.max(1, Math.ceil(totalPlain / CHUNK_SIZE));
    // each chunk: 12 + (plain + 16)
    let total = 0;
    let rem = totalPlain;
    for (let i = 0; i < n; i++) {
        const thisPlain = Math.min(CHUNK_SIZE, rem);
        total += 12 + thisPlain + 16;
        rem -= thisPlain;
    }
    return total;
}

// Plain byte range [start, end) -> set of chunk descriptors to fetch+decrypt.
// AES-GCM cannot decrypt a partial ciphertext: each chunk's full block
// (IV(12) + ct(plainLen + 16)) must be fetched and decrypted as a unit, then
// the requested plaintext sub-slice is extracted from the decrypted result.
function plainRangeToCtRanges(start, end, totalPlain) {
    const firstChunk = Math.floor(start / CHUNK_SIZE);
    const lastChunk = Math.floor((end - 1) / CHUNK_SIZE);
    const ranges = [];
    let cursor = 0; // ciphertext offset
    let rem = totalPlain;
    for (let i = 0; i <= lastChunk; i++) {
        const thisPlain = Math.min(CHUNK_SIZE, rem);
        const blockLen = 12 + thisPlain + 16; // IV + ct + tag
        if (i >= firstChunk) {
            const plainStartInChunk = (i === firstChunk) ? (start - i * CHUNK_SIZE) : 0;
            const plainEndInChunk = (i === lastChunk) ? (end - i * CHUNK_SIZE) : thisPlain;
            // Fetch the entire chunk block so the GCM tag is included.
            ranges.push({
                chunkIndex: i,
                plainStartInChunk,
                plainEndInChunk,
                fetchStart: cursor,                 // start of IV
                fetchEnd: cursor + blockLen,        // end of tag (exclusive)
                ivStart: cursor,
                ctStart: cursor + 12,
                ctLen: thisPlain + 16,
            });
        }
        cursor += blockLen;
        rem -= thisPlain;
    }
    return ranges;
}

async function decryptChunk(ivBytes, ctBytes, key) {
    return new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBytes },
        key,
        ctBytes
    ));
}

async function importKeyFromRaw(rawBuf) {
    return crypto.subtle.importKey('raw', rawBuf, { name: 'AES-GCM' }, false, ['decrypt']);
}

self.addEventListener('message', async (event) => {
    const d = event.data;
    if (!d) return;
    if (d.type === 'DILL_DOWNLOAD_INIT') {
        const port = event.ports && event.ports[0];
        if (!port) return;
        const streamPath = d.streamPath;
        const filename = d.filename || 'download';
        const size = d.size;
        const contentType = d.contentType || 'application/octet-stream';

        const readable = new ReadableStream({
            start(controller) {
                port.onmessage = (evt) => {
                    if (evt.data === 'end') {
                        try { controller.close(); } catch (_) {}
                    } else if (evt.data === 'abort') {
                        try { controller.error(new Error('Download aborted')); } catch (_) {}
                    } else if (evt.data instanceof Uint8Array || ArrayBuffer.isView(evt.data)) {
                        const u8 = new Uint8Array(evt.data.buffer, evt.data.byteOffset, evt.data.byteLength);
                        try { controller.enqueue(u8); } catch (_) {}
                    }
                };
            },
            cancel(reason) {
                try { port.postMessage('cancel'); } catch (_) {}
            }
        });

        downloadStreams.set(streamPath, { readable, filename, size, contentType });
        if (event.source) event.source.postMessage({ type: 'DILL_DOWNLOAD_READY', streamPath });
        return;
    }
    if (d.type === 'DILL_PREVIEW_INIT') {
        console.log('[dill-sw] INIT received for', d.streamPath, 'chunked=', d.chunked, 'size=', d.size);
        try {
            if (files.size >= 5) {
                const firstKey = files.keys().next().value;
                files.delete(firstKey);
            }
            const key = await importKeyFromRaw(d.keyRaw);
            const entry = {
                key,
                size: d.size,
                chunked: !!d.chunked,
                ctSize: d.chunked ? ctSizeFor(d.size, true) : null,
                contentType: d.contentType || 'application/octet-stream',
                url: d.url,
                authUrl: d.authUrl || null,
                urlRefresh: null,
                cached: null, // only used for legacy single-block format
                chunkCache: new Map(), // Map<chunkIndex, Promise<Uint8Array>>
            };
            files.set(d.streamPath, entry);
            console.log('[dill-sw] INIT ok, replying READY');
            if (event.source) event.source.postMessage({ type: 'DILL_PREVIEW_READY', streamPath: d.streamPath });
        } catch (e) {
            console.error('[dill-sw] INIT error:', e);
            if (event.source) event.source.postMessage({ type: 'DILL_PREVIEW_READY', streamPath: d.streamPath, error: String(e) });
        }
        return;
    }
});

self.addEventListener('install', (event) => {
    // Activate immediately instead of waiting for all tabs to be closed.
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    // Take control of all open clients immediately so the current page's
    // media-element range requests get intercepted without a reload.
    event.waitUntil(
        self.clients.claim().then(() => {
            return self.clients.matchAll({ includeUncontrolled: true, type: 'window' });
        }).then((clients) => {
            for (const c of clients) {
                c.postMessage({ type: 'DILL_SW_ACTIVE' });
            }
        }).catch((e) => {
            console.error('sw activate error:', e);
        })
    );
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    if (url.pathname.startsWith(DOWNLOAD_PREFIX)) {
        event.respondWith(handleDownloadStream(url.pathname));
        return;
    }
    if (!url.pathname.startsWith(STREAM_PREFIX)) return;
    console.log('[dill-sw] fetch intercept:', event.request.method, url.pathname, 'range=', event.request.headers.get('Range'));
    event.respondWith(handleStream(event.request, url.pathname));
});

function handleDownloadStream(streamPath) {
    const entry = downloadStreams.get(streamPath);
    if (!entry) {
        return new Response('Download stream not found or expired', { status: 404 });
    }
    downloadStreams.delete(streamPath);
    const filename = entry.filename;
    const encodedFilename = encodeURIComponent(filename).replace(/['()]/g, escape).replace(/\*/g, '%2A');
    const headers = new Headers({
        'Content-Type': entry.contentType || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${encodedFilename}"; filename*=UTF-8''${encodedFilename}`,
        'Cache-Control': 'no-cache, no-store'
    });
    if (typeof entry.size === 'number' && entry.size > 0) {
        headers.set('Content-Length', String(entry.size));
    }
    return new Response(entry.readable, { headers });
}

async function handleStream(request, streamPath) {
    console.log('[dill-sw] handleStream', streamPath, 'has meta:', files.has(streamPath));
    const meta = files.get(streamPath);
    if (!meta) {
        console.error('[dill-sw] handleStream: no meta for', streamPath);
        return new Response('Preview stream not initialized', { status: 503 });
    }

    // Determine the plaintext range requested.
    const total = meta.size;

    // HEAD-like request without range: return 200 + full size, no body needed for media probe.
    if (request.method === 'HEAD') {
        return new Response(null, {
            status: 200,
            headers: headHeaders(meta, total),
        });
    }

    const rangeHeader = request.headers.get('Range');
    let start = 0;
    let end = total; // exclusive
    let isRange = false;
    if (rangeHeader && rangeHeader.startsWith('bytes=')) {
        const spec = rangeHeader.slice(6).split(',')[0].trim();
        // Support byte ranges, open-ended ranges and suffix ranges
        // (e.g. "bytes=0-99", "bytes=100-", "bytes=-500").
        const suffix = /^-(\d+)$/.exec(spec);
        const full = /^(\d+)-(\d*)$/.exec(spec);
        if (suffix) {
            const n = parseInt(suffix[1], 10);
            if (n > 0) {
                start = Math.max(0, total - n);
                end = total;
                isRange = true;
            }
        } else if (full) {
            start = parseInt(full[1], 10);
            if (full[2] !== '') {
                end = parseInt(full[2], 10) + 1; // inclusive->exclusive
            } else {
                end = total;
            }
            isRange = true;
        }
    }
    if (end > total) end = total;
    if (start > end) start = end;

    try {
        if (meta.chunked) {
            return await respondChunkedRange(meta, start, end, isRange);
        } else {
            return await respondLegacyRange(meta, start, end, isRange, total);
        }
    } catch (e) {
        return new Response('Decryption error: ' + e, { status: 500 });
    }
}

function headHeaders(meta, total) {
    const h = {
        'Content-Type': meta.contentType,
        'Accept-Ranges': 'bytes',
        'Content-Length': String(total),
        'Cache-Control': 'no-store',
    };
    return h;
}

async function refreshUpstreamUrl(meta) {
    if (!meta.authUrl) return meta.url;
    if (!meta.urlRefresh) {
        meta.urlRefresh = (async () => {
            const response = await fetch(meta.authUrl, { cache: 'no-store' });
            if (!response.ok) throw new Error('Download authorization failed: ' + response.status);
            const signed = await response.json();
            if (!signed.url) throw new Error('Download authorization returned no URL');
            meta.url = signed.url;
            return meta.url;
        })().finally(() => {
            meta.urlRefresh = null;
        });
    }
    return await meta.urlRefresh;
}

async function getDecryptedChunk(meta, r, signal) {
    if (!meta.chunkCache) {
        meta.chunkCache = new Map();
    }
    const idx = r.chunkIndex;
    if (meta.chunkCache.has(idx)) {
        try {
            return await meta.chunkCache.get(idx);
        } catch (e) {
            meta.chunkCache.delete(idx);
        }
    }

    const promise = (async () => {
        const fetchOpts = {
            headers: { Range: `bytes=${r.fetchStart}-${r.fetchEnd - 1}` }
        };
        if (signal) fetchOpts.signal = signal;
        let res = await fetch(meta.url, fetchOpts);
        if ((res.status === 401 || res.status === 403) && meta.authUrl) {
            await refreshUpstreamUrl(meta);
            res = await fetch(meta.url, fetchOpts);
        }
        if (res.status !== 206) {
            throw new Error('S3 did not honor the requested byte range: ' + res.status);
        }
        const buf = new Uint8Array(await res.arrayBuffer());
        const expectedLength = r.fetchEnd - r.fetchStart;
        const expectedContentRange = `bytes ${r.fetchStart}-${r.fetchEnd - 1}/${meta.ctSize}`;
        if (res.headers.get('Content-Range') !== expectedContentRange || buf.length !== expectedLength) {
            throw new Error('S3 returned an invalid encrypted byte range');
        }
        const iv = buf.subarray(0, 12);
        const ct = buf.subarray(12, 12 + r.ctLen);
        return await decryptChunk(iv, ct, meta.key);
    })();

    meta.chunkCache.set(idx, promise);
    // Bound the cache: a long playback session would otherwise accumulate one
    // entry per 4MB chunk forever. Evict the oldest entries when we exceed the
    // cap; completed (non-in-flight) promises are dropped harmlessly.
    if (meta.chunkCache.size > 48) {
        for (const k of meta.chunkCache.keys()) {
            if (meta.chunkCache.size <= 32) break;
            if (k !== idx) meta.chunkCache.delete(k);
        }
    }

    try {
        return await promise;
    } catch (err) {
        meta.chunkCache.delete(idx);
        throw err;
    }
}

async function respondChunkedRange(meta, start, end, isRange) {
    // Requested range is entirely past EOF: report 416 like a real server so
    // media players stop probing instead of waiting forever.
    if (isRange && meta.size > 0 && start >= meta.size) {
        return new Response(null, {
            status: 416,
            headers: {
                'Accept-Ranges': 'bytes',
                'Content-Range': `bytes */${meta.size}`,
                'Content-Length': '0',
                'Cache-Control': 'no-store',
            }
        });
    }
    const ranges = plainRangeToCtRanges(start, end, meta.size);
    const totalLength = end - start;
    const status = isRange ? 206 : 200;
    const headers = {
        'Content-Type': meta.contentType,
        'Accept-Ranges': 'bytes',
        'Content-Length': String(totalLength),
        'Cache-Control': 'no-store',
    };
    if (isRange) {
        headers['Content-Range'] = `bytes ${start}-${end - 1}/${meta.size}`;
    }

    // Zero-length request (e.g. a probe at EOF): nothing to fetch or decrypt.
    if (totalLength <= 0 || ranges.length === 0) {
        return new Response(null, { status, headers });
    }

    console.log('[dill-sw] respondChunkedRange:', start, '-', end, 'len', totalLength, 'status', status, 'chunks', ranges.length, 'ct', meta.contentType);

    // Pipelined prefetch: kick off decryption of the next chunk while the
    // current one is being streamed to the media element. getDecryptedChunk
    // deduplicates via the chunk cache (Map of in-flight promises), so firing a
    // prefetch is safe even if the consumer later requests the same chunk.
    // This overlaps the network fetch + AES-GCM decrypt of chunk N+1 with the
    // enqueue/playback of chunk N, eliminating the chunk-by-chunk stalls that
    // made playback choppy ("start and stop") even on excellent connections.
    const PREFETCH_AHEAD = 3;
    let aborted = false;
    const streamAc = new AbortController();
    let chunkIndex = 0;

    // Prime the pipeline: start the first PREFETCH_AHEAD fetches immediately so
    // they are already in flight before we begin yielding anything.
    for (let i = 0; i < Math.min(PREFETCH_AHEAD, ranges.length); i++) {
        getDecryptedChunk(meta, ranges[i], streamAc.signal);
    }

    const stream = new ReadableStream({
        async start(controller) {
            try {
                for (let i = 0; i < ranges.length; i++) {
                    if (aborted) break;
                    if (controller.desiredSize === null) break;

                    // Start fetching the chunk PREFETCH_AHEAD positions ahead so
                    // its network round-trip overlaps the current chunk's decrypt.
                    if (i + PREFETCH_AHEAD < ranges.length) {
                        getDecryptedChunk(meta, ranges[i + PREFETCH_AHEAD], streamAc.signal);
                    }

                    const pt = await getDecryptedChunk(meta, ranges[i], streamAc.signal);
                    if (aborted || controller.desiredSize === null) break;

                    const piece = pt.subarray(ranges[i].plainStartInChunk, ranges[i].plainEndInChunk);
                    if (piece.length > 0) {
                        try { controller.enqueue(piece); }
                        catch (_) { break; } // stream closed by consumer mid-enqueue
                    }
                    console.log('[dill-sw] enqueued chunk', chunkIndex++, 'len', piece.length);
                }
                if (!aborted && controller.desiredSize !== null) {
                    controller.close();
                    console.log('[dill-sw] stream closed, all chunks sent');
                }
            } catch (err) {
                if (err.name !== 'AbortError') {
                    console.error('[dill-sw] stream error:', err);
                }
                try { controller.error(err); } catch (_) {}
            }
        },
        cancel() {
            aborted = true;
            try { streamAc.abort(); } catch (_) {}
        }
    });

    return new Response(stream, { status, headers });
}

async function respondLegacyRange(meta, start, end, isRange, total) {
    // Legacy single-block format: must decrypt the whole file once, then slice.
    if (!meta.cached) {
        let res = await fetch(meta.url);
        if ((res.status === 401 || res.status === 403) && meta.authUrl) {
            await refreshUpstreamUrl(meta);
            res = await fetch(meta.url);
        }
        if (!res.ok) throw new Error('Upstream fetch failed: ' + res.status);
        const ab = await res.arrayBuffer();
        const data = new Uint8Array(ab);
        const iv = data.subarray(0, 12);
        const ct = data.subarray(12);
        const pt = await decryptChunk(iv, ct, meta.key);
        meta.cached = pt;
    }
    const slice = meta.cached.subarray(start, end);
    const status = isRange ? 206 : 200;
    const headers = {
        'Content-Type': meta.contentType,
        'Accept-Ranges': 'bytes',
        'Content-Length': String(slice.length),
        'Cache-Control': 'no-store',
    };
    if (isRange) {
        headers['Content-Range'] = `bytes ${start}-${start + slice.length - 1}/${total}`;
    }
    return new Response(slice, { status, headers });
}
