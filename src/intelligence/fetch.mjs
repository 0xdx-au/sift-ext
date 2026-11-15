import { verifyRelease } from './verify.mjs';

const BASE = 'https://admine.au/feeds/sift/';
const MAX_RELEASE = 8_000_000;
const MAX_PROOF = 2048;
const DEFAULT_TIMEOUT = 18000;

async function limitedFetch(url, limit, fetchImpl, signal) {
  const response = await fetchImpl(url, {
    method: 'GET', redirect: 'error', credentials: 'omit',
    cache: 'no-store', referrerPolicy: 'no-referrer',
    headers: { Accept: 'application/json' }, signal
  });
  if (!response || !response.ok || response.redirected || response.url !== url)
    throw new Error('SIFT: untrusted feed response');
  const contentType = (response.headers.get('content-type') || '').toLowerCase();
  if (!/^application\/json(?:\s*;|$)/.test(contentType))
    throw new Error('SIFT: wrong feed content type');
  const length = response.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > limit))
    throw new Error('SIFT: invalid declared byte length');
  if (!response.body?.getReader)
    throw new Error('SIFT: unsupported streaming response');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error('SIFT: malformed response stream');
      size += value.byteLength;
      if (size > limit) throw new Error('SIFT: feed byte limit exceeded');
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(()=>{});
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}
export async function acquireVerifiedRelease(pin, previous={}, opts={}) {
  if (!pin?.publicKeyBase64 || !pin.keyId)
    throw new Error('SIFT: production public key is not provisioned');
  const fetchImpl = opts.fetchImpl ?? fetch;
  if (typeof fetchImpl !== 'function') throw new Error('SIFT: fetch unavailable');
  const ctl = new AbortController();
  const timeout = setTimeout(() => ctl.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT);
  try {
    // The detached proof and payload can be independently cached. A mismatched pair
    // must fail signature verification; never retry with unchecked content.
    const [payload, proofBytes] = await Promise.all([
      limitedFetch(BASE+'current.json',MAX_RELEASE,fetchImpl,ctl.signal),
      limitedFetch(BASE+'current.sig.json',MAX_PROOF,fetchImpl,ctl.signal)
    ]);
    let proof;
    try { proof = new TextDecoder('utf-8',{fatal:true}).decode(proofBytes); }
    catch { throw new Error('SIFT: signature metadata encoding invalid'); }
    return await verifyRelease(payload,proof,pin,previous,opts.now ?? Date.now());
  } finally {
    clearTimeout(timeout);
    ctl.abort();
  }
}
