// TOTP RFC 6238 desde cero: Base32 + SHA-1 + HMAC + truncamiento dinámico. Sin librerías.

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input) {
  const s = input.replace(/[\s=-]/g, '').toUpperCase();
  const out = [];
  let bits = 0, value = 0;
  for (const ch of s) {
    const i = B32.indexOf(ch);
    if (i < 0) throw new Error(`Carácter Base32 inválido: ${ch}`);
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }
  return Uint8Array.from(out);
}

const rotl = (x, n) => (x << n) | (x >>> (32 - n));

export function sha1(msg) {
  const len = msg.length;
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(msg);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor((len * 8) / 2 ** 32));
  dv.setUint32(padded.length - 4, (len * 8) >>> 0);

  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const t = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
      e = d; d = c; c = rotl(b, 30) >>> 0; b = a; a = t;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }
  const out = new Uint8Array(20);
  const odv = new DataView(out.buffer);
  [h0, h1, h2, h3, h4].forEach((h, i) => odv.setUint32(i * 4, h));
  return out;
}

export function hmacSha1(key, msg) {
  if (key.length > 64) key = sha1(key);
  const ipad = new Uint8Array(64 + msg.length);
  const opad = new Uint8Array(64 + 20);
  for (let i = 0; i < 64; i++) {
    const k = key[i] ?? 0;
    ipad[i] = k ^ 0x36;
    opad[i] = k ^ 0x5c;
  }
  ipad.set(msg, 64);
  opad.set(sha1(ipad), 64);
  return sha1(opad);
}

export const PERIOD = 30;

export function hotp(key, counter) {
  const msg = new Uint8Array(8); // contador de 64 bits Big-Endian
  const dv = new DataView(msg.buffer);
  dv.setUint32(0, Math.floor(counter / 2 ** 32));
  dv.setUint32(4, counter >>> 0);
  const hash = hmacSha1(key, msg);
  const offset = hash[19] & 0x0f;
  const value =
    ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
  return String(value % 1_000_000).padStart(6, '0');
}

export function totp(key, unixSeconds = Date.now() / 1000) {
  return hotp(key, Math.floor(unixSeconds / PERIOD));
}
