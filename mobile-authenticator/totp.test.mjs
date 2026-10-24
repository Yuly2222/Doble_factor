// node totp.test.mjs  — vectores oficiales RFC 6238 (SHA1) / RFC 2202 (HMAC-SHA1)
import assert from 'node:assert/strict';
import { base32Decode, hmacSha1, totp } from './totp.js';

const hex = (b) => Buffer.from(b).toString('hex');
const key = new TextEncoder().encode('12345678901234567890');

assert.equal(hex(hmacSha1(new TextEncoder().encode('Jefe'), new TextEncoder().encode('what do ya want for nothing?'))),
  'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79');
assert.equal(hex(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')), hex(key));
for (const [t, code] of [[59, '287082'], [1111111109, '081804'], [1234567890, '005924'], [2000000000, '279037'], [20000000000, '353130']]) {
  assert.equal(totp(key, t), code, `T=${t}`);
}
console.log('TOTP OK (RFC 6238)');
