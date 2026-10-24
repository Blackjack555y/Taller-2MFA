// TOTP (RFC 6238) implementado desde cero: SHA-1, HMAC, Base32 y truncamiento
// dinámico en JavaScript puro, sin librerías. Funciona 100% offline.

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input) {
  const clean = input.replace(/[\s=-]/g, '').toUpperCase();
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const value = BASE32_ALPHABET.indexOf(ch);
    if (value === -1) throw new Error(`Carácter Base32 inválido: "${ch}"`);
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

const rotl = (x, n) => (x << n) | (x >>> (32 - n));

export function sha1(message) {
  // Padding: 0x80, ceros y la longitud en bits (64 bits big-endian)
  const paddedLength = ((message.length + 9 + 63) >> 6) << 6;
  const data = new Uint8Array(paddedLength);
  data.set(message);
  data[message.length] = 0x80;
  const view = new DataView(data.buffer);
  const bitLength = message.length * 8;
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 2 ** 32));
  view.setUint32(paddedLength - 4, bitLength >>> 0);

  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);

  for (let block = 0; block < paddedLength; block += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(block + i * 4);
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const temp = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
      e = d; d = c; c = rotl(b, 30) >>> 0; b = a; a = temp;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }

  const digest = new Uint8Array(20);
  const out = new DataView(digest.buffer);
  [h0, h1, h2, h3, h4].forEach((h, i) => out.setUint32(i * 4, h));
  return digest;
}

const BLOCK_SIZE = 64;

export function hmacSha1(key, message) {
  if (key.length > BLOCK_SIZE) key = sha1(key);
  const k = new Uint8Array(BLOCK_SIZE);
  k.set(key);
  const inner = new Uint8Array(BLOCK_SIZE + message.length);
  const outer = new Uint8Array(BLOCK_SIZE + 20);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    inner[i] = k[i] ^ 0x36;
    outer[i] = k[i] ^ 0x5c;
  }
  inner.set(message, BLOCK_SIZE);
  outer.set(sha1(inner), BLOCK_SIZE);
  return sha1(outer);
}

export function hotp(key, counter, digits = 6) {
  // Contador como entero de 8 bytes big-endian
  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);

  const hash = hmacSha1(key, msg);
  // Truncamiento dinámico (RFC 4226 §5.3)
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    (hash[offset + 1] << 16) |
    (hash[offset + 2] << 8) |
    hash[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function totp(secretB32, { timeMs = Date.now(), period = 30, digits = 6 } = {}) {
  const counter = Math.floor(timeMs / 1000 / period);
  return hotp(base32Decode(secretB32), counter, digits);
}

// otpauth://totp/Issuer:cuenta?secret=XXXX&issuer=Issuer&period=30&digits=6
export function parseOtpauthUri(uri) {
  const match = /^otpauth:\/\/totp\/([^?]*)\?(.*)$/i.exec(uri.trim());
  if (!match) throw new Error('El QR no es una URI otpauth://totp/');
  const label = decodeURIComponent(match[1]);
  const params = {};
  for (const pair of match[2].split('&')) {
    const [k, v = ''] = pair.split('=');
    params[decodeURIComponent(k).toLowerCase()] = decodeURIComponent(v.replace(/\+/g, ' '));
  }
  if (!params.secret) throw new Error('La URI no trae el parámetro secret');
  if (params.algorithm && params.algorithm.toUpperCase() !== 'SHA1') {
    throw new Error(`Algoritmo no soportado: ${params.algorithm}`);
  }
  base32Decode(params.secret); // valida
  const [labelIssuer, account] = label.includes(':') ? label.split(/:(.*)/) : [null, label];
  return {
    secret: params.secret.replace(/\s/g, '').toUpperCase(),
    issuer: params.issuer || labelIssuer || 'Sin emisor',
    account: (account || label).trim(),
    period: Number(params.period) || 30,
    digits: Number(params.digits) || 6,
  };
}
