/*
 * Criptografia da configuração pelo celular (usada pela TV e pela página do celular, web/setup.html).
 * A chave vai só no QR Code (depois do #, não chega a servidor nenhum); o recado passa pelo ntfy.sh já cifrado.
 * Cifra: fluxo SHA-256(chave | nonce | contador) XOR texto, com selo SHA-256(chave | nonce | cifrado) de 16 bytes.
 * Escrito à mão porque a TV (Chromium 53, página local) e o celular em http não têm crypto.subtle garantido.
 */
var PairCrypto = (function () {
  'use strict';
  var K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
    0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

  // bytes (array de números) -> 32 bytes
  function sha256(msg) {
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var m = msg.slice(), l = msg.length * 8;
    m.push(0x80);
    while (m.length % 64 !== 56) m.push(0);
    for (var s = 7; s >= 0; s--) m.push(s >= 4 ? 0 : (l >>> (s * 8)) & 0xff);
    var w = new Array(64);
    for (var o = 0; o < m.length; o += 64) {
      for (var i = 0; i < 16; i++) w[i] = (m[o + i * 4] << 24) | (m[o + i * 4 + 1] << 16) | (m[o + i * 4 + 2] << 8) | m[o + i * 4 + 3];
      for (i = 16; i < 64; i++) {
        var a = w[i - 15], b = w[i - 2];
        var s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        var s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      var A = h[0], B = h[1], C = h[2], D = h[3], E = h[4], F = h[5], G = h[6], H = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = ((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7));
        var t1 = (H + S1 + ((E & F) ^ (~E & G)) + K[i] + w[i]) | 0;
        var S0 = ((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10));
        var t2 = (S0 + ((A & B) ^ (A & C) ^ (B & C))) | 0;
        H = G; G = F; F = E; E = (D + t1) | 0; D = C; C = B; B = A; A = (t1 + t2) | 0;
      }
      h[0] = (h[0] + A) | 0; h[1] = (h[1] + B) | 0; h[2] = (h[2] + C) | 0; h[3] = (h[3] + D) | 0;
      h[4] = (h[4] + E) | 0; h[5] = (h[5] + F) | 0; h[6] = (h[6] + G) | 0; h[7] = (h[7] + H) | 0;
    }
    var out = [];
    h.forEach(function (x) { out.push((x >>> 24) & 0xff, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff); });
    return out;
  }

  function utf8(s) { var b = unescape(encodeURIComponent(s)), o = []; for (var i = 0; i < b.length; i++) o.push(b.charCodeAt(i)); return o; }
  function unutf8(a) { var s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return decodeURIComponent(escape(s)); }
  function hex(a) { return a.map(function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join(''); }
  function unhex(h) { var o = []; for (var i = 0; i + 1 < h.length; i += 2) o.push(parseInt(h.substr(i, 2), 16)); return o; }
  function b64(a) { var s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
  function unb64(s) { var b = atob(s), o = []; for (var i = 0; i < b.length; i++) o.push(b.charCodeAt(i)); return o; }

  function random(n) {
    var a = new Uint8Array(n);
    (window.crypto || window.msCrypto).getRandomValues(a);
    return Array.prototype.slice.call(a);
  }

  function stream(key, nonce, n) {
    var out = [];
    for (var c = 0; out.length < n; c++) out = out.concat(sha256(key.concat(nonce, [c >>> 24 & 255, c >>> 16 & 255, c >>> 8 & 255, c & 255])));
    return out.slice(0, n);
  }

  function seal(keyHex, text) {
    var key = unhex(keyHex), nonce = random(12), pt = utf8(text), ks = stream(key, nonce, pt.length);
    var ct = pt.map(function (x, i) { return x ^ ks[i]; });
    var mac = sha256(key.concat(nonce, ct)).slice(0, 16);
    return b64(nonce.concat(ct, mac));
  }

  // devolve o texto, ou null se a chave não confere (recado de outra TV ou adulterado)
  function open(keyHex, msg) {
    try {
      var key = unhex(keyHex), all = unb64(msg);
      if (all.length < 29) return null;
      var nonce = all.slice(0, 12), ct = all.slice(12, all.length - 16), mac = all.slice(all.length - 16);
      if (hex(sha256(key.concat(nonce, ct)).slice(0, 16)) !== hex(mac)) return null;
      var ks = stream(key, nonce, ct.length);
      return unutf8(ct.map(function (x, i) { return x ^ ks[i]; }));
    } catch (e) { return null; }
  }

  return { sha256: sha256, seal: seal, open: open, random: random, hex: hex };
})();
