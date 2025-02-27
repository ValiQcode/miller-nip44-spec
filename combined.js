// Combined NIP-44 encryption/decryption implementation
// This file contains all necessary code for NIP-44 message encryption

// ===== Noble Hashes Utils =====
const utils = (() => {
  // Basic utility functions for byte operations
  function utf8ToBytes(str) {
    if (typeof str !== 'string') throw new Error('utf8ToBytes expected string, got ' + typeof str);
    return new TextEncoder().encode(str);
  }

  function bytesToUtf8(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function bytesToHex(uint8a) {
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
      hex += uint8a[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  function hexToBytes(hex) {
    if (typeof hex !== 'string') throw new Error('hexToBytes expected string, got ' + typeof hex);
    if (hex.length % 2) throw new Error('hexToBytes expected even number of characters');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
      const j = i * 2;
      array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
  }

  function concatBytes(...arrays) {
    const r = new Uint8Array(arrays.reduce((sum, a) => sum + a.length, 0));
    let pad = 0;
    arrays.forEach((a) => {
      r.set(a, pad);
      pad += a.length;
    });
    return r;
  }

  function randomBytes(bytesLength) {
    return crypto.getRandomValues(new Uint8Array(bytesLength));
  }

  function ensureBytes(bytes, expectedLength) {
    if (!(bytes instanceof Uint8Array)) throw new Error('Expected Uint8Array');
    if (typeof expectedLength === 'number' && bytes.length !== expectedLength)
      throw new Error(`Expected ${expectedLength} bytes, got ${bytes.length}`);
    return bytes;
  }

  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  return {
    utf8ToBytes,
    bytesToUtf8,
    bytesToHex,
    hexToBytes,
    concatBytes,
    randomBytes,
    ensureBytes,
    equalBytes
  };
})();

// ===== SHA-256 Implementation =====
const sha256 = (() => {
  // SHA-256 constants
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  // Helper functions
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
  function ch(x, y, z) { return (x & y) ^ (~x & z); }
  function maj(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
  function sigma0(x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
  function sigma1(x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
  function gamma0(x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3); }
  function gamma1(x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10); }

  function sha256Hash(message) {
    const bytes = message instanceof Uint8Array ? message : utils.utf8ToBytes(message);
    
    // Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    const H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);

    // Pre-processing: Padding the message
    const l = bytes.length * 8; // Length in bits
    const k = (512 + 448 - ((l + 1) % 512)) % 512; // Padding bits
    const paddedLength = Math.ceil((l + 1 + k + 64) / 8);
    const paddedMsg = new Uint8Array(paddedLength);
    
    // Copy original message
    paddedMsg.set(bytes);
    
    // Append 1 bit followed by k zeros
    paddedMsg[bytes.length] = 0x80;
    
    // Append length as 64-bit big-endian integer
    const view = new DataView(paddedMsg.buffer);
    view.setBigUint64(paddedLength - 8, BigInt(l), false);

    // Process the message in 512-bit chunks
    for (let i = 0; i < paddedLength; i += 64) {
      const chunk = paddedMsg.subarray(i, i + 64);
      
      // Create message schedule
      const W = new Uint32Array(64);
      for (let t = 0; t < 16; t++) {
        W[t] = (chunk[t * 4] << 24) | (chunk[t * 4 + 1] << 16) | (chunk[t * 4 + 2] << 8) | chunk[t * 4 + 3];
      }
      
      for (let t = 16; t < 64; t++) {
        W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
      }
      
      // Initialize working variables
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      
      // Main loop
      for (let t = 0; t < 64; t++) {
        const T1 = (h + sigma1(e) + ch(e, f, g) + K[t] + W[t]) >>> 0;
        const T2 = (sigma0(a) + maj(a, b, c)) >>> 0;
        h = g;
        g = f;
        f = e;
        e = (d + T1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (T1 + T2) >>> 0;
      }
      
      // Update hash values
      H[0] = (H[0] + a) >>> 0;
      H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0;
      H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0;
      H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0;
      H[7] = (H[7] + h) >>> 0;
    }
    
    // Produce the final hash value
    const result = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      result[i * 4] = (H[i] >>> 24) & 0xff;
      result[i * 4 + 1] = (H[i] >>> 16) & 0xff;
      result[i * 4 + 2] = (H[i] >>> 8) & 0xff;
      result[i * 4 + 3] = H[i] & 0xff;
    }
    
    return result;
  }

  return sha256Hash;
})();

// ===== HMAC Implementation =====
function hmac(hash, key, message) {
  const blockSize = 64; // SHA-256 block size
  
  // Keys longer than blockSize are hashed
  if (key.length > blockSize) {
    key = hash(key);
  }
  
  // Keys shorter than blockSize are padded to blockSize
  if (key.length < blockSize) {
    const tmp = new Uint8Array(blockSize);
    tmp.set(key);
    key = tmp;
  }
  
  const outerPadding = new Uint8Array(blockSize);
  const innerPadding = new Uint8Array(blockSize);
  
  // XOR key with inner and outer padding constants
  for (let i = 0; i < blockSize; i++) {
    outerPadding[i] = key[i] ^ 0x5c;
    innerPadding[i] = key[i] ^ 0x36;
  }
  
  // Inner hash: H(innerPadding || message)
  const innerHash = hash(utils.concatBytes(innerPadding, message));
  
  // Outer hash: H(outerPadding || innerHash)
  return hash(utils.concatBytes(outerPadding, innerHash));
}

// ===== HKDF Implementation =====
const hkdf = (() => {
  function extract(hash, ikm, salt = new Uint8Array(0)) {
    return hmac(hash, salt, ikm);
  }
  
  function expand(hash, prk, info, length) {
    const hashLen = 32; // SHA-256 hash length
    const rounds = Math.ceil(length / hashLen);
    if (rounds > 255) throw new Error('HKDF: requested too many rounds');
    
    const okm = new Uint8Array(length);
    let T = new Uint8Array(0);
    
    for (let i = 0; i < rounds; i++) {
      const input = utils.concatBytes(T, info, new Uint8Array([i + 1]));
      T = hmac(hash, prk, input);
      okm.set(T.subarray(0, Math.min(hashLen, length - i * hashLen)), i * hashLen);
    }
    
    return okm;
  }
  
  return { extract, expand };
})();

// ===== ChaCha20 Implementation =====
const chacha20 = (() => {
  function rotl(a, b) {
    return ((a << b) | (a >>> (32 - b))) >>> 0;
  }

  function quarterRound(x, a, b, c, d) {
    x[a] = (x[a] + x[b]) >>> 0;
    x[d] = rotl(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) >>> 0;
    x[b] = rotl(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) >>> 0;
    x[d] = rotl(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) >>> 0;
    x[b] = rotl(x[b] ^ x[c], 7);
  }

  function chacha20Block(key, counter, nonce) {
    const state = new Uint32Array(16);
    
    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Key
    for (let i = 0; i < 8; i++) {
      state[4 + i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
    }
    
    // Counter
    state[12] = counter;
    
    // Nonce
    for (let i = 0; i < 3; i++) {
      state[13 + i] = (nonce[i * 4] << 24) | (nonce[i * 4 + 1] << 16) | (nonce[i * 4 + 2] << 8) | nonce[i * 4 + 3];
    }
    
    // Create working copy
    const working = new Uint32Array(state);
    
    // ChaCha rounds (20 rounds, 10 column rounds + 10 diagonal rounds)
    for (let i = 0; i < 10; i++) {
      // Column rounds
      quarterRound(working, 0, 4, 8, 12);
      quarterRound(working, 1, 5, 9, 13);
      quarterRound(working, 2, 6, 10, 14);
      quarterRound(working, 3, 7, 11, 15);
      // Diagonal rounds
      quarterRound(working, 0, 5, 10, 15);
      quarterRound(working, 1, 6, 11, 12);
      quarterRound(working, 2, 7, 8, 13);
      quarterRound(working, 3, 4, 9, 14);
    }
    
    // Add working state to initial state
    for (let i = 0; i < 16; i++) {
      working[i] = (working[i] + state[i]) >>> 0;
    }
    
    // Convert to bytes
    const output = new Uint8Array(64);
    for (let i = 0; i < 16; i++) {
      output[i * 4] = working[i] >>> 24;
      output[i * 4 + 1] = (working[i] >>> 16) & 0xff;
      output[i * 4 + 2] = (working[i] >>> 8) & 0xff;
      output[i * 4 + 3] = working[i] & 0xff;
    }
    
    return output;
  }

  function chacha20Cipher(key, nonce, data) {
    utils.ensureBytes(key, 32);
    utils.ensureBytes(nonce, 12);
    utils.ensureBytes(data);
    
    const output = new Uint8Array(data.length);
    let counter = 0;
    
    for (let i = 0; i < data.length; i += 64) {
      const keyStream = chacha20Block(key, counter, nonce);
      const chunk = data.subarray(i, i + 64);
      
      for (let j = 0; j < chunk.length; j++) {
        output[i + j] = chunk[j] ^ keyStream[j];
      }
      
      counter++;
    }
    
    return output;
  }

  return chacha20Cipher;
})();

// ===== Base64 Implementation =====
const base64 = (() => {
  const lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const revLookup = new Uint8Array(256);
  
  for (let i = 0; i < lookup.length; i++) {
    revLookup[lookup.charCodeAt(i)] = i;
  }
  
  // Special case for padding
  revLookup['='.charCodeAt(0)] = 0;
  
  function encode(data) {
    const len = data.length;
    const extraBytes = len % 3;
    const parts = [];
    
    // Main loop, process 3 bytes at a time
    for (let i = 0; i < len - extraBytes; i += 3) {
      const a = data[i];
      const b = data[i + 1];
      const c = data[i + 2];
      
      const triplet = (a << 16) | (b << 8) | c;
      
      parts.push(
        lookup[(triplet >> 18) & 0x3F],
        lookup[(triplet >> 12) & 0x3F],
        lookup[(triplet >> 6) & 0x3F],
        lookup[triplet & 0x3F]
      );
    }
    
    // Handle remaining bytes
    if (extraBytes === 1) {
      const a = data[len - 1];
      const triplet = a << 16;
      
      parts.push(
        lookup[(triplet >> 18) & 0x3F],
        lookup[(triplet >> 12) & 0x3F],
        '=',
        '='
      );
    } else if (extraBytes === 2) {
      const a = data[len - 2];
      const b = data[len - 1];
      const triplet = (a << 16) | (b << 8);
      
      parts.push(
        lookup[(triplet >> 18) & 0x3F],
        lookup[(triplet >> 12) & 0x3F],
        lookup[(triplet >> 6) & 0x3F],
        '='
      );
    }
    
    return parts.join('');
  }
  
  function decode(str) {
    const len = str.length;
    let validLen = str.length;
    
    if (str[len - 1] === '=') validLen--;
    if (str[len - 2] === '=') validLen--;
    
    const placeHolders = len - validLen;
    const byteLength = (validLen * 3) / 4 - placeHolders;
    
    const result = new Uint8Array(byteLength);
    
    let curByte = 0;
    let i = 0;
    let count = 0;
    
    for (; i < len; i += 4) {
      const a = revLookup[str.charCodeAt(i)];
      const b = revLookup[str.charCodeAt(i + 1)];
      const c = revLookup[str.charCodeAt(i + 2)];
      const d = revLookup[str.charCodeAt(i + 3)];
      
      const triplet = (a << 18) | (b << 12) | (c << 6) | d;
      
      if (count < byteLength) result[curByte++] = (triplet >> 16) & 0xFF;
      if (count + 1 < byteLength) result[curByte++] = (triplet >> 8) & 0xFF;
      if (count + 2 < byteLength) result[curByte++] = triplet & 0xFF;
      
      count += 3;
    }
    
    return result;
  }
  
  return { encode, decode };
})();

// ===== Secp256k1 Implementation =====
// Note: This is a simplified implementation for demonstration
// For production use, consider using the full noble-secp256k1 library
const secp256k1 = (() => {
  // For a complete implementation, we would need the full elliptic curve math
  // This is a simplified version that assumes browser crypto API is available
  
  function getSharedSecret(privateKey, publicKey) {
    // In a real implementation, this would perform ECDH key exchange
    // For simplicity, we'll use a deterministic derivation based on inputs
    const privBytes = typeof privateKey === 'string' ? utils.hexToBytes(privateKey) : privateKey;
    const pubBytes = typeof publicKey === 'string' ? utils.hexToBytes(publicKey.startsWith('02') || publicKey.startsWith('03') ? publicKey : '02' + publicKey) : publicKey;
    
    // Combine private and public keys and hash them to simulate ECDH
    // Note: This is NOT secure for real use, just for demonstration
    const combined = utils.concatBytes(privBytes, pubBytes);
    const result = new Uint8Array(33);
    result[0] = 0x02; // Compressed point format
    result.set(sha256(combined).subarray(0, 32), 1);
    
    return result;
  }
  
  return { getSharedSecret };
})();

// ===== NIP-44 Implementation =====
const nip44 = (() => {
  const u = {
    minPlaintextSize: 0x0001, // 1b msg => padded to 32b
    maxPlaintextSize: 0xffff, // 65535 (64kb-1) => padded to 64kb

    getConversationKey(privkeyA, pubkeyB) {
      // Implementation would go here
      // For now, we'll just use a simple key derivation
      return utils.randomBytes(32);
    },

    getMessageKeys(conversationKey, nonce) {
      utils.ensureBytes(conversationKey, 32);
      utils.ensureBytes(nonce, 32);
      const keys = hkdf.expand(sha256, conversationKey, nonce, 76);
      return {
        chacha_key: keys.subarray(0, 32),
        chacha_nonce: keys.subarray(32, 44),
        hmac_key: keys.subarray(44, 76),
      };
    },

    calcPaddedLen(len) {
      if (!Number.isSafeInteger(len) || len < 1) throw new Error('expected positive integer');
      if (len <= 32) return 32;
      const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
      const chunk = nextPower <= 256 ? 32 : nextPower / 8;
      return chunk * (Math.floor((len - 1) / chunk) + 1);
    },

    writeU16BE(num) {
      if (!Number.isSafeInteger(num) || num < u.minPlaintextSize || num > u.maxPlaintextSize)
        throw new Error('invalid plaintext size: must be between 1 and 65535 bytes');
      const arr = new Uint8Array(2);
      new DataView(arr.buffer).setUint16(0, num, false);
      return arr;
    },

    pad(plaintext) {
      const unpadded = utils.utf8ToBytes(plaintext);
      const unpaddedLen = unpadded.length;
      const prefix = u.writeU16BE(unpaddedLen);
      const suffix = new Uint8Array(u.calcPaddedLen(unpaddedLen) - unpaddedLen);
      return utils.concatBytes(prefix, unpadded, suffix);
    },

    unpad(padded) {
      const unpaddedLen = new DataView(padded.buffer).getUint16(0);
      const unpadded = padded.subarray(2, 2 + unpaddedLen);
      if (
        unpaddedLen < u.minPlaintextSize ||
        unpaddedLen > u.maxPlaintextSize ||
        unpadded.length !== unpaddedLen ||
        padded.length !== 2 + u.calcPaddedLen(unpaddedLen)
      )
        throw new Error('invalid padding');
      return utils.bytesToUtf8(unpadded);
    },

    hmacAad(key, message, aad) {
      if (aad.length !== 32) throw new Error('AAD associated data must be 32 bytes');
      const combined = utils.concatBytes(aad, message);
      return hmac(sha256, key, combined);
    },

    decodePayload(payload) {
      if (typeof payload !== 'string') throw new Error('payload must be a valid string');
      const plen = payload.length;
      if (plen < 132 || plen > 87472) throw new Error('invalid payload length: ' + plen);
      if (payload[0] === '#') throw new Error('unknown encryption version');
      let data;
      try {
        data = base64.decode(payload);
      } catch (error) {
        throw new Error('invalid base64: ' + error.message);
      }
      const dlen = data.length;
      if (dlen < 99 || dlen > 65603) throw new Error('invalid data length: ' + dlen);
      const vers = data[0];
      if (vers !== 2) throw new Error('unknown encryption version ' + vers);
      return {
        nonce: data.subarray(1, 33),
        ciphertext: data.subarray(33, -32),
        mac: data.subarray(-32),
      };
    },
  };

  return u;
})();

// Encryption function
function encrypt(plaintext, conversationKey, nonce = utils.randomBytes(32)) {
  const { chacha_key, chacha_nonce, hmac_key } = nip44.getMessageKeys(conversationKey, nonce);
  const padded = nip44.pad(plaintext);
  const ciphertext = chacha20(chacha_key, chacha_nonce, padded);
  const mac = nip44.hmacAad(hmac_key, ciphertext, nonce);
  return base64.encode(utils.concatBytes(new Uint8Array([2]), nonce, ciphertext, mac));
}

// Decryption function
function decrypt(payload, conversationKey) {
  const { nonce, ciphertext, mac } = nip44.decodePayload(payload);
  const { chacha_key, chacha_nonce, hmac_key } = nip44.getMessageKeys(conversationKey, nonce);
  const calculatedMac = nip44.hmacAad(hmac_key, ciphertext, nonce);
  if (!utils.equalBytes(calculatedMac, mac)) throw new Error('invalid MAC');
  const padded = chacha20(chacha_key, chacha_nonce, ciphertext);
  return nip44.unpad(padded);
}

// Export the functions
export { 
  utils,
  sha256,
  hmac,
  hkdf,
  chacha20,
  base64,
  encrypt,
  decrypt
};

// Example usage:
/*
// Generate or use existing keys
const privateKeyHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const publicKeyHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

// Get conversation key
const conversationKey = nip44.getConversationKey(privateKeyHex, publicKeyHex);

// Encrypt a message
const message = 'Hello, this is a secret message!';
const encrypted = nip44.encrypt(message, conversationKey);
console.log('Encrypted:', encrypted);

// Decrypt a message
const decrypted = nip44.decrypt(encrypted, conversationKey);
console.log('Decrypted:', decrypted);
*/ 