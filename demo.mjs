import { v2 } from './lib/index.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';

// Keep the genVector function for the original test
function genVector(plaintext = 'abc') {
  let conversation_key = randomBytes(32);
  let nonce = randomBytes(32);
  let ciphertext = v2.encrypt(plaintext, conversation_key, nonce);
  return { 
    conversation_key: bytesToHex(conversation_key), 
    nonce: bytesToHex(nonce), 
    p_sha: bytesToHex(sha256(plaintext)), 
    c_sha: bytesToHex(sha256(ciphertext))
  }
}

// Test encryption and decryption with a short message
const testMessage = "Hello, NIP-44!";

// Generate random key and nonce
const conversation_key = randomBytes(32);
const nonce = randomBytes(32);

console.log("=== Test with original library ===");
console.log("Original message:", testMessage);

// Encrypt the message
const ciphertext = v2.encrypt(testMessage, conversation_key, nonce);
console.log("\nEncrypted message (first 50 chars):", ciphertext.substring(0, 50) + "...");

// Decrypt the message
try {
  const decrypted = v2.decrypt(ciphertext, conversation_key);
  console.log("\nDecryption successful!");
  console.log("Decrypted message:", decrypted);
  console.log("Messages match:", decrypted === testMessage);
} catch (error) {
  console.error("\nDecryption failed:", error.message);
}

// Run the original test with many unicorns (but don't print the full output)
console.log("\n=== Original Test with 16383 unicorns ===");
const unicornVector = genVector('🦄'.repeat(16383));
console.log("Encryption of 16383 unicorns successful!");
console.log("Conversation key:", unicornVector.conversation_key.substring(0, 20) + "...");
console.log("Nonce:", unicornVector.nonce.substring(0, 20) + "...");