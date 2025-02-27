// Import our combined implementation
import { utils, sha256, encrypt, decrypt } from './combined.js';

// Keep the genVector function for the original test
function genVector(plaintext = 'abc') {
  let conversation_key = utils.randomBytes(32);
  let nonce = utils.randomBytes(32);
  let ciphertext = encrypt(plaintext, conversation_key, nonce);
  return { 
    conversation_key: utils.bytesToHex(conversation_key), 
    nonce: utils.bytesToHex(nonce), 
    p_sha: utils.bytesToHex(sha256(utils.utf8ToBytes(plaintext))), 
    c_sha: utils.bytesToHex(sha256(utils.utf8ToBytes(ciphertext)))
  }
}

// Test encryption and decryption with a short message
const testMessage = "Hello, NIP-44!";

// Generate random key and nonce
const conversation_key = utils.randomBytes(32);
const nonce = utils.randomBytes(32);

console.log("=== Test with combined.js implementation ===");
console.log("Original message:", testMessage);

// Encrypt the message
const ciphertext = encrypt(testMessage, conversation_key, nonce);
console.log("\nEncrypted message (first 50 chars):", ciphertext.substring(0, 50) + "...");

// Decrypt the message
try {
  const decrypted = decrypt(ciphertext, conversation_key);
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