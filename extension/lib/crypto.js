/**
 * Zero-knowledge vault crypto (Phase 8, Task 8.3).
 *
 * Original implementation using the browser's native Web Crypto API
 * (AES-GCM + PBKDF2) -- NOT ported from Aegis's mask.ts, which PHASE_GUIDE.md
 * suggested reusing. That's unavailable: Aegis carries no license (DEC-020),
 * and that reasoning extends to every Aegis file, not just the extension
 * shell. This uses only standard, browser-audited crypto primitives (no
 * hand-rolled cipher), which is the safe way to avoid "reinventing crypto"
 * without copying code.
 *
 * The server never sees a password, a derived key, or plaintext -- only the
 * opaque blob this module produces. See src/api/vault/ (S10).
 */

const SALT_BYTES = 16;
const IV_BYTES = 12;
const PBKDF2_ITERATIONS = 250_000;

/**
 * Derive an AES-GCM key from a password and salt via PBKDF2.
 * @param {string} password - The vault master password. Never sent to the server.
 * @param {Uint8Array} salt
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encrypt a JSON-serializable value into a single opaque base64 blob.
 *
 * The blob packs salt || iv || ciphertext together so the server only ever
 * has to store/return one string (S10) -- it has no way to separate or
 * interpret the pieces, and neither the salt nor iv are secret (only the
 * password is, and it's never sent).
 *
 * @param {unknown} value - Any JSON-serializable vault contents.
 * @param {string} password - The vault master password.
 * @returns {Promise<string>} A base64-encoded opaque blob.
 */
export async function encryptVault(value, password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(password, salt);

  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext)
  );

  const combined = new Uint8Array(salt.length + iv.length + ciphertext.length);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(ciphertext, salt.length + iv.length);
  return bytesToBase64(combined);
}

/**
 * Decrypt a blob produced by {@link encryptVault}.
 *
 * @param {string} blobBase64 - The opaque blob (as returned by GET /vault).
 * @param {string} password - The vault master password.
 * @returns {Promise<unknown>} The original decrypted value.
 * @throws {Error} If the password is wrong or the blob is corrupt/tampered
 *     with (AES-GCM's authentication tag check fails).
 */
export async function decryptVault(blobBase64, password) {
  const combined = base64ToBytes(blobBase64);
  const salt = combined.slice(0, SALT_BYTES);
  const iv = combined.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const ciphertext = combined.slice(SALT_BYTES + IV_BYTES);

  const key = await deriveKey(password, salt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext));
}
