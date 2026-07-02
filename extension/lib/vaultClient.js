/**
 * ARGUS vault client (Phase 8, Task 8.3) -- zero-knowledge sync.
 *
 * Ties together crypto.js (encrypt/decrypt) + authClient.js (get a valid
 * access token) + GET/PUT /vault. The vault master password lives only in
 * memory for the duration of a call here -- it is never persisted to
 * chrome.storage and never sent to the server (only the ciphertext is).
 */

import { getValidAccessToken } from "./authClient.js";
import { decryptVault, encryptVault } from "./crypto.js";
import { apiRequest } from "./httpClient.js";

async function getApiBaseUrl() {
  const { apiBaseUrl } = await chrome.storage.sync.get({ apiBaseUrl: "" });
  if (!apiBaseUrl) {
    throw new Error("ARGUS API base URL not configured. Open the extension options page.");
  }
  return apiBaseUrl;
}

/**
 * Fetch and decrypt the vault.
 * @param {string} masterPassword - Never sent to the server.
 * @returns {Promise<{value: unknown, version: number}>} ``value`` is ``null``
 *     if no vault has been created yet (fresh account).
 */
export async function fetchVault(masterPassword) {
  const apiBaseUrl = await getApiBaseUrl();
  const accessToken = await getValidAccessToken();

  const { ciphertext, version } = await apiRequest(apiBaseUrl, "GET", "/vault", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (ciphertext === null) {
    return { value: null, version };
  }
  const value = await decryptVault(ciphertext, masterPassword);
  return { value, version };
}

/**
 * Encrypt and write the vault, subject to optimistic-concurrency control.
 * @param {unknown} value - Any JSON-serializable vault contents.
 * @param {string} masterPassword
 * @param {number} expectedVersion - The version last read via {@link fetchVault}.
 * @returns {Promise<{version: number}>}
 * @throws {Error & {status: 409, body: {current_version, current_ciphertext}}}
 *     If another device wrote first. Caller should re-fetch (and typically
 *     re-decrypt/merge) before retrying with the new version.
 */
export async function saveVault(value, masterPassword, expectedVersion) {
  const apiBaseUrl = await getApiBaseUrl();
  const accessToken = await getValidAccessToken();
  const ciphertext = await encryptVault(value, masterPassword);

  return apiRequest(apiBaseUrl, "PUT", "/vault", {
    headers: { Authorization: `Bearer ${accessToken}` },
    body: { ciphertext, version: expectedVersion },
  });
}
