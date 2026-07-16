/**
 * ARGUS developer API — thin JavaScript client (Phase 2, C3).
 *
 * A minimal wrapper over /v1/*, using the built-in fetch API (no
 * dependencies). Works in Node 18+ and any modern browser. Not published
 * as a package; copy this file into your project, or vendor it as-is.
 *
 * Usage:
 *   import { ArgusClient } from "./argus-client.js";
 *   const client = new ArgusClient({ apiKey: "argus_...", baseUrl: "https://argus.example.com" });
 *   const result = await client.scan("https://example.com");
 *   console.log(result.label, result.confidence);
 */

export class ArgusApiError extends Error {
  /**
   * @param {number} statusCode
   * @param {string} message
   */
  constructor(statusCode, message) {
    super(`ARGUS API error ${statusCode}: ${message}`);
    this.statusCode = statusCode;
  }
}

export class ArgusClient {
  /**
   * @param {{apiKey: string, baseUrl?: string}} options
   */
  constructor({ apiKey, baseUrl = "https://api.argus.example.com" }) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async _request(method, path, body) {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const responseBody = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new ArgusApiError(resp.status, responseBody.error || "unknown error");
    }
    return responseBody;
  }

  /**
   * Scan a single URL.
   * @param {string} url
   * @param {boolean} [enrich=false] - Run the full detection fusion layer
   *     (brand/favicon/cert/redirect signals) -- slower, but much more
   *     likely to catch a brand-impersonation phishing page.
   * @returns {Promise<{url: string, label: string, confidence: number, risk_score: number, signals: Array<object>, source: string, latency_ms: number}>}
   */
  scan(url, enrich = false) {
    return this._request("POST", "/v1/scan", { url, enrich });
  }

  /**
   * Scan up to 50 URLs in one call. Each URL counts individually against
   * your per-key rate limit. A malformed URL yields a per-item
   * `{url, error}` entry rather than failing the whole request.
   * @param {string[]} urls
   * @param {boolean} [enrich=false]
   * @returns {Promise<Array<object>>}
   */
  async scanBatch(urls, enrich = false) {
    const body = await this._request("POST", "/v1/scan/batch", { urls, enrich });
    return body.results;
  }

  /**
   * Full explanation for a URL: SHAP top-5 features, triggered detection
   * signals, and a plain-language summary sentence.
   * @param {string} url
   * @returns {Promise<object>}
   */
  explain(url) {
    return this._request("POST", "/v1/explain", { url });
  }

  /**
   * Public liveness/version probe. Does not require an API key.
   * @returns {Promise<{status: string, version: string, model_loaded: boolean, latency_ms: number}>}
   */
  async health() {
    const resp = await fetch(`${this.baseUrl}/v1/health`);
    return resp.json();
  }
}
