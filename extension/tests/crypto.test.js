import { describe, expect, it } from "vitest";
import { decryptVault, encryptVault } from "../lib/crypto.js";

describe("encryptVault / decryptVault", () => {
  it("round-trips an object through encrypt then decrypt", async () => {
    const value = { allowlist: ["bit.ly", "phish.tk"], notes: "hello" };
    const blob = await encryptVault(value, "correct-horse-battery-staple");
    const decrypted = await decryptVault(blob, "correct-horse-battery-staple");
    expect(decrypted).toEqual(value);
  });

  it("produces a base64 string", async () => {
    const blob = await encryptVault({ a: 1 }, "pw");
    expect(blob).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it("produces different ciphertext for the same plaintext each time (random salt/iv)", async () => {
    const blobA = await encryptVault({ a: 1 }, "pw");
    const blobB = await encryptVault({ a: 1 }, "pw");
    expect(blobA).not.toBe(blobB);
  });

  it("rejects decryption with the wrong password", async () => {
    const blob = await encryptVault({ secret: true }, "right-password");
    await expect(decryptVault(blob, "wrong-password")).rejects.toThrow();
  });

  it("rejects a tampered blob (AES-GCM auth tag check)", async () => {
    const blob = await encryptVault({ secret: true }, "pw");
    const tampered = blob.slice(0, -4) + (blob.slice(-4) === "AAAA" ? "BBBB" : "AAAA");
    await expect(decryptVault(tampered, "pw")).rejects.toThrow();
  });

  it("handles arrays and nested structures", async () => {
    const value = { allowlist: ["a.com", "b.com"], meta: { count: 2, tags: ["x", "y"] } };
    const blob = await encryptVault(value, "pw");
    expect(await decryptVault(blob, "pw")).toEqual(value);
  });
});
