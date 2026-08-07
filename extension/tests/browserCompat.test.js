import { afterEach, describe, expect, it } from "vitest";
import { installBrowserCompatShim } from "../lib/browserCompat.js";

describe("installBrowserCompatShim", () => {
  afterEach(() => {
    delete globalThis.chrome;
    delete globalThis.browser;
  });

  it("aliases chrome to browser when browser is defined (Firefox/Safari)", () => {
    const fakeBrowser = { runtime: { id: "firefox-native-webextensions-api" } };
    const target = { browser: fakeBrowser };

    installBrowserCompatShim(target);

    expect(target.chrome).toBe(fakeBrowser);
  });

  it("does nothing when browser is undefined (Chrome)", () => {
    const fakeChrome = { runtime: { id: "chrome-native-api" } };
    const target = { chrome: fakeChrome };

    installBrowserCompatShim(target);

    expect(target.chrome).toBe(fakeChrome);
    expect(target.browser).toBeUndefined();
  });

  it("overrides an existing chrome global with browser when both are present", () => {
    // Firefox itself defines a `chrome` compatibility shim alongside native
    // `browser` -- this must win over Firefox's own shim, since the native
    // `browser` API is the fully promise-based one this codebase relies on.
    const fakeBrowser = { runtime: { id: "firefox-native" } };
    const firefoxOwnChromeShim = { runtime: { id: "firefox-chrome-shim" } };
    const target = { browser: fakeBrowser, chrome: firefoxOwnChromeShim };

    installBrowserCompatShim(target);

    expect(target.chrome).toBe(fakeBrowser);
  });

  it("defaults to globalThis when no target is given", () => {
    globalThis.browser = { runtime: { id: "default-target-test" } };

    installBrowserCompatShim();

    expect(globalThis.chrome).toBe(globalThis.browser);
  });
});
