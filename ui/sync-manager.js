(function (root) {
  "use strict";

  function proxyFailure(error) {
    const text = error && (error.error || error.message || error.detail || error);
    const value = String(text || "");
    if (/invalid\s+(api\s+)?token|unauthori[sz]ed|authentication\s+failed|api\s+key/i.test(value)) return false;
    return /proxy|socks|ClientHttpProxyError|proxyconnect|tunnel\s+connection|could\s+not\s+connect\s+to\s+proxy|(?:TimeoutError|ConnectionRefusedError|ClientConnectorError|ClientProxyConnectionError|ServerDisconnectedError)/i.test(value);
  }

  function createManager(options) {
    const config = options || {};
    const names = Array.from(config.resourceNames || []);
    const now = config.now || (() => Date.now());
    const freshForMs = Number(config.freshForMs || 300000);
    const onState = config.onState || (() => {});
    const resources = {};
    names.forEach(name => {
      resources[name] = { status: "idle", value: undefined, error: null, updatedAt: null, hasValue: false };
    });
    let generation = 0;
    let lastSuccessAt = null;

    function emit() {
      onState(snapshot());
    }

    function current(g) {
      return g === generation;
    }

    function begin() {
      generation += 1;
      Object.keys(resources).forEach(name => {
        resources[name].status = "syncing";
        resources[name].error = null;
      });
      emit();
      return generation;
    }

    function startPhase(g) {
      if (!current(g)) return false;
      Object.keys(resources).forEach(name => {
        if (resources[name].status !== "idle") {
          resources[name].status = "syncing";
        }
      });
      emit();
      return true;
    }

    function setValue(g, name, value, status) {
      if (!current(g) || !resources[name]) return false;
      resources[name].value = value;
      resources[name].hasValue = true;
      resources[name].status = status;
      resources[name].error = null;
      resources[name].updatedAt = now();
      if (status === "synced") lastSuccessAt = resources[name].updatedAt;
      emit();
      return true;
    }

    function hydrate(g, name, value) {
      return setValue(g, name, value, "cached");
    }

    function apply(g, name, value) {
      return setValue(g, name, value, "synced");
    }

    function succeed(g, name) {
      if (!current(g) || !resources[name]) return false;
      resources[name].status = "synced";
      resources[name].error = null;
      resources[name].updatedAt = now();
      lastSuccessAt = resources[name].updatedAt;
      emit();
      return true;
    }

    function fail(g, name, error, hasValue) {
      if (!current(g) || !resources[name]) return false;
      const resource = resources[name];
      resource.error = error instanceof Error ? error.message : String(error || "Refresh failed");
      resource.status = hasValue || resource.hasValue ? "stale" : "error";
      resource.updatedAt = now();
      emit();
      return true;
    }

    function snapshot() {
      const copy = {};
      let attentionCount = 0;
      Object.keys(resources).forEach(name => {
        const item = resources[name];
        copy[name] = Object.assign({}, item);
        if (item.status === "stale" || item.status === "error") attentionCount += 1;
      });
      const isFresh = lastSuccessAt !== null && (now() - lastSuccessAt) < freshForMs;
      return {
        generation,
        resources: copy,
        lastSuccessAt,
        attentionCount,
        fresh: isFresh
      };
    }

    async function recoverProxy(params) {
      const input = params || {};
      const account = input.account;
      if (!current(input.generation)) {
        return { status: "not-applicable", result: null, error: "Sync generation is no longer current" };
      }
      if (!account || !account.has_proxy || !proxyFailure(input.error)) {
        return { status: "not-applicable", result: null, error: input.error || null };
      }
      if (typeof input.healProxy !== "function") {
        return { status: "unresolved", result: null, error: "Proxy recovery is unavailable" };
      }
      try {
        const healResult = await input.healProxy(account);
        if (!current(input.generation)) {
          return { status: "not-applicable", result: null, error: "Sync generation is no longer current" };
        }
        const healed = Array.isArray(healResult && healResult.healed) && healResult.healed.some(item => String(item.id) === String(account.id));
        if (!healed) {
          return { status: "unresolved", result: healResult, error: input.error || "No working replacement proxy was found" };
        }
        if (!current(input.generation)) {
          return { status: "not-applicable", result: null, error: "Sync generation is no longer current" };
        }
        const result = typeof input.retryRead === "function" ? await input.retryRead() : null;
        if (!current(input.generation)) {
          return { status: "not-applicable", result: null, error: "Sync generation is no longer current" };
        }
        if (result && result.status === "error") {
          return { status: "unresolved", result, error: result.error || "Replacement proxy still failed" };
        }
        return { status: "recovered", result, proxyReplaced: true, error: null };
      } catch (error) {
        return { status: "unresolved", result: null, error: error.message || String(error) };
      }
    }

    return { begin, startPhase, current, hydrate, apply, succeed, fail, recoverProxy, snapshot };
  }

  root.CloudbotSync = { createManager, proxyFailure };
})(window);
