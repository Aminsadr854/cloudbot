(function (root) {
  "use strict";

  function accountFailure(error) {
    const text = error && (error.error || error.message || error.detail || error);
    const value = String(text || "");
    let kind = "connection", title = "Connection Error";
    let guidance = "The connection could not be completed. Retry the account check and review the error details.";
    if (/Account suspended|server\(s\) reported suspended/i.test(value)) {
      kind = 'suspended'; title = 'Suspended';
      guidance = 'The provider reports suspended servers on this account. Review account billing and suspension notices with the provider.';
    } else if (/Provider traffic limit reached/i.test(value)) {
      kind = 'quota'; title = 'Provider Traffic Limit Reached';
      guidance = 'Raise this provider’s GB limit or reset its Cloudbot usage counter. The proxy route has not failed.';
    } else if (/HTTP\s+407\b|Proxy authentication failed|ClientHttpProxyError|ClientProxyConnectionError|proxyconnect|tunnel\s+connection|could\s+not\s+connect\s+to\s+proxy|SOCKS proxy needs|Proxy(?:Connection|Timeout|Error)/i.test(value)) {
      kind = "proxy"; title = "Proxy Failed";
      guidance = "The configured proxy could not complete the connection. Check its address, credentials, or session.";
    } else if (/Unauthorized IP address|IP.*(?:not allowed|not authorized|not whitelisted)/i.test(value)) {
      kind = "access"; title = "API Access Denied";
      guidance = "The cloud provider rejected the outbound IP address. Review the account API IP allowlist; this does not mean the proxy is offline.";
    } else if (/HTTP\s+401\b|invalid\s+(api\s+)?token|unauthori[sz]ed|authentication\s+failed|invalid\s+api\s+key|expired\s+token/i.test(value)) {
      kind = "auth"; title = "Invalid / Expired API Token";
      guidance = "The cloud provider was reached but rejected this account's API token. Replace the invalid, expired, or revoked token in the account configuration.";
    } else if (/HTTP\s+403\b|permission denied|insufficient.*(?:scope|permission)/i.test(value)) {
      kind = "access"; title = "API Access Denied";
      guidance = "The cloud provider denied API access. Review token permissions, account restrictions, and API access rules.";
    } else if (/HTTP\s+\d{3}\b/i.test(value)) {
      kind = "provider"; title = "Cloud Provider Error";
      guidance = "The cloud provider returned an API error. Review the details below; changing the proxy is not the suggested fix.";
    } else if (/proxy|socks/i.test(value)) {
      kind = "proxy"; title = "Proxy Failed";
      guidance = "The configured proxy could not complete the connection. Check its address, credentials, or session.";
    }
    return { kind, title, guidance, isProxy: kind === "proxy", error: value, shortMessage: title };
  }

  function proxyFailure(error) {
    return accountFailure(error).isProxy;
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

    function begin(live = true) {
      generation += 1;
      Object.keys(resources).forEach(name => {
        resources[name].status = live ? "syncing" : "cached";
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

  root.CloudbotSync = { createManager, proxyFailure, accountFailure };
})(window);
