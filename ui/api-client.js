(function (root) {
  "use strict";

  const READ_OPERATIONS = new Set([
    "accounts", "account_info", "servers", "server", "regions", "plans",
    "images", "floating_ips", "watch_status", "tunnels", "dns_zones",
    "dns_record", "all_servers", "all_floating_ips", "ssh_keys",
    "check_all_accounts", "hetzner_primary_ips", "dns_records", "proxy_pool",
    "test_account", "test_proxy", "proxy_providers", "proxy_sessions",
    "proxy_availability", "server_password", "parse_proxy_sessions"
  ]);

  const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

  function createError(message, details) {
    const error = new Error(message);
    Object.assign(error, details || {});
    return error;
  }

  function create(options) {
    const config = options || {};
    const fetchImpl = config.fetchImpl || root.fetch.bind(root);
    const getToken = config.getToken || (() => "");
    const onUnauthorized = config.onUnauthorized || (() => {});
    const sleep = config.sleep || ((ms) => new Promise(resolve => setTimeout(resolve, ms)));
    const maxAttempts = Math.max(1, Number(config.maxAttempts || 3));

    async function request(operation, args, requestOptions) {
      const body = args || {};
      const opts = requestOptions || {};
      const retryMode = opts.retryMode || (READ_OPERATIONS.has(operation) ? "read" : "never");
      const canRetry = retryMode === "read";
      let attempt = 0;

      while (true) {
        attempt += 1;
        let response;
        try {
          const headers = { "Content-Type": "application/json" };
          const token = getToken();
          if (token) headers.Authorization = `Bearer ${token}`;
          response = await fetchImpl(`/v1/operations/${operation}`, {
            method: "POST",
            headers,
            body: JSON.stringify(body),
            signal: opts.signal
          });
        } catch (cause) {
          if (canRetry && attempt < maxAttempts) {
            await sleep(Math.min(1000, 250 * (2 ** (attempt - 1))));
            continue;
          }
          throw createError(cause && cause.message ? cause.message : `Operation ${operation} failed`, {
            operation, attempt, retryable: canRetry, cause
          });
        }

        if (response.status === 401) {
          onUnauthorized();
          throw createError("Authentication session expired; please sign in again.", {
            operation, status: 401, attempt, retryable: false
          });
        }

        let data = null;
        try {
          data = await response.json();
        } catch (cause) {
          if (canRetry && attempt < maxAttempts && RETRYABLE_STATUS.has(response.status)) {
            await sleep(Math.min(1000, 250 * (2 ** (attempt - 1))));
            continue;
          }
          throw createError(`Invalid response from ${operation}`, {
            operation, status: response.status, attempt, retryable: canRetry, cause
          });
        }

        if (!response.ok) {
          const message = data && data.error ? data.error : `Operation ${operation} failed (HTTP ${response.status})`;
          if (canRetry && attempt < maxAttempts && RETRYABLE_STATUS.has(response.status)) {
            await sleep(Math.min(1000, 250 * (2 ** (attempt - 1))));
            continue;
          }
          throw createError(message, {
            operation, status: response.status, attempt,
            retryable: canRetry && RETRYABLE_STATUS.has(response.status)
          });
        }
        return data;
      }
    }

    return { request };
  }

  root.CloudbotApiClient = { create, READ_OPERATIONS, RETRYABLE_STATUS };
})(window);
