/**
 * Test suite for Logs and Operational Activity UI & State
 */
const assert = require("assert");
const fs = require("fs");
const path = require("path");

const appCode = fs.readFileSync(path.join(__dirname, "ui", "app.js"), "utf8");
const indexHtml = fs.readFileSync(path.join(__dirname, "ui", "index.html"), "utf8");
const styleCss = fs.readFileSync(path.join(__dirname, "ui", "style.css"), "utf8");

// 1. Verify HTML structure has tab-logs and nav button
assert(indexHtml.includes('data-tab="tab-logs"'), "index.html must include nav item for tab-logs");
assert(indexHtml.includes('id="tab-logs"'), "index.html must include tab pane for tab-logs");
assert(indexHtml.includes('id="log-stream-content"'), "index.html must include log-stream-content terminal");
assert(indexHtml.includes('id="activity-logs-table"'), "index.html must include activity-logs-table");
assert(indexHtml.includes('id="log-service-filter"'), "index.html must include service filter");
assert(indexHtml.includes('id="btn-subtab-system-logs"'), "index.html must include system logs subtab button");
assert(indexHtml.includes('id="btn-subtab-activity-logs"'), "index.html must include activity logs subtab button");

// 2. Verify CSS has terminal and log styling
assert(styleCss.includes(".log-stream-terminal"), "style.css must style .log-stream-terminal");
assert(styleCss.includes(".pulse-dot-badge"), "style.css must style .pulse-dot-badge");
assert(styleCss.includes(".terminal-body"), "style.css must style .terminal-body");
assert(styleCss.includes(".term-lvl-error"), "style.css must style .term-lvl-error");

// 3. Verify JS routing and functions
assert(appCode.includes('"/logs": "tab-logs"'), "ROUTE_MAP must map /logs to tab-logs");
assert(appCode.includes('"tab-logs": "/logs"'), "TAB_TO_ROUTE must map tab-logs to /logs");
assert(appCode.includes('function renderLogs()'), "app.js must define renderLogs()");
assert(appCode.includes('function fetchSystemLogs('), "app.js must define fetchSystemLogs()");
assert(appCode.includes('function fetchActivityLogs('), "app.js must define fetchActivityLogs()");
assert(appCode.includes('function formatLogMessage('), "app.js must define formatLogMessage()");

// 4. Test formatLogMessage highlighting
const vm = require("vm");
const context = {
  escapeHtml: str => String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"),
};
vm.createContext(context);
const formatLogFuncMatch = appCode.match(/function formatLogMessage\(msg\)\s*\{[\s\S]*?\n\}/);
assert(formatLogFuncMatch, "formatLogMessage function body should be extractable");
vm.runInContext(formatLogFuncMatch[0], context);

const testLogLine = 'POST /v1/operations/create_server HTTP/1.1 200 127.0.0.1';
const formatted = context.formatLogMessage(testLogLine);
assert(formatted.includes('class="method-post">POST</span>'), "POST method must be highlighted with class method-post");
assert(formatted.includes('class="status-200">200</span>'), "Status 200 must be highlighted with class status-200");
assert(formatted.includes('127.0.0.1'), "IP address must be preserved or highlighted");

console.log("All Logs UI, state, routing, and formatting tests passed successfully.");
