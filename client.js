(() => {
  try {
    /* 无限五代 (dsh-infinite-gen-5) v1.0.0 专业无头逆向工程工作台
       视觉系统深度对齐 DeepSeek Harness「上下文」原生设计语言：
       - 全量采用官方 CSS 变量 tokens (--dsw-alias-*, --ds-*, tabular-nums)
       - 原生卡片容器 (.ig5-card)、统计磁贴 (.ig5-stat)、分段胶囊选择器 (.ig5-kinds / .ig5-gran-btn)
       - Reverse 分析能力与按配置注册的工具面：
         • 函数浏览器 + Reverse C 伪代码 + CFG 控制流图 (Mermaid) + 变量/微代码切片
         • 结构体与类型库 (Local Types / Til)：C 声明解析、成员偏移推导与应用
         • 字符串常量库 + 实时过滤与引用检索
         • 节段结构、导入表（敏感 API 标注）、导出表
         • 编译器指纹与 Reverse 标准库函数标记（过滤模板代码，聚焦用户业务逻辑）
         • 安全侦测：节段香农熵分析 (>7.2 风险警报)、加密特征常数、敏感 API 画像
         • 补丁审计时间线、Before/After 字节 Diff 对比、自管操作日志逐级回滚 (Undo)
         • 工具能力目录与会话实时投影协同
       - 完美挂载 conversation.view 主标签页与底部输入框徽章 */
    window.__ModuleLoader__.load({
      id: "dsh-infinite-gen-5",
      factory: (require) => {
        var module = { exports: {} };
        var exports = module.exports;
        Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

        var react = require("react");
        var el = react.createElement;

        var inject = ["slots"];
        var PLUGIN_ID = "dsh-infinite-gen-5";
        var PANEL_ID = "ig5-workbench-panel";
        var VERSION = "1.0.0";
        var WORKBENCH_TAB_LABEL = "IG5 逆向工作台";

        /* ── 诊断回路 ── */
        var DIAG = [];
        var flushTimer = null;
        function diag(tag, detail) {
          DIAG.push({
            t: new Date().toISOString().slice(11, 23),
            tag: tag,
            detail: detail === undefined || detail === null ? "" : String(detail).slice(0, 900),
          });
          if (!flushTimer) flushTimer = setTimeout(flushDiag, 1200);
        }
        function flushDiag() {
          flushTimer = null;
          if (!DIAG.length) return;
          var payload = JSON.stringify({ v: VERSION, href: String(location.href).slice(0, 120), events: DIAG });
          DIAG = [];
          try {
            if (typeof fetch === "function") {
              fetch("/ig5-diag", { method: "POST", headers: { "content-type": "application/json" }, body: payload })
                .catch(function () {});
            }
          } catch (e) {}
        }

        /* ── 原生视觉设计系统 (Aligned with dsh-context & DeepSeek Harness Native Tokens) ── */
        var CSS = `
/* 根工作台容器 */
.ig5-root {
  box-sizing: border-box;
  min-width: 0;
  container-type: inline-size;
  height: 100%;
  color: var(--dsw-alias-label-primary, #e2e8f0);
  padding: 16px 20px 32px;
  font-size: 13px;
  overflow-y: auto;
  overflow-x: hidden;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.5;
  background: var(--dsw-alias-bg-module-platform, transparent);
}
.ig5-mono {
  font-family: var(--ds-font-family-code, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
  font-variant-numeric: tabular-nums;
}

/* 布局列 */
.ig5-cols {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 12px;
}
.ig5-col {
  display: flex;
  flex-direction: column;
}
.ig5-functions-list { flex: 0 0 380px; width: 380px; margin-bottom: 0; }
.ig5-functions-detail { flex: 1 1 0%; min-width: 360px; margin-bottom: 0; }
.ig5-mobile-only { display: none; }
.ig5-environment { overflow-wrap: anywhere; }

/* 原生卡片容器 (.lc-card 对齐) */
.ig5-card {
  background: var(--dsw-alias-bg-layer-1, rgba(255, 255, 255, 0.03));
  border: 1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.12));
  border-radius: 10px;
  margin-bottom: 12px;
  padding: 14px 16px;
  box-sizing: border-box;
  transition: border-color var(--ds-transition-duration, .2s) var(--ds-ease-in-out, ease-in-out);
}
.ig5-card-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}
.ig5-card-title-text {
  font-size: 13px;
  font-weight: 600;
  color: var(--dsw-alias-label-primary, #e2e8f0);
  display: flex;
  align-items: center;
  gap: 8px;
}
.ig5-card-sub {
  color: var(--dsw-alias-label-secondary, #94a3b8);
  font-size: 12px;
  font-weight: 400;
}

/* 统计磁贴栅格 (.lc-stat 对齐) */
.ig5-stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(136px, 1fr));
  gap: 8px;
}
.ig5-stat {
  background: var(--dsw-alias-bg-layer-2, rgba(255, 255, 255, 0.05));
  border: 1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.12));
  border-radius: 8px;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
  padding: 8px 10px;
  display: flex;
  box-sizing: border-box;
  transition: border-color var(--ds-transition-duration, .2s) var(--ds-ease-in-out, ease-in-out);
}
.ig5-stat:hover {
  border-color: var(--dsw-alias-label-secondary, #94a3b8);
}
.ig5-stat-label {
  color: var(--dsw-alias-label-secondary, #94a3b8);
  white-space: nowrap;
  text-overflow: ellipsis;
  font-size: 11px;
  font-weight: 600;
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.ig5-stat-value {
  color: var(--dsw-alias-label-primary, #e2e8f0);
  white-space: nowrap;
  text-overflow: ellipsis;
  font-size: 15px;
  font-weight: 600;
  overflow: hidden;
  font-variant-numeric: tabular-nums;
  line-height: 1.3;
}
.ig5-stat-sub {
  color: var(--dsw-alias-label-tertiary, #64748b);
  white-space: nowrap;
  text-overflow: ellipsis;
  font-size: 11px;
  overflow: hidden;
  font-variant-numeric: tabular-nums;
}

/* 分段胶囊选择器 (.lc-kinds / .lc-gran-btn 对齐) */
.ig5-kinds {
  background: var(--dsw-alias-bg-layer-2, rgba(255, 255, 255, 0.05));
  border: 1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.12));
  border-radius: 6px;
  gap: 2px;
  padding: 2px;
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
}
.ig5-gran-btn {
  color: var(--dsw-alias-label-secondary, #94a3b8);
  cursor: pointer;
  transition: color var(--ds-transition-duration, .2s) var(--ds-ease-in-out, ease-in-out);
  background: 0 0;
  border: 0;
  border-radius: 5px;
  padding: 5px 11px;
  font-family: inherit;
  font-size: 12px;
  line-height: 1.2;
  font-weight: 500;
  display: inline-flex;
  align-items: center;
  gap: 5px;
}
.ig5-gran-btn:hover {
  color: var(--dsw-alias-label-primary, #e2e8f0);
}
.ig5-gran-on, .ig5-gran-on:hover {
  background: var(--dsw-alias-button-primary-fill, #3b82f6);
  color: var(--dsw-alias-label-primary-foreground, #ffffff);
  font-weight: 600;
}
.ig5-kind-n {
  font-variant-numeric: tabular-nums;
  opacity: .7;
  margin-left: 2px;
  font-size: 11px;
}
.ig5-gran-on .ig5-kind-n {
  opacity: .95;
}

/* 输入框与下拉选择框 */
.ig5-input {
  background: var(--dsw-alias-bg-layer-2, rgba(255, 255, 255, 0.05));
  border: 1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.12));
  border-radius: 6px;
  padding: 5px 10px;
  font-size: 12px;
  color: var(--dsw-alias-label-primary, #e2e8f0);
  outline: none;
  box-sizing: border-box;
  transition: border-color var(--ds-transition-duration, .2s) var(--ds-ease-in-out, ease-in-out);
}
.ig5-input:focus {
  border-color: var(--dsw-alias-brand-primary, #3b82f6);
}
.ig5-select {
  background: var(--dsw-alias-bg-layer-2, rgba(255, 255, 255, 0.05));
  border: 1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.12));
  border-radius: 6px;
  padding: 4px 8px;
  font-size: 12px;
  color: var(--dsw-alias-label-primary, #e2e8f0);
  outline: none;
  cursor: pointer;
  font-family: inherit;
}

/* 按钮 */
.ig5-btn {
  background: var(--dsw-alias-bg-layer-2, rgba(255, 255, 255, 0.05));
  border: 1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.12));
  color: var(--dsw-alias-label-primary, #e2e8f0);
  border-radius: 6px;
  padding: 4px 11px;
  font-size: 12px;
  font-family: inherit;
  font-weight: 500;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  transition: all var(--ds-transition-duration, .2s) var(--ds-ease-in-out, ease-in-out);
}
.ig5-btn:hover {
  background: var(--dsw-alias-interactive-bg-hover, rgba(255, 255, 255, 0.08));
  border-color: var(--dsw-alias-label-secondary, #94a3b8);
}
.ig5-btn:disabled {
  opacity: .4;
  cursor: not-allowed;
}
.ig5-btn-primary {
  background: var(--dsw-alias-button-primary-fill, #3b82f6);
  color: var(--dsw-alias-label-primary-foreground, #ffffff);
  border-color: transparent;
}
.ig5-btn-primary:hover {
  opacity: .9;
}

/* 状态药丸与徽章 (.lc-detail-tag 对齐) */
.ig5-chip {
  background: var(--dsw-alias-bg-layer-2, rgba(255, 255, 255, 0.05));
  border: 1px solid var(--dsw-alias-border-l1, rgba(255, 255, 255, 0.08));
  color: var(--dsw-alias-label-secondary, #94a3b8);
  border-radius: 4px;
  padding: 2px 7px;
  font-size: 11px;
  font-variant-numeric: tabular-nums;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.ig5-chip.read {
  border-color: color-mix(in srgb, var(--dsw-alias-brand-primary, #3b82f6) 40%, transparent);
  color: var(--dsw-alias-brand-primary, #3b82f6);
  background: color-mix(in srgb, var(--dsw-alias-brand-primary, #3b82f6) 10%, transparent);
}
.ig5-chip.write {
  border-color: color-mix(in srgb, var(--dsw-alias-state-error-primary, #ef4444) 40%, transparent);
  color: var(--dsw-alias-state-error-primary, #ef4444);
  background: color-mix(in srgb, var(--dsw-alias-state-error-primary, #ef4444) 10%, transparent);
}
.ig5-chip.warn {
  border-color: color-mix(in srgb, var(--dsw-alias-state-warn-primary, #f59e0b) 40%, transparent);
  color: var(--dsw-alias-state-warn-primary, #f59e0b);
  background: color-mix(in srgb, var(--dsw-alias-state-warn-primary, #f59e0b) 10%, transparent);
}
.ig5-chip.success {
  border-color: color-mix(in srgb, var(--dsw-alias-state-success-primary, #10b981) 40%, transparent);
  color: var(--dsw-alias-state-success-primary, #10b981);
  background: color-mix(in srgb, var(--dsw-alias-state-success-primary, #10b981) 10%, transparent);
}

/* 原生表格容器 */
.ig5-table-wrap {
  border: 1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.12));
  border-radius: 8px;
  overflow: auto;
  background: var(--dsw-alias-bg-layer-2, rgba(255, 255, 255, 0.05));
  max-height: 480px;
}
.ig5-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  text-align: left;
}
.ig5-table th {
  position: sticky;
  top: 0;
  background: var(--dsw-alias-bg-layer-1, rgba(255, 255, 255, 0.03));
  z-index: 2;
  padding: 8px 12px;
  color: var(--dsw-alias-label-secondary, #94a3b8);
  font-weight: 600;
  border-bottom: 1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.12));
  font-size: 11px;
}
.ig5-table td {
  padding: 6px 12px;
  border-bottom: 1px solid var(--dsw-alias-border-l1, rgba(255, 255, 255, 0.08));
  color: var(--dsw-alias-label-primary, #e2e8f0);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.ig5-table tr {
  cursor: pointer;
  transition: background-color var(--ds-transition-duration, .15s);
}
.ig5-table tr:hover {
  background-color: var(--dsw-alias-interactive-bg-hover, rgba(255, 255, 255, 0.04));
}
.ig5-table tr.selected {
  background-color: color-mix(in srgb, var(--dsw-alias-brand-primary, #3b82f6) 16%, transparent);
}

/* 伪代码与代码展示框 */
.ig5-code-box {
  background: var(--dsw-alias-bg-layer-2, rgba(255, 255, 255, 0.05));
  border: 1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.12));
  border-radius: 8px;
  padding: 12px 16px;
  font-family: var(--ds-font-family-code, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
  font-size: 12px;
  line-height: 1.6;
  color: var(--dsw-alias-label-primary, #e2e8f0);
  overflow: auto;
  white-space: pre;
  max-height: 420px;
}
.ig5-cfg-canvas { width: 100%; height: 440px; border: 1px solid var(--dsw-alias-border-l2, #334155); border-radius: 8px; background: var(--dsw-alias-bg-layer-2, #101828); touch-action: none; cursor: grab; }
.ig5-cfg-canvas:active { cursor: grabbing; }
.ig5-cfg-node { cursor: pointer; outline: none; }
.ig5-cfg-node rect { fill: var(--dsw-alias-bg-layer-1, #182438); stroke: var(--dsw-alias-brand-primary, #60a5fa); stroke-width: 1.5; }
.ig5-cfg-node:hover rect, .ig5-cfg-node:focus rect { stroke-width: 3; }
.ig5-cfg-node text { fill: var(--dsw-alias-label-primary, #e2e8f0); font-size: 12px; }
.ig5-cfg-edge { fill: none; stroke-width: 1.7; }
.ig5-cfg-edge-label { fill: var(--dsw-alias-label-secondary, #94a3b8); font-size: 11px; paint-order: stroke; stroke: var(--dsw-alias-bg-layer-2, #101828); stroke-width: 4px; }
.ig5-code-line { display: block; min-height: 1.6em; }
.ig5-code-line.focused { background: color-mix(in srgb, var(--dsw-alias-brand-primary, #3b82f6) 18%, transparent); }
.ig5-code-line mark { background: #facc15; color: #172033; border-radius: 2px; }
.ig5-form-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0; }
.ig5-textarea { box-sizing: border-box; width: 100%; min-height: 120px; padding: 10px; resize: vertical; color: var(--dsw-alias-label-primary, #e2e8f0); background: var(--dsw-alias-bg-layer-2, #101828); border: 1px solid var(--dsw-alias-border-l2, #334155); border-radius: 6px; }
.ig5-error { color: var(--dsw-alias-state-error-primary, #f87171); white-space: pre-wrap; overflow-wrap: anywhere; }

/* 进度条 (.lc-bar-track 对齐) */
.ig5-track {
  background: color-mix(in srgb, var(--dsw-alias-label-secondary, #888) 18%, transparent);
  border-radius: 4px;
  width: 100%;
  height: 6px;
  overflow: hidden;
  position: relative;
}
.ig5-fill {
  border-radius: 4px;
  height: 100%;
  background: var(--dsw-alias-brand-primary, #3b82f6);
  transition: width 0.3s ease;
}

/* 状态小圆点 */
.ig5-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex: none;
  display: inline-block;
}
@keyframes ig5Pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
.ig5-pulse { animation: ig5Pulse 1.2s ease-in-out infinite; }

/* 底部输入框徽章 */
.ig5-badge-wrap { display: flex; justify-content: center; width: 100%; }
.ig5-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 10px;
  border-radius: 9999px;
  border: 1px solid var(--dsw-alias-border-l2, rgba(255, 255, 255, 0.12));
  background: var(--dsw-alias-bg-layer-2, rgba(255, 255, 255, 0.05));
  font-size: 11px;
  line-height: 18px;
  user-select: none;
  white-space: nowrap;
  cursor: pointer;
  color: var(--dsw-alias-label-secondary, #94a3b8);
  font-weight: 500;
  transition: all var(--ds-transition-duration, .2s) var(--ds-ease-in-out, ease-in-out);
}
.ig5-badge:hover {
  background: var(--dsw-alias-interactive-bg-hover, rgba(255, 255, 255, 0.08));
  color: var(--dsw-alias-label-primary, #e2e8f0);
  border-color: var(--dsw-alias-label-secondary, #94a3b8);
}
@container (max-width: 760px) {
  .ig5-function-workspace { display: block; }
  .ig5-functions-list, .ig5-functions-detail { width: 100%; min-width: 0; margin-bottom: 12px; }
  .ig5-functions-list.is-collapsed { display: none; }
  .ig5-mobile-only { display: inline-flex; }
  .ig5-nav-tabs { flex-wrap: nowrap; max-width: 100%; overflow-x: auto; }
  .ig5-nav-tabs .ig5-gran-btn { flex-shrink: 0; }
  .ig5-card { padding: 12px; }
  .ig5-card-title-text { min-width: 0; flex-wrap: wrap; overflow-wrap: anywhere; }
  .ig5-form-row, .ig5-card-title > div { flex-wrap: wrap; }
  .ig5-btn, .ig5-gran-btn, .ig5-select { min-height: 44px; }
  .ig5-input, .ig5-select, .ig5-textarea { font-size: 16px; max-width: 100%; min-width: 0; }
  .ig5-functions-list .ig5-table-wrap { max-height: 280px; }
  .ig5-cfg-canvas { height: 360px; }
}
@media (max-width: 760px) {
  .ig5-root { padding: 12px 10px calc(20px + env(safe-area-inset-bottom, 0px)); }
  .ig5-function-workspace { display: block; }
  .ig5-functions-list, .ig5-functions-detail { width: 100%; min-width: 0; margin-bottom: 12px; }
  .ig5-functions-list.is-collapsed { display: none; }
  .ig5-mobile-only { display: inline-flex; }
  .ig5-nav-tabs { flex-wrap: nowrap; max-width: 100%; overflow-x: auto; }
  .ig5-nav-tabs .ig5-gran-btn { flex-shrink: 0; }
  .ig5-btn, .ig5-gran-btn, .ig5-select { min-height: 44px; }
  .ig5-input, .ig5-select, .ig5-textarea { font-size: 16px; max-width: 100%; min-width: 0; }
  .ig5-card { padding: 12px; }
  .ig5-card-title-text, .ig5-form-row, .ig5-card-title > div { flex-wrap: wrap; min-width: 0; }
  .ig5-functions-list .ig5-table-wrap { max-height: 280px; }
  .ig5-cfg-canvas { height: 360px; }
}
@media (prefers-reduced-motion: reduce) {
  .ig5-root *, .ig5-pulse { animation: none; transition: none; }
}
`;

        function useStyleOnce() {
          react.useEffect(function () {
            var tagId = "dsh-infinite-gen-5/styles";
            if (typeof document !== "undefined" && !document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId) + "]")) {
              var tag = document.createElement("style");
              tag.dataset.plugin = PLUGIN_ID;
              tag.dataset.pluginCss = tagId;
              tag.textContent = CSS;
              document.head.appendChild(tag);
            }
          }, []);
        }

        /* ── 数据源轮询 Hooks ── */
        function useJobsFeed() {
          var pair = react.useState(null);
          var feed = pair[0];
          var setFeed = pair[1];
          react.useEffect(function () {
            var alive = true;
            var timer = null;
            function tick() {
              fetch("/ig5-jobs")
                .then(function (r) { return r.json(); })
                .then(function (data) {
                  if (!alive) return;
                  setFeed(data);
                  var isRunning = (data.jobs || []).some(function (j) { return j.state === "running"; });
                  timer = setTimeout(tick, isRunning ? 1000 : 3500);
                })
                .catch(function () {
                  if (alive) setFeed(null);
                  timer = setTimeout(tick, 5000);
                });
            }
            tick();
            return function () { alive = false; if (timer) clearTimeout(timer); };
          }, []);
          return feed;
        }

        function useDash(props) {
          try {
            if (props && typeof props.useProjection === "function") {
              return props.useProjection("ig5dash");
            }
          } catch (e) {}
          return null;
        }

        function basename(p) {
          var s = String(p || "");
          var i = Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\"));
          return i >= 0 ? s.slice(i + 1) : s;
        }

        function engineName(engine) { return engine === "ghidra" ? "Ghidra" : engine === "x64dbg" ? "x64dbg" : "Reverse"; }
        function sessionIdentity(session) { return JSON.stringify([session.key || "", session.target || "", session.engine || "reverse"]); }
        function parseWorkbenchFocus(value) {
          if (typeof value !== "string" || value.length > 8192) return null;
          try {
            var focus = JSON.parse(value);
            if (focus.v !== 1 || ["reverse", "ghidra"].indexOf(focus.engine) === -1 || typeof focus.target !== "string" || !focus.target || typeof focus.ea !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(focus.ea)) return null;
            return { v: 1, engine: focus.engine, target: focus.target, ea: "0x" + BigInt(focus.ea).toString(16), name: typeof focus.name === "string" ? focus.name : "", artifactId: typeof focus.artifactId === "string" ? focus.artifactId : null, projectId: typeof focus.projectId === "string" ? focus.projectId : null };
          } catch (e) { return null; }
        }
        // Normalize the actual worker contracts once, before rendering. Keep
        // provenance and native fields intact; rows is a workbench-only alias.
        function normalizeReadData(type, data) {
          if (["xrefs", "calls", "strings", "listing"].indexOf(type) === -1) return data;
          if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("分析数据格式无效");
          function list(primary) {
            var value = data[primary] !== undefined ? data[primary] : data.rows;
            if (!Array.isArray(value) || value.some(function (row) { return !row || typeof row !== "object" || Array.isArray(row); })) throw new Error("分析数据格式无效: " + type + "." + primary);
            return value;
          }
          if (type === "xrefs") return Object.assign({}, data, { rows: list("hits").map(function (row) {
            return Object.assign({}, row, { func_name: row.func_name || row.func || "", from: row.from || row.other || row.ea });
          }) });
          if (type === "calls") return Object.assign({}, data, { rows: list("calls") });
          if (type === "strings") return Object.assign({}, data, { strings: list("strings").map(function (row) {
            return Object.assign({}, row, { str: typeof row.text === "string" ? row.text : (typeof row.str === "string" ? row.str : "") });
          }) });
          if (type === "listing") return Object.assign({}, data, { rows: list("items").map(function (row) {
            var perm = row.perm;
            if (typeof perm === "number") perm = (perm & 4 ? "r" : "-") + (perm & 2 ? "w" : "-") + (perm & 1 ? "x" : "-");
            return Object.assign({}, row, { perm: typeof perm === "string" ? perm : "" });
          }) });
          return data;
        }
        var readIdentityFields = ["target", "engine", "projectId", "artifactId", "sha256", "provider", "attachmentId", "dbRevision"];
        function captureReadSnapshot(session) {
          if (!session) return null;
          var snapshot = {};
          readIdentityFields.forEach(function (field) { snapshot[field] = session[field]; });
          if (readIdentityFields.some(function (field) { return field === "dbRevision" ? !Number.isSafeInteger(snapshot[field]) || snapshot[field] < 0 || Object.is(snapshot[field], -0) : typeof snapshot[field] !== "string" || !snapshot[field]; })) throw new Error("分析会话身份尚未就绪，请刷新后重试");
          return Object.freeze(snapshot);
        }
        function readData(type, target, params, engine, session) {
          var expected;
          try { expected = ["analyses", "analysis_result", "approvals", "debug_state"].indexOf(type) === -1 ? captureReadSnapshot(session) : null; }
          catch (error) { return Promise.reject(error); }
          var base = { type: type, target: target || "" };
          if (engine || ["analyses", "analysis_result"].indexOf(type) === -1) base.engine = engine || "reverse";
          Object.keys(params || {}).forEach(function (key) { if (params[key] !== undefined && params[key] !== null) base[key] = params[key]; });
          if (expected) base.expected_snapshot = JSON.stringify(expected);
          var query = new URLSearchParams(base);
          return fetch("/ig5-data?" + query.toString()).then(function (r) {
            if (!r.ok) throw new Error("读取失败 (HTTP " + r.status + ")");
            return r.json();
          }).then(function (j) {
            if (!j || j.error) throw new Error((j && j.error) || "空响应");
            if (expected && readIdentityFields.some(function (field) { return j[field] !== expected[field] || !j.data || !j.data._ig5 || j.data._ig5[field] !== expected[field]; })) throw new Error("分析会话已变化，请刷新后重试");
            return normalizeReadData(type, j.data);
          });
        }

        // Every selection owns a generation; old reads must never paint a newer selection.
        function makeRequestGate() {
          var generation = 0;
          return { next: function () { generation += 1; return generation; }, isCurrent: function (value) { return value === generation; } };
        }

        function highlightParts(code, variable) {
          var source = String(code || "");
          if (!variable) return [{ text: source, match: false }];
          var escaped = String(variable).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          var re = new RegExp("(^|[^A-Za-z0-9_$])(" + escaped + ")(?=$|[^A-Za-z0-9_$])", "g");
          var result = [], position = 0, match;
          while ((match = re.exec(source))) {
            var start = match.index + match[1].length;
            if (start > position) result.push({ text: source.slice(position, start), match: false });
            result.push({ text: match[2], match: true });
            position = start + match[2].length;
          }
          if (position < source.length || !result.length) result.push({ text: source.slice(position), match: false });
          return result;
        }

        function renderCodeLines(lines, variable) {
          return (lines || []).map(function (line, index) {
            var code = typeof line === "string" ? line : (line.code || line.text || "");
            var parts = highlightParts(code, variable);
            return el("span", { key: index, className: "ig5-code-line" + (parts.some(function (p) { return p.match; }) ? " focused" : "") },
              el("span", { style: { opacity: 0.5, display: "inline-block", width: 46, userSelect: "none" } }, String(line.line_no || index + 1)),
              parts.map(function (p, i) { return p.match ? el("mark", { key: i }, p.text) : p.text; }));
          });
        }

        function layoutCfg(cfg) {
          var raw = Array.isArray(cfg && cfg.blocks) ? cfg.blocks : [];
          var nodes = raw.slice(0, 300).map(function (b) { return Object.assign({}, b, { id: String(b.id), succs: (b.succs || []).map(String) }); });
          var byId = Object.create(null), ranks = Object.create(null), levels = Object.create(null), seen = Object.create(null), edges = [];
          nodes.forEach(function (n) { byId[n.id] = n; });
          var sourceEdges = Array.isArray(cfg && cfg.edges) ? cfg.edges : nodes.reduce(function (out, n) { return out.concat(n.succs.map(function (to) { return { from: n.id, to: to }; })); }, []);
          sourceEdges.forEach(function (e) {
            var from = String(e.from), to = String(e.to), key = from + ":" + to;
            if (!byId[from] || !byId[to] || seen[key]) return;
            seen[key] = true; edges.push({ from: from, to: to, label: String(e.label || "") });
            if (byId[from].succs.indexOf(to) < 0) byId[from].succs.push(to);
          });
          var maxRank = -1;
          nodes.forEach(function (root) {
            if (ranks[root.id] !== undefined) return;
            ranks[root.id] = maxRank + 1;
            var queue = [root.id];
            while (queue.length) {
              var id = queue.shift(), rank = ranks[id]; maxRank = Math.max(maxRank, rank);
              byId[id].succs.forEach(function (to) { if (byId[to] && ranks[to] === undefined) { ranks[to] = rank + 1; queue.push(to); } });
            }
          });
          var width = 300;
          nodes.forEach(function (n) {
            var rank = ranks[n.id], column = levels[rank] || 0; levels[rank] = column + 1;
            n.x = 44 + column * 290; n.y = 36 + rank * 132; n.width = 244; n.height = 88;
            width = Math.max(width, n.x + 290);
          });
          edges.forEach(function (e) {
            var a = byId[e.from], b = byId[e.to], back = b.y <= a.y;
            var x1 = a.x + a.width / 2, y1 = a.y + a.height, x2 = b.x + b.width / 2, y2 = b.y;
            if (back) {
              x1 = a.x + a.width; y1 = a.y + a.height / 2; x2 = b.x + b.width; y2 = b.y + b.height / 2;
              var side = Math.max(x1, x2) + 28;
              e.path = "M " + x1 + " " + y1 + " C " + side + " " + y1 + ", " + side + " " + y2 + ", " + x2 + " " + y2;
              e.labelX = side; e.labelY = (y1 + y2) / 2;
            } else {
              var mid = (y1 + y2) / 2;
              e.path = "M " + x1 + " " + y1 + " C " + x1 + " " + mid + ", " + x2 + " " + mid + ", " + x2 + " " + y2;
              e.labelX = (x1 + x2) / 2 + 7; e.labelY = mid;
            }
            var branch = a.succs.indexOf(e.to);
            e.label = e.label || (back ? "回边" : (a.succs.length > 1 ? "分支 " + (branch + 1) : "继续"));
            e.color = back ? "#c084fc" : (a.succs.length > 1 && branch > 0 ? "#fbbf24" : "#60a5fa");
          });
          return { nodes: nodes, edges: edges, width: width, height: Math.max(180, (maxRank + 1) * 132 + 40), truncated: raw.length > nodes.length };
        }

        function CfgGraph(props) {
          var model = react.useMemo(function () { return layoutCfg(props.cfg); }, [props.cfg]);
          var cameraPair = react.useState({ scale: 1, x: 0, y: 0 });
          var camera = cameraPair[0], setCamera = cameraPair[1], drag = react.useRef(null);
          var canvas = react.useRef(null), viewportPair = react.useState({ width: 800, height: 520 });
          var viewport = viewportPair[0], setViewport = viewportPair[1];
          var pointers = react.useRef({}), pinch = react.useRef(null);
          var touches = react.useRef({});
          var marker = react.useRef("ig5-arrow-" + Math.random().toString(36).slice(2));
          function fitCamera() { return cfgFitCamera(model, viewport.width, viewport.height); }
          react.useEffect(function () {
            if (!canvas.current) return;
            var svg = canvas.current;
            function wheel(e) {
              e.preventDefault();
              var point = cfgPointerPoint(e, svg.viewBox.baseVal.width);
              setCamera(function (c) {
                var scale = Math.max(0.01, Math.min(4, c.scale * Math.exp(-e.deltaY * 0.001)));
                return { scale: scale, x: point.x - (point.x - c.x) * scale / c.scale, y: point.y - (point.y - c.y) * scale / c.scale };
              });
            }
            svg.addEventListener("wheel", wheel, { passive: false });
            var observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(function (entries) {
              var box = entries[0].contentRect;
              if (box.width > 0 && box.height > 0) setViewport({ width: box.width, height: box.height });
            });
            if (observer) observer.observe(svg);
            return function () { if (observer) observer.disconnect(); svg.removeEventListener("wheel", wheel); };
          }, []);
          react.useEffect(function () { setCamera(fitCamera()); }, [props.cfg, viewport.width, viewport.height]);
          function zoom(factor) { setCamera(function (c) {
            var scale = Math.max(0.01, Math.min(4, c.scale * factor)), x = viewport.width / 2, y = viewport.height / 2;
            return { scale: scale, x: x - (x - c.x) * scale / c.scale, y: y - (y - c.y) * scale / c.scale };
          }); }
          return el("div", null,
            el("div", { className: "ig5-form-row" },
              el("button", { className: "ig5-btn", onClick: function () { zoom(1.2); }, "aria-label": "放大控制流图" }, "+"),
              el("button", { className: "ig5-btn", onClick: function () { zoom(1 / 1.2); }, "aria-label": "缩小控制流图" }, "−"),
              el("button", { className: "ig5-btn", onClick: function () { setCamera(fitCamera()); } }, "适应画布"),
              el("span", { className: "ig5-card-sub" }, "拖动平移 · 双指缩放 · 触控点按 / 鼠标双击基本块 · " + Math.round(camera.scale * 100) + "%")),
            el("svg", { ref: canvas, className: "ig5-cfg-canvas", viewBox: "0 0 " + viewport.width + " " + viewport.height, role: "img", "aria-label": "控制流图",
              onPointerDown: function (e) {
                var node = e.target.closest && e.target.closest(".ig5-cfg-node");
                if (e.pointerType !== "touch" && (e.button !== 0 || node)) return;
                var point = cfgPointerPoint(e, viewport.width);
                pointers.current[e.pointerId] = point;
                if (e.pointerType === "touch") touches.current[e.pointerId] = { start: point, moved: false, multi: false, block: node && model.nodes.find(function (n) { return n.id === node.getAttribute("data-node-id"); }) };
                var points = Object.values(pointers.current);
                if (points.length >= 2) Object.values(touches.current).forEach(function (t) { t.multi = true; });
                if (points.length === 2) { pinch.current = cfgPinchStart(points, camera); drag.current = null; }
                else if (points.length > 2) { pinch.current = null; drag.current = null; }
                else drag.current = { point: point, camera: camera };
                e.currentTarget.setPointerCapture(e.pointerId);
              },
              onPointerMove: function (e) {
                if (!pointers.current[e.pointerId]) return;
                var point = cfgPointerPoint(e, viewport.width); pointers.current[e.pointerId] = point;
                var touch = touches.current[e.pointerId];
                if (touch && Math.hypot(point.x - touch.start.x, point.y - touch.start.y) > 8) touch.moved = true;
                var points = Object.values(pointers.current);
                if (pinch.current && points.length === 2) setCamera(cfgPinchCamera(pinch.current, points));
                else if (drag.current) setCamera(Object.assign({}, drag.current.camera, { x: drag.current.camera.x + point.x - drag.current.point.x, y: drag.current.camera.y + point.y - drag.current.point.y }));
              },
              onPointerUp: function (e) {
                var touch = touches.current[e.pointerId];
                if (touch) { var point = cfgPointerPoint(e, viewport.width); if (Math.hypot(point.x - touch.start.x, point.y - touch.start.y) > 8) touch.moved = true; }
                if (touch && !touch.moved && !touch.multi && touch.block) props.onOpen(touch.block);
                delete touches.current[e.pointerId]; delete pointers.current[e.pointerId]; pinch.current = null;
                var points = Object.values(pointers.current); drag.current = points.length === 1 ? { point: points[0], camera: camera } : null;
              },
              onPointerCancel: function () { pointers.current = {}; touches.current = {}; pinch.current = null; drag.current = null; }
            },
              el("defs", null, el("marker", { id: marker.current, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto-start-reverse" }, el("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "#94a3b8" }))),
              el("g", { transform: "translate(" + camera.x + " " + camera.y + ") scale(" + camera.scale + ")" },
                model.edges.map(function (e, i) { return el("g", { key: i }, el("path", { className: "ig5-cfg-edge", d: e.path, stroke: e.color, markerEnd: "url(#" + marker.current + ")" }), el("text", { className: "ig5-cfg-edge-label", x: e.labelX, y: e.labelY }, e.label)); }),
                model.nodes.map(function (n) { return el("g", { key: n.id, className: "ig5-cfg-node", "data-node-id": n.id, transform: "translate(" + n.x + " " + n.y + ")", role: "button", tabIndex: 0, "aria-label": "基本块 " + n.id + " " + n.start,
                  onDoubleClick: function () { props.onOpen(n); }, onKeyDown: function (e) { if (e.key === "Enter") props.onOpen(n); } },
                  el("title", null, n.start + " → " + n.end + "\n" + (n.first || "") + "\n" + (n.last || "")),
                  el("rect", { width: n.width, height: n.height, rx: 7 }),
                  el("text", { x: 12, y: 22, className: "ig5-mono" }, "B" + n.id + " · " + n.start),
                  el("text", { x: 12, y: 43, className: "ig5-mono" }, String(n.first || "").slice(0, 31)),
                  el("text", { x: 12, y: 64, className: "ig5-mono" }, String(n.last || "").slice(0, 31)),
                  el("text", { x: 12, y: 81 }, n.insns + " 条指令")); })
              )),
            model.truncated ? el("div", { className: "ig5-card-sub" }, "图中显示前 300 个基本块；完整拓扑可复制 Mermaid 查看。") : null);
        }

        function cfgFitCamera(model, width, height) {
          var scale = Math.max(0.01, Math.min(1, Math.max(1, width - 24) / model.width, Math.max(1, height - 24) / model.height));
          return { scale: scale, x: (width - model.width * scale) / 2, y: (height - model.height * scale) / 2 };
        }
        function cfgPointerPoint(e, width) {
          var svg = e.currentTarget;
          if (svg.createSVGPoint && svg.getScreenCTM) {
            var matrix = svg.getScreenCTM();
            if (matrix) { var p = svg.createSVGPoint(); p.x = e.clientX; p.y = e.clientY; return p.matrixTransform(matrix.inverse()); }
          }
          var box = svg.getBoundingClientRect(), factor = width / Math.max(1, box.width);
          return { x: (e.clientX - (box.left || 0)) * factor, y: (e.clientY - (box.top || 0)) * factor };
        }
        function cfgPinchStart(points, camera) {
          return { distance: Math.max(1, Math.hypot(points[1].x - points[0].x, points[1].y - points[0].y)),
            center: { x: (points[0].x + points[1].x) / 2, y: (points[0].y + points[1].y) / 2 }, camera: camera };
        }
        function cfgPinchCamera(start, points) {
          var distance = Math.hypot(points[1].x - points[0].x, points[1].y - points[0].y),
            center = { x: (points[0].x + points[1].x) / 2, y: (points[0].y + points[1].y) / 2 },
            scale = Math.max(0.01, Math.min(4, start.camera.scale * distance / start.distance));
          return { scale: scale, x: center.x - (start.center.x - start.camera.x) * scale / start.camera.scale,
            y: center.y - (start.center.y - start.camera.y) * scale / start.camera.scale };
        }

        function normalizedTarget(target) {
          var value = String(target || "");
          return /^[A-Za-z]:[\\/]/.test(value) || /^\\\\/.test(value) ? value.replace(/\//g, "\\").toLowerCase() : value;
        }
        function normalizeAudit(item) {
          var args = item.args || item.arguments || {}, result = item.detail || (item.result && (item.result.value || item.result)) || {};
          return { tool: String(item.tool || item.name || "未知工具"), target: (result.destination && result.destination.target) || (result._ig5 && result._ig5.target) || args.target || item.target || "", engine: (result.destination && result.destination.engine) || (result._ig5 && result._ig5.engine) || args.engine || item.engine || "reverse", time: item.ts || item.time || "", ea: result.ea || args.ea || "", fileOffset: result.fileOffset, before: result.before, after: result.after, isError: item.isError === true || !!(item.result && item.result.isError), detail: typeof result === "string" ? result : String(result.error || result.note || "") };
        }
        function normalizeScan(data) {
          data = data || {};
          function rows(primary, legacy) { return Array.isArray(data[primary]) ? data[primary] : Array.isArray(data[legacy]) ? data[legacy] : []; }
          return {
            entropies: rows("entropies", "entropy").map(function (item) { return Object.assign({}, item, { name: String(item.name || item.segment || "未命名节段") }); }),
            crypto_markers: rows("crypto_markers", "crypto").map(function (item) { return typeof item === "string" ? { name: item } : Object.assign({}, item, { name: String(item.name || item.marker || "未命名常量") }); }),
            suspicious_apis: rows("suspicious_apis", "suspiciousApis").map(function (item) { return typeof item === "string" ? { api: item, module: "" } : Object.assign({}, item, { api: String(item.api || item.name || "未命名 API"), module: String(item.module || "") }); }),
            truncated: data.truncated === true, coverage: data.coverage || {}, limits: data.limits || {}, sourceEngine: data.sourceEngine,
          };
        }
        function buildAnalysisDraft(kind, action, input, parameters, target, engine) {
          if (!["crypto", "protocol"].includes(kind)) throw new Error("请选择解密或协议分析");
          var allowed = kind === "crypto" ? ["inspect", "transform", "recover", "verify"] : ["inspect", "capture", "decode", "infer"];
          if (allowed.indexOf(action) < 0) throw new Error("分析操作无效");
          var extra = parameters ? JSON.parse(parameters) : {};
          if (!extra || typeof extra !== "object" || Array.isArray(extra)) throw new Error("附加参数必须是 JSON 对象");
          var blocked = ["input", "action", "target", "engine", "__proto__", "constructor", "prototype"];
          if (Object.keys(extra).some(function (key) { return blocked.indexOf(key) >= 0; })) throw new Error("附加参数不能覆盖来源或操作");
          var args = Object.assign({ action: action, input: input }, extra);
          if (target) args.target = target;
          if (target && engine) args.engine = engine;
          return "如当前为 Core 工具面，先调用 ig5_profile toolset=full。请调用 ig5_" + kind + "，参数如下；先检查来源与算法／字段假设，再发送：\n" + JSON.stringify(args, null, 2);
        }
        function analysisTemplate(kind, action) {
          if (kind === "crypto" && action === "recover") return { recovery: { method: "auto", max_trials: 4096, max_candidates: 4, max_work_bytes: 16777216 } };
          if (kind === "protocol" && action === "infer") return { inference: { format: "stream", boundary: "unknown", min_frames: 3, max_candidates: 4 } };
          if (kind === "crypto" && action === "transform") return { recipe: { kind: "xor", key_ref: { ref: "sha256:完整候选密钥引用", result_id: "恢复报告UUID" } } };
          if (kind === "protocol" && action === "decode") return { schema: { fields: [] }, framing: { type: "delimiter", delimiterHex: "0a", includeDelimiter: true } };
          return {};
        }
        function buildStructDraft(target, declaration, engine) {
          return "请调用 ig5_struct，参数如下，并通过宿主审批门后执行：\n" + JSON.stringify(Object.assign({ target: target, action: "define", decl: String(declaration).trim() }, engine ? { engine: engine } : {}), null, 2);
        }

        function StructEditor(props) {
          var declPair = react.useState(props.declaration || "struct Packet {\n  int id;\n  char payload[32];\n};"), decl = declPair[0], setDecl = declPair[1];
          var draftPair = react.useState(""), draft = draftPair[0], setDraft = draftPair[1];
          var noticePair = react.useState(""), notice = noticePair[0], setNotice = noticePair[1];
          react.useEffect(function () { setDecl(props.declaration || "struct Packet {\n  int id;\n  char payload[32];\n};"); setDraft(""); setNotice(""); }, [props.declaration, props.revision, props.target, props.engine]);
          function insertDraft() {
            try {
              var actions = props.inputActions;
              if (!actions || typeof actions.captureInsertion !== "function" || typeof actions.insertText !== "function") { setNotice("当前视图未提供会话编辑器接口，请复制下方草稿到会话后发送。"); return; }
              var span = actions.captureInsertion();
              if (!actions.insertText("\n" + draft + "\n", span)) { setNotice("会话草稿正在变化或编辑器暂不可用，请重试或复制草稿。"); return; }
              if (typeof actions.persistDraft === "function") actions.persistDraft();
              setNotice("已插入会话草稿，尚未发送或执行；请检查后发送，并在宿主审批门批准。");
            } catch (e) { setNotice("插入草稿失败，请复制下方草稿：" + String(e.message || e)); }
          }
          return el("div", { style: { marginBottom: 12, borderBottom: "1px solid var(--dsw-alias-border-l2)", paddingBottom: 12 } },
            el("div", { className: "ig5-card-title-text" }, props.name ? "编辑类型声明 · " + props.name : "新增结构体声明"),
            el("p", { className: "ig5-card-sub" }, "编辑 C 声明后生成待发送草稿。修改现有类型时保留类型名；数据库仅在会话发送并获宿主审批后变更。"),
            el("textarea", { className: "ig5-textarea ig5-mono", "aria-label": "C 结构体声明", value: decl, onChange: function (e) { setDecl(e.target.value); setDraft(""); setNotice(""); } }),
            el("div", { className: "ig5-form-row" }, el("button", { className: "ig5-btn ig5-btn-primary", disabled: !props.target || !decl.trim(), onClick: function () { setDraft(buildStructDraft(props.target, decl, props.engine || "reverse")); setNotice("草稿已生成，尚未发送或执行。"); } }, "生成审批草稿")),
            draft ? el("div", null,
              el("textarea", { className: "ig5-textarea ig5-mono", "aria-label": "待发送工具调用草稿", value: draft, onChange: function (e) { setDraft(e.target.value); } }),
              el("div", { className: "ig5-form-row" }, el("button", { className: "ig5-btn", onClick: insertDraft }, "插入会话草稿（待发送）"), el("button", { className: "ig5-btn", onClick: function () { if (navigator.clipboard) navigator.clipboard.writeText(draft).then(function () { setNotice("已复制草稿，尚未发送或执行。"); }).catch(function () { setNotice("复制失败，请手动选择草稿复制。"); }); else setNotice("请手动选择草稿复制。"); } }, "复制草稿"))) : null,
            notice ? el("div", { role: "status", className: "ig5-card-sub" }, notice) : null);
        }

        function activateTopTab(label) {
          try {
            var tabs = document.querySelectorAll('button[role="tab"]');
            for (var i = 0; i < tabs.length; i++) {
              if ((tabs[i].textContent || "").indexOf(label) !== -1 || (tabs[i].textContent || "").indexOf("工作台") !== -1) {
                if (tabs[i].getAttribute("aria-selected") !== "true") tabs[i].click();
                diag("top-tab-activated", label);
                return true;
              }
            }
          } catch (e) {}
          return false;
        }

        /* ── 核心工作台主界面 (Professional Workbench) ── */
        function Ig5Workbench(props) {
          useStyleOnce();
          var feed = useJobsFeed();
          var dash = useDash(props);

          var activeTabState = react.useState("funcs");
          var activeTab = activeTabState[0];
          var setActiveTab = activeTabState[1];

          var allSessions = (feed && feed.sessions) || [];
          var sessions = allSessions.filter(function (s) { return s.alive && s.engine !== "x64dbg"; });
          var currentTargetState = react.useState(null);
          var selectedIdentity = currentTargetState[0];
          var setSelectedIdentity = currentTargetState[1];
          var currentSession = sessions.find(function (s) { return sessionIdentity(s) === selectedIdentity; }) || sessions[0] || null;
          var selectedTarget = currentSession && currentSession.target;
          var engine = (currentSession && currentSession.engine) || (feed && feed.config && feed.config.engine) || "reverse";
          var currentIdentity = currentSession ? sessionIdentity(currentSession) : "none";
          // Polling can miss a close/reopen interval; a new database owner must remount every static result view.
          var viewKey = JSON.stringify([currentIdentity, currentSession && currentSession.projectId || "", currentSession && currentSession.artifactId || "legacy", currentSession && currentSession.sha256 || "", currentSession && currentSession.provider || "", currentSession && currentSession.attachmentId || "", currentSession && currentSession.dbRevision || 0]);
          var focusPair = react.useState(null), focus = focusPair[0], setFocus = focusPair[1];
          var focusNoticePair = react.useState(""), focusNotice = focusNoticePair[0], setFocusNotice = focusNoticePair[1];
          var focusCounter = react.useRef(0);
          var visibleFocus = focus && (!focus.artifactId || (currentSession && focus.artifactId === currentSession.artifactId)) && (!focus.projectId || (currentSession && focus.projectId === currentSession.projectId)) ? focus : null;

          react.useEffect(function () {
            if (currentSession && currentIdentity !== selectedIdentity) setSelectedIdentity(currentIdentity);
          }, [currentIdentity, selectedIdentity]);

          function acceptFocus(location) {
            var match = sessions.find(function (s) { return (s.engine || "reverse") === location.engine && normalizedTarget(s.target) === normalizedTarget(location.target) && (!location.artifactId || s.artifactId === location.artifactId) && (!location.projectId || s.projectId === location.projectId); });
            if (!match) { setFocusNotice("导航位置与当前已打开的引擎/样本身份不匹配，请先打开对应样本。"); return; }
            setSelectedIdentity(sessionIdentity(match)); setActiveTab("funcs"); setFocusNotice("");
            setFocus(Object.assign({}, location, { token: ++focusCounter.current }));
          }
          function navigate(location) {
            var request = Object.assign({ v: 1, target: selectedTarget, engine: engine, projectId: currentSession && currentSession.projectId, artifactId: currentSession && currentSession.artifactId }, location);
            var parsed = parseWorkbenchFocus(JSON.stringify(request));
            if (!parsed) { setFocusNotice("该位置缺少明确的静态地址，无法导航。"); return; }
            if (typeof props.openView === "function") props.openView("ig5", JSON.stringify(parsed));
            else acceptFocus(parsed);
          }
          react.useEffect(function () {
            var request = props.viewRequest;
            if (!request || request.view !== "ig5" || !feed) return;
            var parsed = parseWorkbenchFocus(request.focus);
            if (parsed) acceptFocus(parsed);
            else if (request.focus) setFocusNotice("无法识别地址导航请求；仅接受带引擎与样本的静态 VA。");
            if (typeof props.completeViewRequest === "function") props.completeViewRequest();
          }, [props.viewRequest && props.viewRequest.focus, !!feed]);

          var jobs = (feed && feed.jobs) || [];
          var runningJobs = jobs.filter(function (j) { return j.state === "running"; });

          return el(
            "div",
            { className: "ig5-root" },
            // 1. 全局概览与状态磁贴卡片
            el(Ig5OverviewCard, {
              currentSession: currentSession,
              sessions: sessions,
              selectedIdentity: currentIdentity,
              onSelectTarget: function (identity) { setSelectedIdentity(identity); setFocus(null); setFocusNotice(""); },
              runningCount: runningJobs.length,
              runningJob: runningJobs[0] || null,
              dash: dash,
            }),
            el(Ig5EnvironmentCard, { config: feed && feed.config }),
            // 2. 领域分段胶囊导航栏 (.ig5-kinds)
            el(
              "div",
              { style: { marginBottom: 12, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 } },
              el(Ig5NavTabs, {
                activeTab: activeTab,
                onSelectTab: setActiveTab,
                nFuncs: (currentSession && currentSession.n_funcs) || null,
              }),
              el("div", { className: "ig5-card-sub ig5-mono" },
                selectedTarget ? engineName(engine) + " · " + basename(selectedTarget) + " · 修订 " + ((currentSession && currentSession.dbRevision) || 0) : "等待静态样本载入 (ig5_open)"
              )
            ),
            // 3. 对应能力域工作区视图
            focusNotice ? el("p", { className: "ig5-error", role: "status" }, focusNotice) : null,
            activeTab === "funcs" && el(Ig5FunctionsView, { key: viewKey, target: selectedTarget, engine: engine, session: currentSession, focus: visibleFocus, onNavigate: navigate }),
            activeTab === "strings" && el(Ig5StringsView, { key: viewKey, target: selectedTarget, engine: engine, session: currentSession, onNavigate: navigate }),
            activeTab === "listing" && el(Ig5ListingView, { key: viewKey, target: selectedTarget, engine: engine, session: currentSession, inputActions: props.inputActions }),
            activeTab === "scan" && el(Ig5ScanView, { key: viewKey, target: selectedTarget, engine: engine, session: currentSession }),
            activeTab === "analysis" && el(Ig5AnalysisView, { key: viewKey, target: selectedTarget, engine: engine, inputActions: props.inputActions }),
            activeTab === "patches" && el(Ig5PatchesView, { key: viewKey, target: selectedTarget, engine: engine }),
            activeTab === "runtime" && el(Ig5RuntimeView, { sessions: allSessions.filter(function (s) { return s.engine === "x64dbg"; }), refresh: feed && feed.now }),
            activeTab === "tools" && el(Ig5ToolsMatrixView, { dash: dash, session: currentSession, feed: feed })
          );
        }

        function Ig5EnvironmentCard(props) {
          var config = props.config;
          if (!config || !config.host) return null;
          var host = config.host, engines = Array.isArray(config.engines) ? config.engines : [];
          return el("div", { className: "ig5-card ig5-environment" },
            el("div", { className: "ig5-card-title" }, el("b", null, "本机执行环境"),
              el("span", { className: "ig5-chip " + (host.supported ? "read" : "warn") }, host.id || "待确认")),
            el("p", { className: "ig5-card-sub" }, host.supported ? "分析引擎在当前宿主设备执行；能力以下列实际可用状态为准。" : "当前宿主尚无匹配的本地引擎执行方案。移动界面可用不代表引擎已移植。"),
            el("div", { className: "ig5-form-row" }, engines.map(function (engine) {
              var failed = engine.id === "reverse" && engine.readiness === "startup-failed";
              var builtin = engine.id === "reverse" && engine.provider === "ghidra" && engine.distribution === "bundled";
              var pending = engine.id === "reverse" && engine.available && engine.runtimeReady !== true;
              return el("span", { key: engine.id, className: "ig5-chip " + (engine.available && !failed && !pending ? "read" : "warn") },
                (engine.label || engineName(engine.id)) + " · " + (failed ? "启动失败" : engine.available ? (pending ? builtin ? "待启动验证" : "已发现，待验证" : "可用") : "不可用") + (engine.source === "bundled" && !builtin ? " · 随包" : ""));
            })),
            engines.some(function (engine) { return engine.id === "reverse" && engine.provider === "ghidra" && engine.distribution === "bundled"; }) ? el("p", { className: "ig5-card-sub" }, "Reverse 内置分析由五代核心与 Ghidra 提供；本机扩展可按配置单独启用。") : null,
            engines.filter(function (engine) { return engine.reason && (!engine.available || engine.id === "reverse"); }).map(function (engine) {
              return el("p", { key: engine.id, className: "ig5-card-sub" }, (engine.label || engineName(engine.id)) + ": " + String(engine.reason).slice(0, 300));
            }));
        }

        /* ── 全局概览卡片 (Overview & Stat Tiles) ── */
        function Ig5RuntimeView(props) {
          var sessions = props.sessions || [], selectedPair = react.useState(null), selected = selectedPair[0], setSelected = selectedPair[1];
          var session = sessions.find(function (item) { return sessionIdentity(item) === selected; }) || sessions[0];
          var scopeKey = session ? sessionIdentity(session) + ":" + (session.artifactId || "legacy") + ":" + (session.attachmentId || "") : "none";
          var statePair = react.useState({ scope: null, loading: false, data: null, error: null }), state = statePair[0], setState = statePair[1];
          react.useEffect(function () {
            var alive = true;
            if (!session) { setState({ scope: scopeKey, loading: false, data: null, error: null }); return; }
            setState(function (old) { return { scope: scopeKey, loading: true, data: old.scope === scopeKey ? old.data : null, error: null }; });
            readData("debug_state", session.target, {}, "x64dbg").then(function (data) { if (alive) setState({ scope: scopeKey, loading: false, data: data, error: null }); }).catch(function (error) { if (alive) setState({ scope: scopeKey, loading: false, data: null, error: String(error.message || error) }); });
            return function () { alive = false; };
          }, [scopeKey, props.refresh]);
          var visibleState = state.scope === scopeKey ? state : { loading: !!session, data: null, error: null };
          var data = visibleState.data || {};
          return el("div", { className: "ig5-card" },
            el("div", { className: "ig5-card-title" }, el("b", null, "x64dbg · 最近运行态快照"), el("span", { className: "ig5-chip read" }, "只读缓存")),
            el("p", { className: "ig5-card-sub" }, "此页只读取已记录的状态，不启动、继续、附加或修改样本。运行控制仍需会话中的明确操作与宿主审批。"),
            sessions.length > 1 ? el("select", { className: "ig5-select", "aria-label": "运行态会话", value: sessionIdentity(session), onChange: function (e) { setSelected(e.target.value); } }, sessions.map(function (item) { return el("option", { key: sessionIdentity(item), value: sessionIdentity(item) }, basename(item.target)); })) : null,
            !session ? el("p", { className: "ig5-card-sub" }, "没有已登记的 x64dbg 运行态会话。") : el("p", { className: "ig5-mono" }, basename(session.target) + " · " + (typeof data.state === "string" ? data.state : "状态见快照") + " · run " + (data.runId || "—") + " · stop " + (data.stopSeq == null ? "—" : data.stopSeq)),
            visibleState.loading ? el("p", { role: "status" }, "读取最近快照…") : null,
            visibleState.error ? el("p", { className: "ig5-error", role: "alert" }, visibleState.error) : null,
            data.note ? el("p", { className: "ig5-card-sub" }, data.note) : null,
            visibleState.data ? el("pre", { className: "ig5-code-box ig5-mono" }, JSON.stringify(visibleState.data, null, 2).slice(0, 64000)) : null);
        }
        function Ig5IrView(props) {
          var levelPair = react.useState("high"), level = levelPair[0], setLevel = levelPair[1];
          var pair = react.useState({ loading: true, data: null, error: null }), state = pair[0], setState = pair[1];
          react.useEffect(function () {
            var alive = true; setState({ loading: true, data: null, error: null });
            readData("ir", props.target, { ea: props.ea, level: level, limit: 120 }, props.engine, props.session).then(function (data) { if (alive) setState({ loading: false, data: data, error: null }); }).catch(function (error) { if (alive) setState({ loading: false, data: null, error: String(error.message || error) }); });
            return function () { alive = false; };
          }, [props.target, props.engine, props.ea, level]);
          var serialized = state.data ? JSON.stringify(state.data, null, 2) : "";
          return el("div", null, el("div", { className: "ig5-form-row" }, el("b", null, "Ghidra p-code · " + level), el("select", { className: "ig5-select", "aria-label": "p-code 层级", value: level, onChange: function (e) { setLevel(e.target.value); } }, el("option", { value: "high" }, "High p-code"), el("option", { value: "raw" }, "Raw p-code"))), el("p", { className: "ig5-card-sub" }, "Ghidra IR 保留自身语义，不对应 Reverse 微码成熟度。"), state.loading ? el("p", null, "读取 IR…") : state.error ? el("p", { className: "ig5-error", role: "alert" }, state.error) : el("pre", { className: "ig5-code-box ig5-mono" }, serialized.slice(0, 64000)), serialized.length > 64000 ? el("p", { className: "ig5-card-sub" }, "视图已截断到 64,000 字符；请按范围读取完整工件。") : null);
        }
        function Ig5OverviewCard(props) {
          var session = props.currentSession;
          var sessions = props.sessions || [];
          var isBusy = props.runningCount > 0;
          var isPartial = !!(session && session.partial);
          var dash = props.dash;
          var runningJob = props.runningJob;

          return el(
            "div",
            { className: "ig5-card" },
            el(
              "div",
              { className: "ig5-card-title" },
              el(
                "div",
                { className: "ig5-card-title-text" },
                el("span", null, "🛠️ 无限五代 · 逆向工作台"),
                el("span", { className: "ig5-chip read ig5-mono" }, (session ? engineName(session.engine) : "IG5") + " · v" + VERSION),
                el(
                  "span",
                  { className: "ig5-chip " + (isBusy || isPartial ? "warn" : "success") },
                  el("span", {
                    className: "ig5-dot " + (isBusy ? "ig5-pulse" : ""),
                    style: { background: isBusy || isPartial ? "var(--dsw-alias-state-warn-primary, #f59e0b)" : "var(--dsw-alias-state-success-primary, #10b981)" }
                  }),
                  isBusy ? "正在分析 (" + (runningJob && runningJob.stage ? runningJob.stage : "执行中") + ")" : isPartial ? "部分分析结果" : session ? "分析会话就绪" : "尚无静态会话"
                )
              ),
              el(
                "div",
                { style: { display: "flex", alignItems: "center", gap: 8 } },
                sessions.length > 1
                  ? el(
                      "select",
                      {
                        className: "ig5-select ig5-mono",
                        "aria-label": "静态引擎与样本",
                        value: props.selectedIdentity || "",
                        onChange: function (e) { props.onSelectTarget(e.target.value); }
                      },
                      sessions.map(function (s) {
                        return el("option", { key: sessionIdentity(s), value: sessionIdentity(s) }, engineName(s.engine) + " · " + basename(s.target) + " · r" + (s.dbRevision || 0));
                      })
                    )
                  : null,
                el(
                  "button",
                  {
                    className: "ig5-btn",
                    title: "验证所选分析会话的只读函数列表响应",
                    disabled: !session,
                    onClick: function () {
                      readData("funcs", session.target, { limit: 1 }, session.engine || "reverse", session)
                        .then(function () { alert("已收到 " + engineName(session.engine) + " 的只读函数列表响应。"); })
                        .catch(function (err) { alert("读取异常: " + err); });
                    }
                  },
                  "验证读取"
                )
              )
            ),
            runningJob
              ? el(
                  "div",
                  { style: { marginBottom: 12, padding: "8px 10px", background: "var(--dsw-alias-bg-layer-2)", borderRadius: 6 } },
                  el(
                    "div",
                    { style: { display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 } },
                    el("span", { style: { color: "var(--dsw-alias-brand-primary)" } },
                      "⚡ " + (runningJob.label || "正在自动反编译与扫描") + " · 阶段: " + (runningJob.stage || "analyzing")
                    ),
                    el("span", { className: "ig5-mono" }, (runningJob.pct || 0) + "%")
                  ),
                  el(
                    "div",
                    { className: "ig5-track" },
                    el("div", { className: "ig5-fill", style: { width: Math.max(0, Math.min(100, runningJob.pct || 0)) + "%" } })
                  )
                )
              : null,
            el(
              "div",
              { className: "ig5-stats-grid" },
              el("div", { className: "ig5-stat" },
                el("span", { className: "ig5-stat-label" }, "目标样本 (Target)"),
                el("b", { className: "ig5-stat-value ig5-mono" }, session ? basename(session.target) : "未载入样本"),
                el("span", { className: "ig5-stat-sub" }, session ? (session.size ? session.size + " 字节" : "活跃会话") : "请下达 ig5_open")
              ),
              el("div", { className: "ig5-stat" },
                el("span", { className: "ig5-stat-label" }, "架构位数 (Arch & Bits)"),
                el("b", { className: "ig5-stat-value ig5-mono" }, session && session.bits ? session.bits + "-bit " + (session.file_type || "PE/ELF") : "—"),
                el("span", { className: "ig5-stat-sub" }, session && session.cpu ? session.cpu : "架构未返回")
              ),
              el("div", { className: "ig5-stat" },
                el("span", { className: "ig5-stat-label" }, "函数总量 (Functions)"),
                el("b", { className: "ig5-stat-value ig5-mono" }, session && session.n_funcs ? String(session.n_funcs) : "0"),
                el("span", { className: "ig5-stat-sub" }, session ? engineName(session.engine) + " 分析结果" : "尚无分析结果")
              ),
              el("div", { className: "ig5-stat" },
                el("span", { className: "ig5-stat-label" }, "节段/导入 (Sections/Imp)"),
                el("b", { className: "ig5-stat-value ig5-mono" }, session ? (session.n_segs == null ? "—" : session.n_segs) + " 段 · " + (session.n_imports == null ? "—" : session.n_imports) + " 导入" : "—"),
                el("span", { className: "ig5-stat-sub" }, session && session.projectId ? "工程 " + session.projectId : "工程身份未返回")
              ),
              el("div", { className: "ig5-stat" },
                el("span", { className: "ig5-stat-label" }, "工具调用 (Tool Calls)"),
                el("b", { className: "ig5-stat-value ig5-mono" }, String((dash && dash.calls) || 0) + " 次"),
                el("span", { className: "ig5-stat-sub" }, (dash && dash.errors) ? (dash.errors + " 次拦截/异常") : "0 拦截 · 安全运行")
              ),
              el("div", { className: "ig5-stat" },
                el("span", { className: "ig5-stat-label" }, "结构与补丁 (Types/Patch)"),
                el("b", { className: "ig5-stat-value ig5-mono" }, "类型系统/审批门"),
                el("span", { className: "ig5-stat-sub", title: session && session.artifactId || "" }, session && session.artifactId ? "样本 " + session.artifactId.slice(0, 20) + "…" : "撤销范围依各后端操作而定")
              )
            )
          );
        }

        /* ── 分段胶囊导航栏 ── */
        function Ig5NavTabs(props) {
          var tabs = [
            { id: "funcs", label: "🧩 函数/CFG/切片", tag: props.nFuncs ? String(props.nFuncs) : null },
            { id: "strings", label: "🔤 字符串常量", tag: null },
            { id: "listing", label: "📑 节段/符号/结构体", tag: null },
            { id: "scan", label: "🛡 熵与指纹侦测", tag: null },
            { id: "analysis", label: "🔐 解密与协议", tag: null },
            { id: "patches", label: "⚡ 补丁审计与回滚", tag: null },
            { id: "runtime", label: "▶ 运行态（只读）", tag: null },
            { id: "tools", label: "🧰 工具能力目录", tag: null },
          ];

          return el(
            "div",
            { className: "ig5-kinds ig5-nav-tabs" },
            tabs.map(function (t) {
              var isSel = props.activeTab === t.id;
              return el(
                "button",
                {
                  key: t.id,
                  className: "ig5-gran-btn" + (isSel ? " ig5-gran-on" : ""),
                  onClick: function () { props.onSelectTab(t.id); }
                },
                el("span", null, t.label),
                t.tag ? el("span", { className: "ig5-kind-n ig5-mono" }, t.tag) : null
              );
            })
          );
        }

        /* ── Tab 1: 函数浏览器 + 反编译 + CFG 拓扑 + 变量切片 ── */
        function Ig5FunctionsView(props) {
          var target = props.target;
          var engine = props.engine || "reverse", scopeKey = engine + "\n" + target;
          var listState = react.useState({ rows: [], total: 0, offset: 0, filter: "", userOnly: false, loading: false, error: null });
          var list = listState[0];
          var setList = listState[1];
          var collapsePair = react.useState(false), listCollapsed = collapsePair[0], setListCollapsed = collapsePair[1];

          var codeState = react.useState({ ea: null, name: null, code: null, loading: false, error: null });
          var storedCode = codeState[0];
          var curCode = storedCode.scope && storedCode.scope !== scopeKey ? { ea: null, loading: false, code: null } : storedCode;
          var setCode = codeState[1];

          var xrefsState = react.useState({ list: [], callers: [], callees: [], loading: false, xrefsError: null, callsError: null });
          var xrefs = xrefsState[0];
          var setXrefs = xrefsState[1];

          var viewModeState = react.useState("code"); // 'code' | 'cfg' | 'slice'
          var viewMode = viewModeState[0];
          var setViewMode = viewModeState[1];

          var cfgState = react.useState(null);
          var cfg = cfgState[0];
          var setCfg = cfgState[1];

          var sliceState = react.useState(null);
          var slice = sliceState[0];
          var setSlice = sliceState[1];
          var focusPair = react.useState({ variable: "", loading: false, lines: [], error: null });
          var focused = focusPair[0], setFocused = focusPair[1];
          var disasmPair = react.useState(null), disasm = disasmPair[0], setDisasm = disasmPair[1];
          var selectionGate = react.useRef(makeRequestGate()), focusGate = react.useRef(makeRequestGate()), disasmGate = react.useRef(makeRequestGate()), modeGate = react.useRef(makeRequestGate());
          var previousTarget = react.useRef(scopeKey);
          if (previousTarget.current !== scopeKey) { previousTarget.current = scopeKey; selectionGate.current.next(); focusGate.current.next(); disasmGate.current.next(); modeGate.current.next(); }
          react.useEffect(function () {
            setCode({ ea: null, name: null, code: null, loading: false, error: null }); setCfg(null); setSlice(null); setDisasm(null);
            setFocused({ variable: "", loading: false, lines: [], error: null }); setXrefs({ list: [], callers: [], callees: [], loading: false, xrefsError: null, callsError: null });
            setList(function (s) { return Object.assign({}, s, { rows: [], total: 0, offset: 0 }); });
            setListCollapsed(false);
            return function () { selectionGate.current.next(); focusGate.current.next(); disasmGate.current.next(); modeGate.current.next(); };
          }, [target, engine]);

          react.useEffect(function () {
            if (!target) return;
            var alive = true;
            setList(function (s) { return Object.assign({}, s, { loading: true, error: null }); });
            readData("funcs", target, { offset: list.offset || 0, limit: 50, filter: list.filter || "", user_only: list.userOnly ? true : undefined }, engine, props.session)
              .then(function (data) {
                if (!alive) return;
                setList(function (s) { return Object.assign({}, s, { loading: false, rows: data.funcs || [], total: data.total || 0, error: null }); });
              })
              .catch(function (e) { if (alive) setList(function (s) { return Object.assign({}, s, { loading: false, error: String(e) }); }); });
            return function () { alive = false; };
          }, [target, engine, list.offset, list.searchNonce, list.userOnly]);

          function selectFunction(ea, name) {
            var ticket = selectionGate.current.next(); focusGate.current.next(); disasmGate.current.next(); modeGate.current.next();
            setListCollapsed(true);
            function current() { return selectionGate.current.isCurrent(ticket); }
            setCode({ ea: ea, name: name, code: null, loading: true, error: null, generation: ticket, scope: scopeKey });
            setXrefs({ list: [], callers: [], callees: [], loading: true, xrefsError: null, callsError: null });
            setCfg(null);
            setSlice(null);
            setDisasm(null); setFocused({ variable: "", loading: false, lines: [], error: null });

            // 1. 获取反编译伪代码
            readData("decompile", target, { ea: ea }, engine, props.session)
              .then(function (data) {
                if (!current()) return;
                setCode({ ea: data.ea, name: data.name, code: data.code || data.preview || "(空函数)", loading: false, error: null, generation: ticket, scope: scopeKey });
              })
              .catch(function (e) { if (current()) setCode({ ea: ea, name: name, code: null, loading: false, error: String(e), generation: ticket, scope: scopeKey }); });

            // 2. 交叉引用 & 子调用
            Promise.all([
              readData("xrefs", target, { ea: ea }, engine, props.session).then(function (data) { return { data: data }; }, function (e) { return { error: String(e.message || e) }; }),
              readData("calls", target, { ea: ea }, engine, props.session).then(function (data) { return { data: data }; }, function (e) { return { error: String(e.message || e) }; })
            ]).then(function (results) {
              if (!current()) return;
              var xrefData = (results[0] && results[0].data && results[0].data.rows) || [];
              var callData = (results[1] && results[1].data && results[1].data.rows) || [];
              setXrefs({ list: xrefData, callees: callData, callers: [], loading: false, xrefsError: results[0].error || null, callsError: results[1].error || null });
            });

          }

          // Only request the selected analysis view; every pending read owns its selection generation.
          react.useEffect(function () {
            if (!target || !curCode.ea || (viewMode !== "cfg" && viewMode !== "slice")) return;
            var ticket = modeGate.current.next(), type = viewMode, ea = curCode.ea;
            if ((type === "cfg" && cfg) || (type === "slice" && slice)) return;
            readData(type, target, { ea: ea }, engine, props.session).then(function (data) {
              if (!modeGate.current.isCurrent(ticket)) return;
              if (type === "cfg") setCfg(data); else setSlice(data);
            }).catch(function (e) {
              if (!modeGate.current.isCurrent(ticket)) return;
              if (type === "cfg") setCfg({ error: String(e.message || e), blocks: [], edges: [] });
              else setSlice({ error: String(e.message || e), variables: [] });
            });
            return function () { modeGate.current.next(); };
          }, [target, engine, curCode.ea, curCode.generation, viewMode]);

          function chooseFunction(ea, name) {
            if (typeof props.onNavigate === "function") props.onNavigate({ ea: ea, name: name });
            else selectFunction(ea, name);
          }
          react.useEffect(function () {
            if (props.focus && props.focus.engine === engine && normalizedTarget(props.focus.target) === normalizedTarget(target)) selectFunction(props.focus.ea, props.focus.name);
          }, [props.focus && props.focus.token, target, engine]);

          function focusVariable(variable) {
            var ticket = focusGate.current.next();
            setFocused({ variable: variable, loading: true, lines: [], error: null });
            readData("slice", target, { ea: curCode.ea, var: variable }, engine, props.session).then(function (data) {
              if (focusGate.current.isCurrent(ticket)) setFocused({ variable: variable, loading: false, lines: data.slice_lines || [], error: null });
            }).catch(function (e) { if (focusGate.current.isCurrent(ticket)) setFocused({ variable: variable, loading: false, lines: [], error: String(e.message || e) }); });
          }

          function openBlock(block) {
            var ticket = disasmGate.current.next();
            setDisasm({ ea: block.start, block: block.id, rows: [], loading: true });
            var size = 256;
            try { var span = BigInt(block.end) - BigInt(block.start); if (span > 0n) size = Number(span > 8192n ? 8192n : span); } catch (e) {}
            readData("disasm", target, { ea: block.start, size: size, limit: 120 }, engine, props.session).then(function (data) {
              if (disasmGate.current.isCurrent(ticket)) setDisasm({ ea: block.start, block: block.id, rows: data.rows || [], loading: false, nextEa: data.nextEa });
            }).catch(function (e) { if (disasmGate.current.isCurrent(ticket)) setDisasm({ ea: block.start, block: block.id, rows: [], loading: false, error: String(e.message || e) }); });
          }

          if (!target) {
            return el("div", { className: "ig5-card", style: { textAlign: "center", padding: "40px 20px" } },
              el("p", { style: { color: "var(--dsw-alias-label-secondary)" } },
                "当前未载入逆向样本。请在会话中让模型使用「ig5_open」打开目标二进制文件。"
              )
            );
          }

          var page = Math.floor((list.offset || 0) / 50) + 1;
          var pages = Math.max(1, Math.ceil((list.total || 0) / 50));

          return el(
            "div",
            { className: "ig5-cols ig5-function-workspace", style: { alignItems: "flex-start" } },
            curCode.ea ? el("button", { className: "ig5-btn ig5-mobile-only", "aria-expanded": !listCollapsed, onClick: function () { setListCollapsed(!listCollapsed); } }, listCollapsed ? "返回函数列表" : "收起函数列表") : null,
            // 左列卡片：函数检索与分页列表
            el(
              "div",
              { className: "ig5-card ig5-col ig5-functions-list" + (curCode.ea && listCollapsed ? " is-collapsed" : "") },
              el(
                "div",
                { className: "ig5-card-title" },
                el("span", { className: "ig5-card-title-text" }, "函数浏览 (Functions)"),
                el("span", { className: "ig5-chip read ig5-mono" }, list.total + " 项")
              ),
              el(
                "div",
                { style: { display: "flex", gap: 6, marginBottom: 8, alignItems: "center" } },
                el("input", {
                  className: "ig5-input ig5-mono",
                  style: { flex: 1 },
                  placeholder: "过滤函数名并按回车...",
                  value: list.filter,
                  onChange: function (e) { setList(function (s) { return Object.assign({}, s, { filter: e.target.value }); }); },
                  onKeyDown: function (e) {
                    if (e.key === "Enter") setList(function (s) { return Object.assign({}, s, { offset: 0, searchNonce: (s.searchNonce || 0) + 1 }); });
                  }
                }),
                el("button", {
                  className: "ig5-btn" + (list.userOnly ? " ig5-btn-primary" : ""),
                  style: { fontSize: 11, padding: "4px 8px" },
                  title: "根据当前静态引擎提供的库函数标记过滤列表",
                  onClick: function () { setList(function (s) { return Object.assign({}, s, { userOnly: !s.userOnly, offset: 0 }); }); }
                }, list.userOnly ? "仅用户代码" : "全部函数")
              ),
              el(
                "div",
                { className: "ig5-table-wrap" },
                el(
                  "table",
                  { className: "ig5-table ig5-mono" },
                  el("thead", null,
                    el("tr", null,
                      el("th", { style: { width: 95 } }, "地址 (EA)"),
                      el("th", null, "函数名"),
                      el("th", { style: { width: 50, textAlign: "right" } }, "大小")
                    )
                  ),
                  el("tbody", null,
                    list.rows.map(function (f) {
                      var isSel = curCode.ea === f.ea;
                      return el(
                        "tr",
                        {
                          key: f.ea,
                          className: isSel ? "selected" : "",
                          onClick: function () { chooseFunction(f.ea, f.name); }
                        },
                        el("td", { style: { color: "var(--dsw-alias-brand-primary)" } }, f.ea),
                        el("td", { style: { fontWeight: 500 } },
                          f.name,
                          f.is_lib ? el("span", { className: "ig5-chip", style: { fontSize: 10, padding: "1px 4px", marginLeft: 6, opacity: 0.7 } }, "LIB") : null
                        ),
                        el("td", { style: { textAlign: "right", color: "var(--dsw-alias-label-secondary)" } }, String(f.size))
                      );
                    })
                  )
                )
              ),
              el(
                "div",
                { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 10 } },
                el("span", { className: "ig5-card-sub ig5-mono" }, "第 " + page + " / " + pages + " 页"),
                el("div", { style: { display: "flex", gap: 6 } },
                  el("button", {
                    className: "ig5-btn",
                    disabled: (list.offset || 0) <= 0,
                    onClick: function () { setList(function (s) { return Object.assign({}, s, { offset: Math.max(0, s.offset - 50) }); }); }
                  }, "上一页"),
                  el("button", {
                    className: "ig5-btn",
                    disabled: list.offset + 50 >= list.total,
                    onClick: function () { setList(function (s) { return Object.assign({}, s, { offset: s.offset + 50 }); }); }
                  }, "下一页")
                )
              )
            ),
            // 右列卡片：Reverse 伪代码 / CFG 控制流拓扑 / 变量与微代码切片 三模切换
            el(
              "div",
              { className: "ig5-card ig5-col ig5-functions-detail" },
              el(
                "div",
                { className: "ig5-card-title" },
                el(
                  "div",
                  { className: "ig5-card-title-text" },
                  el("span", null, curCode.ea ? (curCode.name || "func") : "反编译与拓扑分析"),
                  curCode.ea ? el("span", { className: "ig5-chip read ig5-mono" }, curCode.ea) : null
                ),
                el(
                  "div",
                  { style: { display: "flex", gap: 6 } },
                  el(
                    "div",
                    { className: "ig5-kinds" },
                    [
                      { id: "code", label: "伪代码 (C)" },
                      { id: "cfg", label: "控制流 (CFG)" },
                      { id: "slice", label: "变量与切片" },
                      { id: "ir", label: "Ghidra p-code" },
                    ].filter(function (m) { return m.id !== "ir" || engine === "ghidra" || props.session && props.session.provider === "ghidra"; }).map(function (m) {
                      return el("button", {
                        key: m.id,
                        className: "ig5-gran-btn" + (viewMode === m.id ? " ig5-gran-on" : ""),
                          "aria-pressed": viewMode === m.id,
                        onClick: function () { setViewMode(m.id); }
                      }, m.label);
                    })
                  ),
                  curCode.code && viewMode === "code"
                    ? el("button", {
                        className: "ig5-btn",
                        onClick: function () {
                          if (curCode.code && navigator.clipboard) {
                            navigator.clipboard.writeText(curCode.code);
                            alert("已将伪代码复制到剪贴板！");
                          }
                        }
                      }, "复制代码")
                    : null
                )
              ),
              curCode.ea
                ? el(
                    "div",
                    null,
                    viewMode === "ir" && el(Ig5IrView, { key: engine + ":" + curCode.ea, target: target, engine: engine, session: props.session, ea: curCode.ea }),
                    // 视图 1: 伪代码
                    viewMode === "code" && (
                      curCode.loading
                        ? el("div", { style: { padding: 30, color: "var(--dsw-alias-label-secondary)", textAlign: "center" } }, "正在使用 " + engineName(engine) + " 反编译该函数...")
                        : curCode.error
                        ? el("div", { style: { padding: 20, color: "var(--dsw-alias-state-error-primary)" } }, "反编译失败: " + curCode.error)
                        : el("pre", { className: "ig5-code-box ig5-mono" }, curCode.code)
                    ),
                    // 视图 2: 控制流图 (CFG) 拓扑与 Mermaid
                    viewMode === "cfg" && (
                      cfg
                        ? el(
                            "div",
                            null,
                            el("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 } },
                              el("span", { className: "ig5-card-sub ig5-mono" },
                              "共 " + (cfg.total_blocks || 0) + " 个基本块 · " + (cfg.total_edges || 0) + " 条跳转边"
                              ),
                              el("button", {
                                className: "ig5-btn",
                                onClick: function () {
                                  if (cfg.mermaid && navigator.clipboard) {
                                    navigator.clipboard.writeText(cfg.mermaid);
                                    alert("已复制 Mermaid 流程图代码到剪贴板！可直接粘贴渲染。");
                                  }
                                }
                              }, "复制 Mermaid 图表")
                            ),
                            cfg.error ? el("div", { className: "ig5-error", role: "alert" }, cfg.error) : el(CfgGraph, { cfg: cfg, onOpen: openBlock }),
                            disasm ? el("div", { style: { marginTop: 12 } },
                              el("div", { className: "ig5-form-row" }, el("b", { className: "ig5-mono" }, "B" + disasm.block + " · " + disasm.ea + " 反汇编（只读）"), el("button", { className: "ig5-btn", onClick: function () { disasmGate.current.next(); setDisasm(null); } }, "关闭")),
                              disasm.loading ? el("p", { className: "ig5-card-sub", role: "status" }, "正在读取基本块指令…") : disasm.error ? el("p", { className: "ig5-error", role: "alert" }, disasm.error) : el("pre", { className: "ig5-code-box ig5-mono" }, disasm.rows.map(function (row, i) { return el("span", { key: i, className: "ig5-code-line" }, row.ea + "  " + (row.bytes || "").padEnd(24) + "  " + row.text); }))) : null,
                            el("details", { style: { marginTop: 10 } }, el("summary", { className: "ig5-card-sub" }, "Mermaid 源码"), el("pre", { className: "ig5-code-box ig5-mono" }, cfg.mermaid)),
                            el("div", { style: { marginTop: 10 } },
                              el("div", { style: { fontSize: 11, fontWeight: 600, color: "var(--dsw-alias-label-secondary)", marginBottom: 4 } }, "基本块明细:"),
                              el(
                                "div",
                                { style: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(170px, 1fr))", gap: 6, maxHeight: 150, overflowY: "auto" } },
                                (cfg.blocks || []).map(function (b) {
                                  return el("button", { key: b.id, className: "ig5-btn", onClick: function () { openBlock(b); }, style: { background: "var(--dsw-alias-bg-layer-2)", padding: "4px 8px", borderRadius: 4, fontSize: 11, textAlign: "left" } },
                                    el("div", { className: "ig5-mono", style: { fontWeight: 600, color: "var(--dsw-alias-brand-primary)" } }, "B" + b.id + " [" + b.start + "]"),
                                    el("div", { className: "ig5-card-sub" }, b.insns + " 条指令 · 跳转 -> " + ((b.succs || []).join(", ") || "返回"))
                                  );
                                })
                              )
                            )
                          )
                        : el("div", { style: { padding: 30, color: "var(--dsw-alias-label-secondary)", textAlign: "center" } }, "正在提取控制流图基本块...")
                    ),
                    // 视图 3: 变量表与微代码切片
                    viewMode === "slice" && (
                      slice
                        ? el(
                            "div",
                            null,
                            el("div", { style: { fontSize: 12, fontWeight: 600, color: "var(--dsw-alias-label-secondary)", marginBottom: 8 } },
                              "局部变量与参数清单 (" + (slice.variables || []).length + " 个) · 点击变量查看匹配代码行"
                            ),
                            el(
                              "div",
                              { className: "ig5-table-wrap", style: { maxHeight: 220, marginBottom: 12 } },
                              el(
                                "table",
                                { className: "ig5-table ig5-mono" },
                                el("thead", null,
                                  el("tr", null,
                                    el("th", null, "变量名"),
                                    el("th", null, "推导类型"),
                                    el("th", null, "宽度 (字节)"),
                                    el("th", null, "角色")
                                  )
                                ),
                                el("tbody", null,
                                  (slice.variables || []).map(function (v, idx) {
                                    return el("tr", { key: idx, className: focused.variable === v.name ? "selected" : "", onClick: function () { focusVariable(v.name); }, tabIndex: 0, onKeyDown: function (e) { if (e.key === "Enter") focusVariable(v.name); } },
                                      el("td", { style: { fontWeight: 600, color: "var(--dsw-alias-brand-primary)" } }, v.name),
                                      el("td", null, v.type),
                                      el("td", null, String(v.size)),
                                      el("td", null, v.is_arg === true ? el("span", { className: "ig5-chip read" }, "参数") : v.is_arg === false ? "局部变量" : "角色未提供")
                                    );
                                  })
                                )
                              )
                            ),
                            slice.error ? el("div", { className: "ig5-error", role: "alert" }, slice.error) : null,
                            focused.variable ? el("div", null,
                              el("div", { className: "ig5-form-row" }, el("b", { className: "ig5-mono" }, "关注变量 · " + focused.variable), el("span", { className: "ig5-card-sub" }, "按标识符匹配代码行，非完整数据流证明")),
                              focused.loading ? el("p", { role: "status", className: "ig5-card-sub" }, "正在提取变量切片…") : focused.error ? el("p", { className: "ig5-error", role: "alert" }, focused.error) : focused.lines.length ? el("pre", { className: "ig5-code-box ig5-mono" }, renderCodeLines(focused.lines, focused.variable)) : el("p", { className: "ig5-card-sub" }, "没有匹配代码行。")) : el("p", { className: "ig5-card-sub" }, "选择变量后读取 focused slice 并高亮匹配位置。")
                          )
                        : el("div", { style: { padding: 30, color: "var(--dsw-alias-label-secondary)", textAlign: "center" } }, "正在提取局部变量与 AST 节点...")
                    ),
                    // 关联交叉引用与子调用抽屉
                    el(
                      "div",
                      { style: { marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--dsw-alias-border-l1)" } },
                      el("div", { style: { fontSize: 12, fontWeight: 600, color: "var(--dsw-alias-label-secondary)", marginBottom: 6 } },
                        xrefs.loading ? "正在读取关联调用链…" : "关联调用链: " + (xrefs.callsError ? "子调用读取失败" : xrefs.callees.length + " 个子调用") + " · " + (xrefs.xrefsError ? "交叉引用读取失败" : xrefs.list.length + " 个交叉引用")
                      ),
                      xrefs.xrefsError ? el("p", { className: "ig5-error", role: "alert" }, "交叉引用读取失败: " + xrefs.xrefsError) : null,
                      xrefs.callsError ? el("p", { className: "ig5-error", role: "alert" }, "子调用读取失败: " + xrefs.callsError) : null,
                      el(
                        "div",
                        { style: { display: "flex", flexWrap: "wrap", gap: 6 } },
                        xrefs.callees.map(function (c, idx) {
                          return el("span", {
                            key: "c" + idx,
                            className: "ig5-chip read",
                            style: { cursor: "pointer" },
                            onClick: function () { chooseFunction(c.ea || "", c.name || ""); }
                          }, "调用 -> " + (c.name || c.ea));
                        }),
                        xrefs.list.map(function (x, idx) {
                          return el("span", {
                            key: "x" + idx,
                            className: "ig5-chip write",
                            style: { cursor: "pointer" },
                            onClick: function () { chooseFunction(x.func_ea || x.from || x.ea, x.func_name || ""); }
                          }, "引用自 <- " + (x.func_name || x.from || x.ea));
                        }),
                        (!xrefs.loading && !xrefs.xrefsError && !xrefs.callsError && !xrefs.callees.length && !xrefs.list.length) ? el("span", { className: "ig5-card-sub" }, "无外部交叉调用记录") : null
                      )
                    )
                  )
                : el("div", { style: { padding: 50, textAlign: "center", color: "var(--dsw-alias-label-secondary)" } },
                    "选择函数，查看当前静态引擎的伪代码、CFG 拓扑及变量焦点行。"
                  )
            )
          );
        }

        /* ── Tab 2: 字符串常量库 (Strings) ── */
        function Ig5StringsView(props) {
          var target = props.target;
          var engine = props.engine || "reverse";
          var statePair = react.useState({ rows: [], offset: 0, total: 0, filter: "", loading: false, error: null });
          var data = statePair[0];
          var setData = statePair[1];
          var refsPair = react.useState(null), refs = refsPair[0], setRefs = refsPair[1];
          var refsGate = react.useRef(makeRequestGate()), refsScope = react.useRef(engine + "\n" + target);
          if (refsScope.current !== engine + "\n" + target) { refsScope.current = engine + "\n" + target; refsGate.current.next(); }
          react.useEffect(function () { setRefs(null); setData(function (s) { return Object.assign({}, s, { rows: [], total: 0, offset: 0 }); }); return function () { refsGate.current.next(); }; }, [target, engine]);

          react.useEffect(function () {
            if (!target) return;
            var alive = true;
            setData(function (s) { return Object.assign({}, s, { loading: true, error: null }); });
            readData("strings", target, { offset: data.offset || 0, limit: 80 }, engine, props.session)
              .then(function (result) {
                if (!alive) return;
                var list = result.strings || [];
                setData(function (s) { return Object.assign({}, s, { loading: false, rows: list, total: result.total || list.length }); });
              })
              .catch(function (e) { if (alive) setData(function (s) { return Object.assign({}, s, { loading: false, error: String(e.message || e) }); }); });
            return function () { alive = false; };
          }, [target, engine, data.offset]);
          function showReferences(ea) {
            var ticket = refsGate.current.next(); setRefs({ ea: ea, loading: true, rows: [] });
            readData("xrefs", target, { ea: ea }, engine, props.session).then(function (result) { if (refsGate.current.isCurrent(ticket)) setRefs({ ea: ea, loading: false, rows: result.rows || [] }); }).catch(function (e) { if (refsGate.current.isCurrent(ticket)) setRefs({ ea: ea, loading: false, rows: [], error: String(e.message || e) }); });
          }

          var filtered = (data.rows || []).filter(function (item) {
            if (!data.filter) return true;
            return String(item.str || "").toLowerCase().indexOf(data.filter.toLowerCase()) !== -1 ||
                   String(item.ea || "").indexOf(data.filter) !== -1;
          });

          return el(
            "div",
            { className: "ig5-card" },
            data.error ? el("p", { className: "ig5-error", role: "alert" }, data.error) : null,
            refs ? el("div", { className: "ig5-card", style: { marginBottom: 10 } }, el("b", { className: "ig5-mono" }, engineName(engine) + " · " + refs.ea + " 引用"), refs.loading ? el("p", null, "读取引用…") : refs.error ? el("p", { className: "ig5-error" }, refs.error) : refs.rows.length ? refs.rows.map(function (item, index) { return el("button", { key: index, className: "ig5-btn ig5-mono", disabled: typeof props.onNavigate !== "function", onClick: function () { props.onNavigate({ ea: item.func_ea || item.from || item.ea, name: item.func_name || item.name || "" }); } }, (item.func_name || item.name || "引用位置") + " · " + (item.func_ea || item.from || item.ea)); }) : el("p", { className: "ig5-card-sub" }, "没有引用记录。")) : null,
            el(
              "div",
              { className: "ig5-card-title" },
              el("span", { className: "ig5-card-title-text" }, "🔤 字符串常量库 (String Literals)"),
              el("span", { className: "ig5-chip read ig5-mono" }, "匹配 " + filtered.length + " / " + data.rows.length + " 项")
            ),
            el(
              "div",
              { style: { display: "flex", gap: 8, marginBottom: 10 } },
              el("input", {
                className: "ig5-input ig5-mono",
                style: { flex: 1 },
                placeholder: "实时过滤字符串关键字 (如 password, key, http, flag, error)...",
                value: data.filter,
                onChange: function (e) { setData(Object.assign({}, data, { filter: e.target.value })); }
              })
            ),
            el(
              "div",
              { className: "ig5-table-wrap" },
              el(
                "table",
                { className: "ig5-table ig5-mono" },
                el("thead", null,
                  el("tr", null,
                    el("th", { style: { width: 110 } }, "地址 (EA)"),
                    el("th", { style: { width: 60 } }, "长度"),
                    el("th", null, "字符串内容 (Literal)"),
                    el("th", { style: { width: 90, textAlign: "right" } }, "操作")
                  )
                ),
                el("tbody", null,
                  filtered.map(function (row, idx) {
                    return el("tr", { key: idx },
                      el("td", { style: { color: "var(--dsw-alias-brand-primary)" } }, row.ea),
                      el("td", { style: { color: "var(--dsw-alias-label-secondary)" } }, String(row.length || (row.str || "").length)),
                      el("td", { style: { color: "var(--dsw-alias-label-primary)", wordBreak: "break-all" } }, String(row.str)),
                      el("td", { style: { textAlign: "right" } },
                        el("button", {
                          className: "ig5-btn",
                          style: { fontSize: 11, padding: "2px 8px" },
                          onClick: function () {
                            showReferences(row.ea);
                          }
                        }, "查引用")
                      )
                    );
                  })
                )
              )
            )
          );
        }

        /* ── Tab 3: 节段、符号与结构体库 (Listing & Structs) ── */
        function Ig5ListingView(props) {
          var target = props.target;
          var engine = props.engine || "reverse", scopeKey = engine + "\n" + target;
          var subTabPair = react.useState("segments");
          var subTab = subTabPair[0];
          var setSubTab = subTabPair[1];

          var dataPair = react.useState({ list: [], structs: [], loading: false, error: null });
          var data = dataPair[0];
          var setData = dataPair[1];
          var typePair = react.useState({ name: "", declaration: "", revision: 0, fields: [], error: null });
          var selectedType = typePair[0], setSelectedType = typePair[1];
          var typeGate = react.useRef(makeRequestGate());
          var typeTarget = react.useRef(scopeKey);
          if (typeTarget.current !== scopeKey) { typeTarget.current = scopeKey; typeGate.current.next(); }
          var refreshPair = react.useState(0), refresh = refreshPair[0], setRefresh = refreshPair[1];
          react.useEffect(function () { typeGate.current.next(); setSelectedType({ name: "", declaration: "", revision: 0, fields: [], error: null }); return function () { typeGate.current.next(); }; }, [target, engine]);
          function loadType(name) {
            var ticket = typeGate.current.next();
            readData("struct", target, { action: "get", name: name }, engine, props.session).then(function (result) {
              if (!typeGate.current.isCurrent(ticket)) return;
              setSelectedType(function (s) { return { name: name, declaration: result.decl || "", fields: result.fields || [], revision: s.revision + 1, error: result.decl ? null : "引擎未返回可编辑 C 声明；请根据字段列表填写完整声明后再生成草稿。" }; });
            }).catch(function (e) { if (typeGate.current.isCurrent(ticket)) setSelectedType(function (s) { return Object.assign({}, s, { error: String(e.message || e) }); }); });
          }

          react.useEffect(function () {
            if (!target) return;
            var alive = true;
            setData(function (s) { return Object.assign({}, s, { loading: true, error: null }); });
            if (subTab === "structs") {
              readData("struct", target, { action: "list", limit: 100 }, engine, props.session)
                .then(function (result) {
                  if (!alive) return;
                  setData({ list: [], structs: result.items || [], loading: false });
                })
                .catch(function (e) { if (alive) setData({ list: [], structs: [], loading: false, error: String(e.message || e) }); });
            } else {
              readData("listing", target, { kind: subTab, limit: 150 }, engine, props.session)
                .then(function (result) {
                  if (!alive) return;
                  setData({ list: result.rows || [], structs: [], loading: false });
                })
                .catch(function (e) { if (alive) setData({ list: [], structs: [], loading: false, error: String(e.message || e) }); });
            }
            return function () { alive = false; };
          }, [target, engine, subTab, refresh]);

          return el(
            "div",
            { className: "ig5-card" },
            el(
              "div",
              { className: "ig5-card-title" },
              el("span", { className: "ig5-card-title-text" }, "📑 节段、符号与结构体库 (Listing & Structs)"),
              el(
                "div",
                { className: "ig5-kinds" },
                [
                  { id: "segments", label: "节段结构 (Segments)" },
                  { id: "imports", label: "导入函数 (Imports)" },
                  { id: "exports", label: "导出符号 (Exports)" },
                  { id: "structs", label: "结构体与类型 (Structs)" },
                ].map(function (k) {
                  return el("button", {
                    key: k.id,
                    className: "ig5-gran-btn" + (subTab === k.id ? " ig5-gran-on" : ""),
                    "aria-pressed": subTab === k.id,
                    onClick: function () { setSubTab(k.id); }
                  }, k.label);
                })
              )
            ),
            data.error ? el("p", { className: "ig5-error", role: "alert" }, data.error) : null,
            subTab === "structs" ? el("div", null,
              el("div", { className: "ig5-form-row" },
                el("button", { className: "ig5-btn", onClick: function () { typeGate.current.next(); setSelectedType(function (s) { return { name: "", declaration: "", fields: [], revision: s.revision + 1, error: null }; }); } }, "新增声明"),
                el("button", { className: "ig5-btn", onClick: function () { setRefresh(function (v) { return v + 1; }); } }, "刷新类型列表")),
              el(StructEditor, { target: target, engine: engine, inputActions: props.inputActions, name: selectedType.name, declaration: selectedType.declaration, revision: selectedType.revision }),
              selectedType.error ? el("div", { className: "ig5-error", role: "alert" }, selectedType.error) : null,
              selectedType.name ? el("div", { style: { margin: "8px 0" } }, el("b", { className: "ig5-mono" }, selectedType.name + " 字段布局"), el("pre", { className: "ig5-code-box ig5-mono", style: { maxHeight: 180 } }, selectedType.fields.map(function (f) { return "+" + f.offset + "B [" + f.size + "B] " + f.type + " " + f.name; }).join("\n") || "无成员或不透明类型")) : null) : null,
            el(
              "div",
              { className: "ig5-table-wrap" },
              subTab === "structs"
                ? el(
                    "table",
                    { className: "ig5-table ig5-mono" },
                    el("thead", null,
                      el("tr", null,
                        el("th", { style: { width: 70 } }, "序号"),
                        el("th", null, "类型/结构体名 (Type Name)"),
                        el("th", { style: { width: 90 } }, "大小 (字节)"),
                        el("th", { style: { width: 90 } }, "类型属性"),
                        el("th", { style: { width: 100, textAlign: "right" } }, "操作")
                      )
                    ),
                    el("tbody", null,
                      data.structs.map(function (st, idx) {
                        return el("tr", { key: idx },
                          el("td", { style: { color: "var(--dsw-alias-label-secondary)" } }, String(st.ordinal ?? "—")),
                          el("td", { style: { fontWeight: 600, color: "var(--dsw-alias-brand-primary)" } }, st.name),
                          el("td", null, String(st.size)),
                          el("td", null, st.is_struct ? el("span", { className: "ig5-chip read" }, "struct") : "type"),
                          el("td", { style: { textAlign: "right" } },
                            el("button", {
                              className: "ig5-btn",
                              style: { fontSize: 11, padding: "2px 8px" },
                              onClick: function () { loadType(st.name); }
                            }, "字段 / 编辑声明")
                          )
                        );
                      }),
                      !data.structs.length ? el("tr", null, el("td", { colSpan: 5, style: { textAlign: "center", padding: 20, color: "var(--dsw-alias-label-secondary)" } }, "暂无自定义结构体。可用 ig5_struct action=define 定义并编译 C 结构体。")) : null
                    )
                  )
                : el(
                    "table",
                    { className: "ig5-table ig5-mono" },
                    el("thead", null,
                      subTab === "segments"
                        ? el("tr", null,
                            el("th", null, "段名称 (Name)"),
                            el("th", null, "起始地址 (Start)"),
                            el("th", null, "结束地址 (End)"),
                            el("th", null, "字节大小"),
                            el("th", null, "权限 (Perm)"),
                            el("th", null, "类别 (Class)")
                          )
                        : subTab === "imports"
                        ? el("tr", null,
                            el("th", null, "模块库 (Module)"),
                            el("th", null, "导入函数名 (Function Name)"),
                            el("th", null, "序号 (Ordinal)"),
                            el("th", null, "安全级别")
                          )
                        : el("tr", null,
                            el("th", null, "序号 (Ordinal)"),
                            el("th", null, "导出函数名 (Exported Name)"),
                            el("th", null, "地址 (EA)")
                          )
                    ),
                    el("tbody", null,
                      data.list.map(function (item, idx) {
                        if (subTab === "segments") {
                          return el("tr", { key: idx },
                            el("td", { style: { color: "var(--dsw-alias-brand-primary)", fontWeight: 600 } }, item.name),
                            el("td", null, item.start),
                            el("td", null, item.end),
                            el("td", null, String(item.size)),
                            el("td", { style: { color: item.perm && item.perm.indexOf("w") !== -1 ? "var(--dsw-alias-state-warn-primary)" : "var(--dsw-alias-state-success-primary)" } }, item.perm),
                            el("td", { style: { color: "var(--dsw-alias-label-secondary)" } }, item.class)
                          );
                        } else if (subTab === "imports") {
                          var isDanger = /VirtualProtect|CreateProcess|WriteProcessMemory|LoadLibrary|WinExec|HttpSend/i.test(item.name || "");
                          return el("tr", { key: idx },
                            el("td", { style: { color: "var(--dsw-alias-label-secondary)" } }, item.module),
                            el("td", { style: { color: isDanger ? "var(--dsw-alias-state-error-primary)" : "var(--dsw-alias-label-primary)", fontWeight: isDanger ? 600 : 400 } }, item.name),
                            el("td", { style: { color: "var(--dsw-alias-label-secondary)" } }, String(item.ordinal ?? "-")),
                            el("td", null, isDanger ? el("span", { className: "ig5-chip write" }, "敏感 API") : "常规")
                          );
                        } else {
                          return el("tr", { key: idx },
                            el("td", { style: { color: "var(--dsw-alias-label-secondary)" } }, String(item.ordinal ?? idx)),
                            el("td", { style: { color: "var(--dsw-alias-state-success-primary)", fontWeight: 600 } }, item.name),
                            el("td", { style: { color: "var(--dsw-alias-brand-primary)" } }, item.ea)
                          );
                        }
                      })
                    )
                  )
            )
          );
        }

        /* ── Tab 4: 熵扫描与特征指纹 (Reverse Recon & Scan) ── */
        function Ig5ScanView(props) {
          var target = props.target;
          var engine = props.engine || "reverse";
          var scopeKey = engine + "\n" + normalizedTarget(target);
          var scanPair = react.useState({ data: null, loading: false, error: null });
          var scan = scanPair[0];
          var setScan = scanPair[1];

          var fpPair = react.useState(null);
          var fp = fpPair[0];
          var setFp = fpPair[1];

          react.useEffect(function () {
            if (!target) return;
            var alive = true;
            setScan({ data: null, loading: true });
            setFp(null);
            readData("scan", target, {}, engine, props.session)
              .then(function (data) { if (alive) setScan({ data: data, loading: false, scopeKey: scopeKey }); })
              .catch(function (e) { if (alive) setScan({ data: null, loading: false, error: String(e.message || e), scopeKey: scopeKey }); });

            readData("fingerprint", target, {}, engine, props.session)
              .then(function (data) { if (alive) setFp({ data: data, scopeKey: scopeKey }); })
              .catch(function () {});
            return function () { alive = false; };
          }, [target, engine]);

          var d = normalizeScan(scan.scopeKey === scopeKey ? scan.data : null);
          var visibleFp = fp && fp.scopeKey === scopeKey ? fp.data : null;
          var entropies = d.entropies, cryptos = d.crypto_markers, suspApi = d.suspicious_apis;
          fp = visibleFp;

          return el(
            "div",
            null,
            scan.scopeKey === scopeKey && scan.error ? el("p", { className: "ig5-error", role: "alert" }, scan.error) : null,
            scan.loading ? el("p", { className: "ig5-card-sub", role: "status" }, "读取有界扫描证据…") : null,
            d.truncated ? el("p", { className: "ig5-card-sub" }, "扫描包含采样或截断；未命中不代表整个文件不存在该特征。") : null,
            // 编译器与标准库指纹识别卡片
            el(
              "div",
              { className: "ig5-card" },
              el(
                "div",
                { className: "ig5-card-title" },
                el("span", { className: "ig5-card-title-text" }, "🎯 编译器指纹与标准库识别 (" + engineName(engine) + ")"),
                fp ? el("span", { className: "ig5-chip read ig5-mono" }, "ABI: " + fp.abi) : null
              ),
              fp
                ? el(
                    "div",
                    null,
                    el(
                      "div",
                      { className: "ig5-stats-grid", style: { marginBottom: 10 } },
                      el("div", { className: "ig5-stat" },
                        el("span", { className: "ig5-stat-label" }, "总函数量"),
                        el("b", { className: "ig5-stat-value ig5-mono" }, String(fp.total_functions))
                      ),
                      el("div", { className: "ig5-stat" },
                        el("span", { className: "ig5-stat-label" }, engine === "ghidra" ? "外部／跳板函数" : "库标记函数 (Reverse)"),
                        el("b", { className: "ig5-stat-value ig5-mono", style: { color: "var(--dsw-alias-brand-primary)" } }, String(fp.library_functions_count)),
                        el("span", { className: "ig5-stat-sub" }, "占比 " + Math.round(fp.library_ratio * 100) + "%")
                      ),
                      el("div", { className: "ig5-stat" },
                        el("span", { className: "ig5-stat-label" }, "目标用户逻辑函数"),
                        el("b", { className: "ig5-stat-value ig5-mono", style: { color: "var(--dsw-alias-state-success-primary)" } }, String(fp.user_functions_count)),
                        el("span", { className: "ig5-stat-sub" }, "核心业务面")
                      )
                    ),
                    el("div", { className: "ig5-card-sub" },
                      "已识别标准库函数样例: " + (fp.sample_library_funcs || []).map(function (f) { return f.name; }).join(", ")
                    )
                  )
                : el("div", { className: "ig5-card-sub" }, "正在读取 " + engineName(engine) + " 指纹线索...")
            ),
            // 节段熵分析卡片
            el(
              "div",
              { className: "ig5-card" },
              el(
                "div",
                { className: "ig5-card-title" },
                el("span", { className: "ig5-card-title-text" }, "📊 节段香农熵分析 (Shannon Entropy · >7.2 疑似加密或加壳)"),
                el("span", { className: "ig5-chip read ig5-mono" }, entropies.length + " 个节段")
              ),
              el(
                "div",
                null,
                entropies.map(function (e, idx) {
                  var entVal = Number(e.entropy || 0);
                  var isHigh = entVal >= 7.2;
                  var pct = Math.min(100, Math.round((entVal / 8.0) * 100));
                  return el(
                    "div",
                    { key: idx, style: { marginBottom: 10 } },
                    el(
                      "div",
                      { style: { display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 3 } },
                      el("span", { className: "ig5-mono", style: { fontWeight: 600, color: isHigh ? "var(--dsw-alias-state-error-primary)" : "var(--dsw-alias-label-primary)" } },
                        e.name + (isHigh ? " · 高熵线索" : "")
                      ),
                      el("span", { className: "ig5-mono", style: { color: "var(--dsw-alias-label-secondary)" } }, entVal.toFixed(3) + " / 8.0")
                    ),
                    el(
                      "div",
                      { className: "ig5-track" },
                      el("div", {
                        className: "ig5-fill",
                        style: {
                          width: pct + "%",
                          background: isHigh ? "var(--dsw-alias-state-error-primary, #ef4444)" : "var(--dsw-alias-brand-primary, #3b82f6)"
                        }
                      })
                    )
                  );
                }),
                !entropies.length ? el("div", { className: "ig5-card-sub" }, "暂无段熵数据或样本未开启熵分析") : null
              )
            ),
            // 密码学常量特征卡片
            el(
              "div",
              { className: "ig5-card" },
              el(
                "div",
                { className: "ig5-card-title" },
                el("span", { className: "ig5-card-title-text" }, "🔐 密码学特征与算法常数检出 (Crypto Markers)"),
                el("span", { className: "ig5-chip read ig5-mono" }, cryptos.length + " 处特征")
              ),
              el(
                "div",
                { style: { display: "flex", flexWrap: "wrap", gap: 6 } },
                cryptos.map(function (c, idx) {
                  return el("span", { key: idx, className: "ig5-chip read", title: c.ea || "" }, "常数: " + c.name + (c.ea ? " @ " + c.ea : ""));
                }),
                !cryptos.length ? el("span", { className: "ig5-card-sub" }, "当前扫描范围未命中已知常量。常量命中不证明算法用途或密钥。") : null
              )
            ),
            // 敏感 API 画像卡片
            el(
              "div",
              { className: "ig5-card" },
              el(
                "div",
                { className: "ig5-card-title" },
                el("span", { className: "ig5-card-title-text" }, "🔍 密码学／通信／行为 API 线索"),
                el("span", { className: "ig5-chip read ig5-mono" }, suspApi.length + " 个导入线索")
              ),
              el(
                "div",
                { style: { display: "flex", flexWrap: "wrap", gap: 6 } },
                suspApi.map(function (a, idx) {
                  return el("span", { key: idx, className: "ig5-chip read", title: a.ea || a.externalAddress || "" }, (a.module ? a.module + "!" : "") + a.api + (a.category ? " · " + a.category : ""));
                }),
                !suspApi.length ? el("span", { className: "ig5-card-sub" }, "当前导入范围暂无已知 API 线索；动态解析和内联实现仍需追踪。") : null
              )
            )
          );
        }

        function AnalysisDraft(props) {
          var lanePair = react.useState("crypto"), lane = lanePair[0], setLane = lanePair[1];
          var actionPair = react.useState("inspect"), action = actionPair[0], setAction = actionPair[1];
          var inputPair = react.useState("path"), inputType = inputPair[0], setInputType = inputPair[1];
          var valuePair = react.useState(""), value = valuePair[0], setValue = valuePair[1];
          var producerPair = react.useState(""), producer = producerPair[0], setProducer = producerPair[1];
          var parametersPair = react.useState("{}"), parameters = parametersPair[0], setParameters = parametersPair[1];
          var draftPair = react.useState(""), draft = draftPair[0], setDraft = draftPair[1];
          var noticePair = react.useState(""), notice = noticePair[0], setNotice = noticePair[1];
          var draftScopePair = react.useState(null), draftScope = draftScopePair[0], setDraftScope = draftScopePair[1];
          var scope = (props.engine || "") + "\n" + normalizedTarget(props.target);
          var visibleDraft = draftScope === scope ? draft : "";
          react.useEffect(function () { setDraft(""); setNotice(""); }, [props.target, props.engine]);
          function createDraft() {
            try {
              if (!value.trim()) throw new Error("请填写输入文件、引用或编码字节");
              var input = inputType === "path" ? { path: value.trim() } : inputType === "ref" ? { ref: value.trim() } : { encoding: inputType, data: value.trim() };
              if (inputType === "ref" && producer.trim()) {
                if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(producer.trim())) throw new Error("来源报告 ID 必须为 UUID");
                input.result_id = producer.trim();
              }
              setDraft(buildAnalysisDraft(lane, action, input, parameters, props.target, props.engine)); setDraftScope(scope); setNotice("草稿已生成，尚未发送或执行。");
            } catch (e) { setNotice(String(e.message || e)); }
          }
          function insert() {
            try {
              var actions = props.inputActions;
              if (!actions || typeof actions.captureInsertion !== "function" || typeof actions.insertText !== "function") { setNotice("请复制草稿到会话，核对参数后发送。"); return; }
              var span = actions.captureInsertion();
              if (!visibleDraft) return;
              if (!actions.insertText("\n" + visibleDraft + "\n", span)) { setNotice("编辑器内容已变化，请重新插入或复制草稿。"); return; }
              if (typeof actions.persistDraft === "function") actions.persistDraft();
              setNotice("已插入会话草稿，尚未发送或执行。");
            } catch (e) { setNotice("插入失败：" + String(e.message || e)); }
          }
          return el("div", { className: "ig5-card" },
            el("div", { className: "ig5-card-title-text" }, "建立解密／协议分析草稿"),
            el("p", { className: "ig5-card-sub" }, "提供数据来源与显式参数；此编辑器只生成草稿。运行样本与回写数据库仍使用对应审批工具。"),
            el("div", { className: "ig5-form-row" },
              el("select", { className: "ig5-input", "aria-label": "数据分析领域", value: lane, onChange: function (e) { setLane(e.target.value); setAction("inspect"); setParameters("{}"); setDraft(""); } }, el("option", { value: "crypto" }, "解密与配置"), el("option", { value: "protocol" }, "协议与报文")),
              el("select", { className: "ig5-input", "aria-label": "数据分析操作", value: action, onChange: function (e) { setAction(e.target.value); setDraft(""); } }, (lane === "crypto" ? ["inspect", "transform", "recover", "verify"] : ["inspect", "capture", "decode", "infer"]).map(function (item) { return el("option", { key: item, value: item }, item); })),
              el("select", { className: "ig5-input", "aria-label": "分析数据来源", value: inputType, onChange: function (e) { setInputType(e.target.value); setDraft(""); } }, ["path", "ref", "hex", "base64"].map(function (item) { return el("option", { key: item, value: item }, item); }))),
            el("input", { className: "ig5-input ig5-mono", "aria-label": "分析输入文件或字节", value: value, placeholder: inputType === "path" ? "本机输入文件路径" : inputType === "ref" ? "sha256:…" : "完整编码字节", onChange: function (e) { setValue(e.target.value); setDraft(""); } }),
            inputType === "ref" ? el("input", { className: "ig5-input ig5-mono", "aria-label": "来源分析报告 ID", value: producer, placeholder: "来源报告 UUID（填写后保留引用链；省略则无绑定来源）", onChange: function (e) { setProducer(e.target.value); setDraft(""); } }) : null,
            action === "recover" ? el("p", { className: "ig5-card-sub" }, "自动恢复在预算内搜索单字节／重复 XOR，或验证显式候选及 key_source 提取的 AES 密钥。统计评分是候选；提供已知明文、expected 或 GCM 认证可核验。密钥只保存敏感引用，完整候选可用 recipe.key_ref 复用，不自动展开密钥字节。") : null,
            action === "infer" ? el("p", { className: "ig5-card-sub" }, "推导消息边界、长度字段、端序与字段候选；未知流起点保留不确定性。独立 holdout_samples 用于验证，不能用训练样本自证。候选 framing／schema 可复制到 decode，decodeInput 的 startOffset／byteLength 对应 offset／length；原始前缀与尾部保留在来源引用。字段含义与状态机仍需人工确认。") : null,
            el("textarea", { className: "ig5-textarea ig5-mono", "aria-label": "分析附加参数 JSON", value: parameters, onChange: function (e) { setParameters(e.target.value); setDraft(""); }, placeholder: "recovery / recipe / expected，或 inference / schema / framing 的 JSON 参数" }),
            el("button", { className: "ig5-btn", onClick: function () { setParameters(JSON.stringify(analysisTemplate(lane, action), null, 2)); setDraft(""); setNotice("已填入可编辑参数模板，请核对数据边界与验证证据。"); } }, "填入分析参数模板"),
            el("button", { className: "ig5-btn ig5-btn-primary", onClick: createDraft }, "生成分析草稿"),
            visibleDraft ? el("div", null, el("textarea", { className: "ig5-textarea ig5-mono", "aria-label": "待发送数据分析草稿", value: visibleDraft, onChange: function (e) { setDraft(e.target.value); } }), el("button", { className: "ig5-btn", onClick: insert }, "插入会话草稿（待发送）")) : null,
            notice ? el("p", { className: "ig5-card-sub", role: "status" }, notice) : null);
        }

        function analysisReuseDraft(report, candidate, kind) {
          if (!report || !report.id || !report.input || !report.input.ref || report.input.sensitive) throw new Error("报告缺少可复用的输入引用。");
          var input = { ref: report.input.ref, result_id: report.id }, parameters;
          if (kind === "crypto") {
            if (candidate.kind !== "xor" || !candidate.keyComplete || !candidate.keyMaterial || !candidate.keyMaterial.dataRef || !candidate.keyMaterial.dataRef.sensitive) throw new Error("此候选需要补齐密钥或显式 AES 参数，请使用参数编辑器。");
            parameters = { recipe: { kind: "xor", key_ref: { ref: candidate.keyMaterial.dataRef.ref, result_id: report.id } } };
          } else {
            if (!report.value || !report.value.inference || report.value.inference.format !== "stream" || candidate.evidence && candidate.evidence.origin && candidate.evidence.origin.flowId) throw new Error("请先选择正确方向的重组流或完整消息，不能把捕获容器当成报文解码。");
            var range = candidate.decodeInput;
            if (!range || !Number.isSafeInteger(range.startOffset) || range.startOffset < 0 || !Number.isSafeInteger(range.byteLength) || range.byteLength < 1) throw new Error("候选没有完整的解码字节范围。");
            parameters = { framing: candidate.framing, schema: candidate.schema, offset: range.startOffset, length: range.byteLength };
          }
          var association = report.association || {};
          return buildAnalysisDraft(kind, kind === "crypto" ? "transform" : "decode", input, JSON.stringify(parameters), association.target, association.engine);
        }

        function AnalysisEvidence(props) {
          var report = props.report, value = report.value || {}, inference = value.inference, recovery = value.recovery;
          var candidates = (inference || recovery || {}).candidates || [];
          var draftPair = react.useState(null), draft = draftPair[0], setDraft = draftPair[1];
          var noticePair = react.useState(""), notice = noticePair[0], setNotice = noticePair[1];
          var visibleDraft = draft && draft.id === report.id ? draft.text : "";
          function reuse(candidate) { try { setDraft({ id: report.id, text: analysisReuseDraft(report, candidate, recovery ? "crypto" : "protocol") }); setNotice("已生成复用草稿；评分和边界证据仍需核对，尚未执行。"); } catch (e) { setNotice(String(e.message || e)); setDraft(null); } }
          var previews = [];
          if (typeof value.previewHex === "string") previews.push({ name: "输入", hex: value.previewHex });
          (value.frames || []).slice(0, 8).forEach(function (frame, index) { if (typeof frame.previewHex === "string") previews.push({ name: "帧 " + index + " · 偏移 " + (frame.offset || 0), hex: frame.previewHex }); });
          function hexRows(hex) { var bytes = (hex.slice(0, 512).match(/../g) || []), rows = []; for (var at = 0; at < bytes.length; at += 16) rows.push(at.toString(16).padStart(4, "0") + "  " + bytes.slice(at, at + 16).join(" ")); return rows.join("\n"); }
          return el("div", { className: "ig5-card" },
            el("div", { className: "ig5-card-title-text" }, "候选、验证与字节证据"),
            inference && inference.coverage ? el("p", { className: "ig5-card-sub", role: "status" }, "分析覆盖: " + inference.coverage.status + " · 已分析 " + inference.coverage.analyzedGroups + " / " + inference.coverage.eligibleGroups + " 组 · 跳过 " + inference.coverage.skippedGroups + (inference.coverage.previewTruncated ? " · 预览另有省略" : "")) : null,
            candidates.length ? el("div", { style: { overflowX: "auto" } }, el("table", { className: "ig5-table" },
              el("thead", null, el("tr", null, ["候选", "评分", "验证", "复用"].map(function (label) { return el("th", { key: label }, label); }))),
              el("tbody", null, candidates.slice(0, 8).map(function (candidate, index) { return el("tr", { key: candidate.id || index },
                el("td", null, candidate.kind || candidate.framing && candidate.framing.type || "未知"),
                el("td", { className: "ig5-mono" }, String(candidate.score === undefined ? "—" : candidate.score)),
                el("td", null, candidate.validation && candidate.validation.status || candidate.verification || candidate.status || "未验证"),
                el("td", null, el("button", { className: "ig5-btn", onClick: function () { reuse(candidate); } }, "生成复用草稿"))); })))) : null,
            candidates.length > 8 ? el("p", { className: "ig5-card-sub" }, "此表预览前 8 个候选；完整候选保存在报告中。") : null,
            previews.map(function (preview, index) { return el("div", { key: index }, el("b", null, preview.name + " · 前 256 字节"), el("pre", { className: "ig5-code" }, hexRows(preview.hex))); }),
            el("p", { className: "ig5-card-sub" }, "评分用于比较假设，不是正确概率；字段关系和标签序列不证明协议语义。密钥字节不在此展开。"),
            report.id ? el("button", { className: "ig5-btn", onClick: function () { setDraft({ id: report.id, text: "调用 ig5_profile，核对后管理报告历史：\n" + JSON.stringify({ history: { action: props.archived ? "restore" : "archive", ids: [report.id] } }, null, 2) }); setNotice("已生成可恢复的历史管理草稿，尚未执行。"); } }, props.archived ? "生成恢复报告草稿" : "生成归档报告草稿") : null,
            visibleDraft ? el("div", null, el("textarea", { className: "ig5-textarea ig5-mono", "aria-label": "证据复用草稿", value: visibleDraft, onChange: function (e) { setDraft({ id: report.id, text: e.target.value }); } }), el("button", { className: "ig5-btn", onClick: function () { try { var actions = props.inputActions; if (!actions || typeof actions.captureInsertion !== "function" || typeof actions.insertText !== "function") { setNotice("请复制草稿到会话，核对后发送。"); return; } var span = actions.captureInsertion(); if (actions.insertText("\n" + visibleDraft + "\n", span)) { if (typeof actions.persistDraft === "function") actions.persistDraft(); setNotice("已插入草稿，尚未发送或执行。"); } else setNotice("编辑器内容已变化，请重新插入。"); } catch (e) { setNotice(String(e.message || e)); } } }, "插入证据草稿（待发送）")) : null,
            notice ? el("p", { className: "ig5-card-sub", role: "status" }, notice) : null);
        }

        function Ig5AnalysisView(props) {
          var allPair = react.useState(true), all = allPair[0], setAll = allPair[1];
          var archivePair = react.useState(false), archived = archivePair[0], setArchived = archivePair[1];
          var refreshPair = react.useState(0), refresh = refreshPair[0], setRefresh = refreshPair[1];
          var listPair = react.useState({ items: [], loading: false }), list = listPair[0], setList = listPair[1];
          var selectedPair = react.useState(null), selected = selectedPair[0], setSelected = selectedPair[1];
          var resultPair = react.useState(null), result = resultPair[0], setResult = resultPair[1];
          var pagePair = react.useState({ scope: null, offset: 0 }), page = pagePair[0], setPage = pagePair[1];
          var scope = (all ? "all" : (props.engine || "reverse") + "\n" + normalizedTarget(props.target)) + "\n" + (archived ? "archived" : "active");
          var offset = page.scope === scope ? page.offset : 0, listScope = scope + "\n" + offset;
          var listGate = react.useRef(makeRequestGate()), resultGate = react.useRef(makeRequestGate()), currentScope = react.useRef(scope);
          var currentListScope = react.useRef(listScope);
          if (currentScope.current !== scope) { currentScope.current = scope; resultGate.current.next(); }
          if (currentListScope.current !== listScope) { currentListScope.current = listScope; listGate.current.next(); }
          var id = selected && selected.scope === scope ? selected.id : null;
          react.useEffect(function () {
            var ticket = listGate.current.next(); setList({ items: [], loading: true, scope: listScope });
            if (!all && !props.target) { setList({ items: [], scope: listScope, error: "请载入目标或选择全部数据结果。" }); return; }
            readData("analyses", all ? "" : props.target, { offset: offset, limit: 20, archived: archived }, all ? undefined : props.engine)
              .then(function (data) { if (listGate.current.isCurrent(ticket)) setList({ items: data.items || [], total: data.total, partial: data.partial, note: data.note, hasMore: data.hasMore === undefined ? offset + 20 < (data.total || 0) : data.hasMore, totalLowerBound: data.totalLowerBound, scope: listScope }); })
              .catch(function (e) { if (listGate.current.isCurrent(ticket)) setList({ items: [], scope: listScope, error: String(e.message || e) }); });
            return function () { listGate.current.next(); };
          }, [listScope, refresh]);
          react.useEffect(function () {
            if (!id) return;
            var ticket = resultGate.current.next(); setResult({ id: id, scope: scope, loading: true });
            readData("analysis_result", all ? "" : props.target, { id: id }, all ? undefined : props.engine)
              .then(function (data) { if (resultGate.current.isCurrent(ticket)) setResult({ id: id, scope: scope, data: data }); })
              .catch(function (e) { if (resultGate.current.isCurrent(ticket)) setResult({ id: id, scope: scope, error: String(e.message || e) }); });
            return function () { resultGate.current.next(); };
          }, [id, scope]);
          var rows = list.scope === listScope ? list.items : [], visible = result && result.id === id && result.scope === scope ? result : null;
          return el("div", null, el(AnalysisDraft, { target: props.target, engine: props.engine, inputActions: props.inputActions }),
            el("div", { className: "ig5-card" },
              el("div", { className: "ig5-card-title" }, el("b", null, "已保存的解密／协议证据"), el("button", { className: "ig5-btn", onClick: function () { setAll(!all); } }, all ? "全部数据结果" : "当前目标结果"), el("button", { className: "ig5-btn", onClick: function () { setArchived(!archived); } }, archived ? "已归档报告" : "活动报告"), el("button", { className: "ig5-btn", onClick: function () { setRefresh(refresh + 1); } }, "刷新分析结果")),
              list.scope === listScope && list.error ? el("p", { className: "ig5-error", role: "alert" }, list.error) : null,
              list.loading ? el("p", { role: "status" }, "读取结果索引…") : null,
              list.scope === listScope && list.partial ? el("p", { className: "ig5-card-sub", role: "status" }, "索引尚未完成；刷新继续构建。当前数量为已读取的下限，不能视为全部历史。") : null,
              rows.map(function (row) { return el("button", { key: row.id, className: "ig5-btn", style: { display: "block", width: "100%", textAlign: "left", marginBottom: 6 }, onClick: function () { setSelected({ scope: scope, id: row.id }); } }, row.kind + " · " + row.action + " · " + row.createdAt + (row.association && row.association.target ? " · " + basename(row.association.target) : " · 独立数据")); }),
              el("div", { className: "ig5-form-row" }, el("button", { className: "ig5-btn", disabled: offset === 0 || list.loading, onClick: function () { setPage({ scope: scope, offset: Math.max(0, offset - 20) }); } }, "上一页分析结果"), el("span", { className: "ig5-card-sub" }, "第 " + (Math.floor(offset / 20) + 1) + " 页 · " + (list.scope === listScope ? list.total == null ? "至少 " + (list.totalLowerBound || 0) : list.total : 0) + " 条"), el("button", { className: "ig5-btn", disabled: list.scope !== listScope || list.loading || !list.hasMore, onClick: function () { setPage({ scope: scope, offset: offset + 20 }); } }, "下一页分析结果")),
              !rows.length && !list.loading ? el("p", { className: "ig5-card-sub" }, "尚无记录。通过会话发送草稿后刷新；此页不会执行分析。") : null,
              visible && visible.error ? el("p", { className: "ig5-error", role: "alert" }, visible.error) : null,
              visible && visible.data ? el("div", null, visible.data.responseTruncated ? el("p", { className: "ig5-card-sub" }, "当前为有界摘要；使用 action=result、result_id 和 select 读取指定字段。") : null, el(AnalysisEvidence, { key: id, report: visible.data, archived: archived, inputActions: props.inputActions }), el("details", null, el("summary", null, "原始报告 JSON"), el("pre", { className: "ig5-code", style: { overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" } }, JSON.stringify(visible.data, null, 2)))) : null));
        }

        /* ── Tab 5: 补丁审计与回滚 (Patches & Undo) ── */
        function Ig5PatchesView(props) {
          var target = props.target;
          var engine = props.engine || "reverse", scopeKey = engine + "\n" + target;
          var approvalsPair = react.useState({ list: [], loading: false, total: 0, target: null, error: null });
          var approvals = approvalsPair[0];
          var setApprovals = approvalsPair[1];
          var pagePair = react.useState({ offset: 0, refresh: 0, cursor: null, history: [] }), page = pagePair[0], setPage = pagePair[1];
          var auditGate = react.useRef(makeRequestGate()), auditTarget = react.useRef(scopeKey);
          if (auditTarget.current !== scopeKey) { auditTarget.current = scopeKey; auditGate.current.next(); }
          react.useEffect(function () { setPage(function (s) { return { offset: 0, refresh: s.refresh, cursor: null, history: [] }; }); }, [target, engine]);

          react.useEffect(function () {
            var ticket = auditGate.current.next();
            if (!target) { setApprovals({ list: [], total: 0, loading: false, target: null, error: null }); return; }
            setApprovals(function (s) { return Object.assign({}, s, { loading: true, error: null }); });
            readData("approvals", target, { offset: page.offset, limit: 20, cursor: page.cursor || undefined }, engine).then(function (data) {
              if (!auditGate.current.isCurrent(ticket)) return;
              var legacy = Array.isArray(data);
              var records = (legacy ? data : (data.rows || [])).map(normalizeAudit).filter(function (r) { return normalizedTarget(r.target) === normalizedTarget(target) && r.engine === engine; });
              var total = legacy ? records.length : data.total == null ? null : Number(data.total);
              setApprovals({ list: legacy ? records.slice(page.offset, page.offset + 20) : records, total: total, totalLowerBound: data.totalLowerBound, hasMore: data.hasMore === undefined ? page.offset + 20 < total : data.hasMore, nextCursor: data.nextCursor, partial: data.partial, issues: data.issues, loading: false, target: target, engine: engine, error: null });
            }).catch(function (e) { if (auditGate.current.isCurrent(ticket)) setApprovals({ list: [], total: 0, loading: false, target: target, error: String(e.message || e) }); });
            return function () { auditGate.current.next(); };
          }, [target, engine, page.offset, page.cursor, page.refresh]);
          var records = approvals.target === target && approvals.engine === engine ? approvals.list : [];

          return el(
            "div",
            null,
            el(
              "div",
              { className: "ig5-card" },
              el(
                "div",
                { className: "ig5-card-title" },
                el("span", { className: "ig5-card-title-text" }, "⚡ 写操作与补丁审计时间线"),
                el("button", { className: "ig5-btn", disabled: !target || approvals.loading, onClick: function () { setPage(function (s) { return { offset: 0, cursor: null, history: [], refresh: s.refresh + 1 }; }); } }, "刷新记录"),
                el("button", {
                  className: "ig5-btn ig5-btn-primary",
                  onClick: function () {
                    alert("可在会话中直接指挥模型:「调用 ig5_export_diff 导出当前所有补丁与 changes.md 交付物」！");
                  }
                }, "导出补丁交付物 (Export Diff)")
              ),
              el("p", { className: "ig5-card-sub ig5-mono" }, target ? "当前目标: " + target : "请先选择目标。"),
              approvals.loading ? el("p", { role: "status", className: "ig5-card-sub" }, "正在读取审计记录…") : null,
              approvals.error ? el("p", { className: "ig5-error", role: "alert" }, approvals.error) : null,
              approvals.partial || approvals.issues && approvals.issues.length ? el("p", { className: "ig5-card-sub", role: "status" }, "当前为有界审计视图；部分记录未扫描或格式损坏，请继续分页并检查原始日志。") : null,
              records.map(function (item, idx) {
                return el(
                  "div",
                  { key: idx, style: { background: "var(--dsw-alias-bg-layer-2)", border: "1px solid var(--dsw-alias-border-l1)", borderRadius: 6, padding: "8px 12px", marginBottom: 8 } },
                  el(
                    "div",
                    { style: { display: "flex", justifyContent: "space-between", marginBottom: 4 } },
                    el("span", { className: "ig5-mono", style: { color: "var(--dsw-alias-brand-primary)", fontWeight: 600 } }, item.tool),
                    el("span", { className: "ig5-mono ig5-card-sub" }, item.time || "时间未记录")
                  ),
                  el("span", { className: "ig5-chip " + (item.isError ? "write" : "read") }, item.isError ? "执行错误" : "执行记录"),
                  el("div", { className: "ig5-mono", style: { fontSize: 12, marginBottom: 4 } },
                    "目标地址: " + (item.ea || "-") + " · 文件偏移: " + (item.fileOffset === undefined || item.fileOffset === null ? "-" : String(item.fileOffset))
                  ),
                  item.detail ? el("p", { className: item.isError ? "ig5-error" : "ig5-card-sub" }, item.detail) : null,
                  item.before !== undefined && item.after !== undefined
                    ? el(
                        "div",
                        { className: "ig5-mono", style: { fontSize: 11, background: "var(--dsw-alias-bg-layer-3)", padding: "4px 8px", borderRadius: 4, display: "flex", gap: 12 } },
                        el("span", { style: { color: "var(--dsw-alias-state-error-primary)", overflowWrap: "anywhere" } }, "- " + String(item.before)),
                        el("span", { style: { color: "var(--dsw-alias-state-success-primary)", overflowWrap: "anywhere" } }, "+ " + String(item.after))
                      )
                    : null
                );
              }),
              !records.length && !approvals.loading && !approvals.error ? el("div", { className: "ig5-card-sub" }, "当前目标暂无写操作记录。审批后执行的工具结果会显示于此。") : null,
              el("div", { className: "ig5-form-row", style: { justifyContent: "space-between" } },
                el("span", { className: "ig5-card-sub" }, (approvals.total == null ? "已读取至少 " + (approvals.totalLowerBound || 0) : "共 " + approvals.total) + " 条 · 第 " + (page.history.length + 1) + " 页"),
                el("div", { className: "ig5-form-row" },
                  el("button", { className: "ig5-btn", disabled: !page.history.length || approvals.loading, onClick: function () { setPage(function (s) { var previous = s.history[s.history.length - 1]; return Object.assign({}, s, previous, { history: s.history.slice(0, -1) }); }); } }, "上一页"),
                  el("button", { className: "ig5-btn", disabled: !approvals.hasMore || approvals.loading, onClick: function () { setPage(function (s) { return Object.assign({}, s, { offset: s.offset + (approvals.nextCursor ? records.length : 20), cursor: approvals.nextCursor || null, history: s.history.concat([{ offset: s.offset, cursor: s.cursor }]) }); }); } }, "下一页")))
            ),
            el(
              "div",
              { className: "ig5-card" },
              el(
                "div",
                { className: "ig5-card-title" },
                el("span", { className: "ig5-card-title-text" }, "↩ 自管操作日志与逐级回滚 (Undo Controller)")
              ),
              el("p", { className: "ig5-card-sub", style: { marginBottom: 12 } },
                "可回滚范围由当前引擎的操作日志决定。重命名、字节补丁和注释可逐步撤销；类型与结构体修改请先核对后端返回的 Undo 和持久化状态。"
              ),
              el("button", {
                className: "ig5-btn",
                onClick: function () {
                  alert("可在会话中对模型说:「调用 ig5_undo 撤销上一步操作」进行安全回滚！");
                }
                }, "查看回滚调用提示 (ig5_undo)")
            )
          );
        }

        /* ── Tab 6: 工具能力目录与会话协同 (Tool Matrix) ── */
        function Ig5ToolsMatrixView(props) {
          var dash = props.dash;
          var readTools = [
            "ig5_doctor", "ig5_open", "ig5_status", "ig5_funcs", "ig5_strings",
            "ig5_decompile", "ig5_xrefs", "ig5_calls", "ig5_bytes", "ig5_search",
            "ig5_listing", "ig5_scan", "ig5_export_diff", "ig5_cfg", "ig5_slice", "ig5_fingerprint",
            "ig5_stack", "ig5_switches", "ig5_vtables", "ig5_microcode", "ig5_bindiff", "ig5_ir", "ig5_crypto", "ig5_protocol"
          ];
          var writeTools = [
            "ig5_rename", "ig5_patch_bytes", "ig5_comment", "ig5_analyze",
            "ig5_set_type", "ig5_undo", "ig5_run_idapython", "ig5_dbg", "ig5_struct",
            "ig5_switch_repair", "ig5_emulate", "ig5_sync"
          ];
          var metaTools = ["ig5_close", "ig5_profile"];
          var totalTools = readTools.length + writeTools.length + metaTools.length;

          return el(
            "div",
            null,
            el(
              "div",
              { className: "ig5-card" },
              el(
                "div",
                { className: "ig5-card-title" },
                el("span", { className: "ig5-card-title-text" }, "🤖 模型协同与会话投影 (Session Projection)")
              ),
              el(
                "div",
                { className: "ig5-stats-grid" },
                el("div", { className: "ig5-stat" },
                  el("span", { className: "ig5-stat-label" }, "累计工具调用"),
                  el("b", { className: "ig5-stat-value ig5-mono" }, String((dash && dash.calls) || 0) + " 次")
                ),
                el("div", { className: "ig5-stat" },
                  el("span", { className: "ig5-stat-label" }, "异常/拦截计数"),
                  el("b", { className: "ig5-stat-value ig5-mono", style: { color: (dash && dash.errors) ? "var(--dsw-alias-state-error-primary)" : "var(--dsw-alias-state-success-primary)" } }, String((dash && dash.errors) || 0) + " 次")
                ),
                el("div", { className: "ig5-stat" },
                  el("span", { className: "ig5-stat-label" }, "最近执行操作"),
                  el("b", { className: "ig5-stat-value ig5-mono" }, String((dash && dash.last) || "空闲"))
                )
              )
            ),
            el(
              "div",
              { className: "ig5-card" },
              el(
                "div",
                { className: "ig5-card-title" },
                el("span", { className: "ig5-card-title-text" }, "🧰 无限五代工具能力目录"),
                el("span", { className: "ig5-chip read ig5-mono" }, totalTools + " Tools · 完整目录")
              ),
              el("p", { className: "ig5-card-sub" }, "工具注册遵循宿主配置：core 默认提供 8 个入口，full 提供完整工具面。目录数量不代表当前会话已注册数量；请以 ig5_profile 返回的实际工具列表为准。"),
              el("p", { className: "ig5-card-sub" }, "默认 Reverse 内置核心与随包 Ghidra / x64dbg 提供静态分析与调试。五代核心已提供独立文件加载、原生 IR/CFG、RTTI 与真实 C 反编译；使用 ig5_ir level=kernel 无需启动 Java 或商业引擎，action=decompile 选择 C 输出。原生解码与反编译保留开源 Ghidra 核心来源。跳转表读取、修复与虚表分析也支持 Ghidra。ig5_microcode 返回实际 IG5/Ghidra IR 与优化记录；ig5_run_idapython 提供有界兼容 API，支持范围见返回结果。ig5_sync 需要两个静态数据库，Reverse 与 Ghidra 会话分别持有独立数据库。实际支持以当前后端 capabilities 为准。"),
              el(
                "div",
                { style: { marginBottom: 12 } },
                el("div", { style: { fontSize: 12, fontWeight: 600, color: "var(--dsw-alias-brand-primary)", marginBottom: 6 } }, "只读侦测域 (" + readTools.length + " 工具 · 包含 CFG、切片与指纹识别):"),
                readTools.map(function (t) { return el("span", { key: t, className: "ig5-chip read ig5-mono", style: { margin: 2 } }, t); })
              ),
              el(
                "div",
                { style: { marginBottom: 12 } },
                el("div", { style: { fontSize: 12, fontWeight: 600, color: "var(--dsw-alias-state-error-primary)", marginBottom: 6 } }, "写操作审批门 (" + writeTools.length + " 工具 · 包含结构体与类型系统):"),
                writeTools.map(function (t) { return el("span", { key: t, className: "ig5-chip write ig5-mono", style: { margin: 2 } }, t); })
              ),
              el(
                "div",
                null,
                el("div", { style: { fontSize: 12, fontWeight: 600, color: "var(--dsw-alias-label-secondary)", marginBottom: 6 } }, "生命周期与配置 (" + metaTools.length + " 工具):"),
                metaTools.map(function (t) { return el("span", { key: t, className: "ig5-chip ig5-mono", style: { margin: 2 } }, t); })
              )
            ),
            el(
              "div",
              { className: "ig5-card" },
              el(
                "div",
                { className: "ig5-card-title" },
                el("span", { className: "ig5-card-title-text" }, "💡 高阶逆向操作指令指引")
              ),
              el(
                "ul",
                { style: { margin: 0, paddingLeft: 18, fontSize: 12, lineHeight: 1.8, color: "var(--dsw-alias-label-secondary)" } },
                el("li", null, "结构体建模: 「根据 a1 的偏移访问，用 ig5_struct action=define 定义 struct Packet { ... } 并应用到该变量」"),
                el("li", null, "控制流分析: 「用 ig5_cfg 提取 main 函数的控制流图并输出 Mermaid 流程图」"),
                el("li", null, "变量焦点行: 「用 ig5_slice 查看函数 0x... 中匹配变量 key 的伪代码行」；这不代表完整数据流分析。"),
                el("li", null, "库函数过滤: 「用 ig5_fingerprint 识别标准库，然后在 ig5_funcs 中开启 user_only 排除噪音」")
              )
            )
          );
        }

        /* ── 底部输入框徽章 ── */
        function Ig5Badge(props) {
          useStyleOnce();
          var dash = useDash(props);
          var running = dash && dash.running;
          var text = "无限五代 " + VERSION + " · 多引擎";
          if (running) {
            text = "IG5 分析中: " + running;
          } else if (dash && dash.calls > 0) {
            text = "IG5 ✓ " + dash.calls + (dash.errors ? " · ✗" + dash.errors : "");
          }

          return el(
            "div",
            { className: "ig5-badge-wrap" },
            el(
              "div",
              {
                className: "ig5-badge",
                title: "点击打开「IG5 逆向工作台」",
                onClick: function () { if (typeof props.openView === "function") props.openView("ig5", ""); else activateTopTab(WORKBENCH_TAB_LABEL); }
              },
              el("span", {
                className: "ig5-dot " + (running ? "ig5-pulse" : ""),
                style: { background: running ? "var(--dsw-alias-state-warn-primary, #f59e0b)" : "var(--dsw-alias-state-success-primary, #10b981)" }
              }),
              el("span", null, text)
            )
          );
        }

        /* ── 插件生命周期挂载 ── */
        function apply(ctx) {
          diag("apply-start", "version " + VERSION);

          try {
            ctx.slots.inject("conversation.input.dock", function () {
              return ctx.slots.register(
                { name: "conversation.input.dock", id: "ig5-badge", order: 31 },
                function (props) { return el(Ig5Badge, Object.assign({}, props, { ig5ctx: ctx })); }
              );
            });
          } catch (e) {
            diag("badge-register-error", e && e.message);
          }

          try {
            ctx.slots.inject("conversation.view", function () {
              diag("view-tab-slot", "conversation.view 声明就绪");
              return ctx.slots.register(
                {
                  name: "conversation.view",
                  id: "ig5",
                  order: 25,
                  label: function () { return WORKBENCH_TAB_LABEL; },
                },
                function (props) { return el(Ig5Workbench, props); }
              );
            });
          } catch (e) {
            diag("view-tab-error", e && e.message);
          }

          try {
            ctx.slots.inject("sidebar.panellist", function () {
              return ctx.slots.register(
                { name: "sidebar.panellist", id: PANEL_ID, order: 55, label: function () { return WORKBENCH_TAB_LABEL; } },
                function () {
                  return el("svg", { width: 16, height: 16, viewBox: "0 0 16 16", fill: "currentColor" },
                    el("path", { d: "M2.5 3h4.6v2.1H4.7v5.8h2.4V13H2.5V3zm11 0H8.9v2.1h2.4v5.8H8.9V13h4.6V3zM6.6 7.2h2.8v1.6H6.6V7.2z" })
                  );
                }
              );
            });
          } catch (e) {}

          try {
            ctx.slots.inject("main", function () {
              return ctx.slots.register({ name: "main", key: PANEL_ID }, function (props) {
                return el(Ig5Workbench, props);
              });
            });
          } catch (e) {}
        }

        exports.name = PLUGIN_ID;
        exports.inject = inject;
        exports.apply = apply;
        // Exposed without side effects for deterministic renderer regression and local preview.
        exports.__test = { normalizeScan: normalizeScan, buildAnalysisDraft: buildAnalysisDraft, ScanView: Ig5ScanView, AnalysisDraft: AnalysisDraft, AnalysisView: Ig5AnalysisView, cfgFitCamera: cfgFitCamera, EnvironmentCard: Ig5EnvironmentCard, cfgPinchStart: cfgPinchStart, cfgPinchCamera: cfgPinchCamera, engineName: engineName, sessionIdentity: sessionIdentity, parseWorkbenchFocus: parseWorkbenchFocus, layoutCfg: layoutCfg, highlightParts: highlightParts, renderCodeLines: renderCodeLines, normalizeAudit: normalizeAudit, normalizedTarget: normalizedTarget, buildStructDraft: buildStructDraft, makeRequestGate: makeRequestGate, CfgGraph: CfgGraph, StructEditor: StructEditor, FunctionsView: Ig5FunctionsView, StringsView: Ig5StringsView, ListingView: Ig5ListingView, PatchesView: Ig5PatchesView, RuntimeView: Ig5RuntimeView, IrView: Ig5IrView, OverviewCard: Ig5OverviewCard, Workbench: Ig5Workbench };
        exports.__test.analysisReuseDraft = analysisReuseDraft;
        exports.__test.AnalysisEvidence = AnalysisEvidence;
        exports.__test.normalizeReadData = normalizeReadData;
        exports.__test.readData = readData;
        exports.__test.captureReadSnapshot = captureReadSnapshot;
        exports.__test.ToolsMatrixView = Ig5ToolsMatrixView;
        return module.exports;
      },
    });
  } catch (err) {
    console.warn("[AI Client Sandbox] dsh-infinite-gen-5 runtime error:", err);
  }
})();
