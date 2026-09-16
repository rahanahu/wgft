// 管理 UI の最小限のクライアント処理（外部依存なし）。
// data-refresh を持つ要素を、その URL から 5 秒ごとに取得して中身を差し替える（仕様の自動更新）。
(function () {
  "use strict";
  function refresh(el) {
    fetch(el.dataset.refresh, { headers: { "X-Partial": "1" } })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (html) { if (html !== null) el.innerHTML = html; })
      .catch(function () { /* 一時的な失敗は無視して次の周期で再試行 */ });
  }
  function start() {
    var targets = document.querySelectorAll("[data-refresh]");
    if (!targets.length) return;
    var enabled = true;
    var toggle = document.getElementById("autorefresh-toggle");
    if (toggle) {
      toggle.addEventListener("click", function () {
        enabled = !enabled;
        toggle.classList.toggle("off", !enabled);
        toggle.setAttribute("aria-pressed", String(enabled));
      });
    }
    setInterval(function () {
      if (!enabled || document.hidden) return;
      targets.forEach(refresh);
    }, 5000);
  }
  // 破壊的操作はネイティブの confirm で確認する（data-confirm 付きの form）
  function confirmForms() {
    document.body.addEventListener("submit", function (e) {
      var f = e.target;
      if (f.dataset && f.dataset.confirm && !window.confirm(f.dataset.confirm)) {
        e.preventDefault();
      }
    });
  }
  // ルール追加フォームの補助：フロー図を入力に追従させ、proxy 専用項目を出し分ける。
  function initRuleForm() {
    var form = document.getElementById("rule-form");
    if (!form) return;
    var agent = document.getElementById("f-agent");
    var proto = document.getElementById("f-proto");
    var listen = document.getElementById("f-listen");
    var target = document.getElementById("f-target");
    var flowListen = document.getElementById("flow-listen");
    var flowAgent = document.getElementById("flow-agent");
    var flowTarget = document.getElementById("flow-target");
    var listenLabel = flowListen ? flowListen.textContent.replace(/^:/, "") : "";
    var agentLabel = flowAgent ? flowAgent.textContent : "";
    var targetLabel = flowTarget ? flowTarget.textContent : "";
    var proxyRadio = form.querySelector('input[name="vps_mode"][value="proxy"]');
    var kernelRadio = form.querySelector('input[name="vps_mode"][value="kernel"]');
    var proxyOnly = form.querySelector(".proxy-only");

    function agentName() {
      if (!agent || agent.selectedIndex < 0) return agentLabel;
      var t = (agent.options[agent.selectedIndex].text || "").trim();
      var i = t.indexOf(" (");
      return i > 0 ? t.slice(0, i) : (t || agentLabel);
    }
    function updateFlow() {
      if (flowListen) flowListen.textContent = ":" + (listen && listen.value.trim() ? listen.value.trim() : listenLabel);
      if (flowAgent) flowAgent.textContent = agentName();
      if (flowTarget) flowTarget.textContent = (target && target.value.trim()) ? target.value.trim() : targetLabel;
    }
    function updateMode() {
      if (proxyOnly) proxyOnly.hidden = !(proxyRadio && proxyRadio.checked);
    }
    function updateProto() {
      var udp = proto && proto.value === "udp";
      if (proxyRadio) proxyRadio.disabled = udp;
      if (udp && proxyRadio && proxyRadio.checked && kernelRadio) kernelRadio.checked = true;
      updateMode();
    }
    [listen, target].forEach(function (el) { if (el) el.addEventListener("input", updateFlow); });
    if (agent) agent.addEventListener("change", updateFlow);
    if (proto) proto.addEventListener("change", updateProto);
    form.querySelectorAll('input[name="vps_mode"]').forEach(function (r) { r.addEventListener("change", updateMode); });
    updateFlow();
    updateProto();
  }

  // ルール一覧のグループ見出し行の折りたたみ（単一テーブルなので行の表示を切り替える）。
  function initRuleGroups() {
    document.querySelectorAll(".group-toggle").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var g = btn.dataset.group;
        var open = btn.getAttribute("aria-expanded") !== "false";
        open = !open;
        btn.setAttribute("aria-expanded", String(open));
        btn.textContent = open ? "▾" : "▸";
        document.querySelectorAll('.rule-row[data-group="' + g + '"]').forEach(function (row) {
          row.hidden = !open;
        });
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { start(); confirmForms(); initRuleForm(); initRuleGroups(); });
  } else {
    start(); confirmForms(); initRuleForm(); initRuleGroups();
  }
})();
