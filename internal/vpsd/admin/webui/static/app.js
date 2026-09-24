// 管理 UI の最小限のクライアント処理（外部依存なし）。
// data-refresh を持つ要素を、その URL から 5 秒ごとに取得して中身を差し替える（仕様の自動更新）。
(function () {
  "use strict";
  function refresh(el) {
    // #rules は差し替えのたびにグループの折りたたみ state と group-toggle の click
    // listener を失う（querySelectorAll で一度だけ束縛しているため）ので、差し替えの前後で
    // 折りたたみ state を保存・復元し、listener を束縛し直す。他の要素（#warnings、#agents、
    // #health）は差し替えても壊れる state を持たない。
    var isRules = el.id === "rules";
    var collapsed = isRules ? collapsedGroupNames() : null;
    fetch(el.dataset.refresh, { headers: { "X-Partial": "1" } })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (html) {
        if (html === null) return;
        el.innerHTML = html;
        syncToggle(el);
        if (isRules) {
          initRuleGroups();
          restoreCollapsedGroups(collapsed);
        }
      })
      .catch(function () { /* 一時的な失敗は無視して次の周期で再試行 */ });
  }
  // collapsedGroupNames/restoreCollapsedGroups: グループの折りたたみは group-name の表示名を
  // 手掛かりに保つ（data-group はグループの並び順で振った通し番号なので、部分更新の間に
  // グループの追加・削除で並びが変わると同じ番号が別のグループを指しうる）。
  function collapsedGroupNames() {
    var names = {};
    document.querySelectorAll("#rules .group-row").forEach(function (row) {
      var btn = row.querySelector(".group-toggle");
      var label = row.querySelector(".group-name");
      if (btn && label && btn.getAttribute("aria-expanded") === "false") {
        names[label.textContent] = true;
      }
    });
    return names;
  }
  function restoreCollapsedGroups(names) {
    if (!names) return;
    document.querySelectorAll("#rules .group-row").forEach(function (row) {
      var btn = row.querySelector(".group-toggle");
      var label = row.querySelector(".group-name");
      if (!btn || !label || !names[label.textContent]) return;
      btn.setAttribute("aria-expanded", "false");
      btn.textContent = "▸";
      var g = btn.dataset.group;
      document.querySelectorAll('.rule-row[data-group="' + g + '"]').forEach(function (r) {
        r.hidden = true;
      });
    });
  }
  // syncToggle は、部分更新で作り直された切り替えのボタンに今の状態を描き直す。
  function syncToggle(el) {
    var t = el.querySelector && el.querySelector("#autorefresh-toggle");
    if (!t) return;
    var off = document.body.dataset.autorefresh === "off";
    t.classList.toggle("off", off);
    t.setAttribute("aria-pressed", String(!off));
  }
  function start() {
    var targets = document.querySelectorAll("[data-refresh]");
    if (!targets.length) return;
    var enabled = true;
    // 切り替えのボタンは #agents の中にあり、その部分更新で作り直される。要素に直接束縛すると
    // 最初の差し替えで listener を失うので、document から委譲し、差し替えの後の見た目も直す。
    document.body.addEventListener("click", function (e) {
      var toggle = e.target.closest && e.target.closest("#autorefresh-toggle");
      if (!toggle) return;
      enabled = !enabled;
      document.body.dataset.autorefresh = enabled ? "on" : "off";
      toggle.classList.toggle("off", !enabled);
      toggle.setAttribute("aria-pressed", String(enabled));
    });
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
    // A listen port range maps onto the destination starting at its port, one port after another,
    // so show the destination as host:lo-hi (the same shape as the rules list).
    function effectiveTarget(listenValue, targetValue) {
      var range = /^(\d+)-(\d+)$/.exec(listenValue);
      var hp = /^(.*):(\d+)$/.exec(targetValue);
      if (!range || !hp) return targetValue;
      var width = parseInt(range[2], 10) - parseInt(range[1], 10);
      if (!(width > 0)) return targetValue;
      return hp[1] + ":" + hp[2] + "-" + (parseInt(hp[2], 10) + width);
    }
    var listenLabel = flowListen ? flowListen.textContent.replace(/^:/, "") : "";
    var agentLabel = flowAgent ? flowAgent.textContent : "";
    var targetLabel = flowTarget ? flowTarget.textContent : "";
    var proxyRadio = form.querySelector('input[name="vps_mode"][value="proxy"]');
    var kernelRadio = form.querySelector('input[name="vps_mode"][value="kernel"]');
    var proxyOnly = form.querySelector(".proxy-only");
    // Userspace mode: a single "PROXY protocol" checkbox replaces the kernel/proxy radio group
    // (the per-rule kernel/proxy choice has no meaning once the server relays every rule).
    // The checkbox drives a hidden vps_mode field so the submitted form still carries kernel/proxy.
    var usProxyCheckbox = document.getElementById("f-proxy-userspace");
    var usModeHidden = document.getElementById("f-vps-mode-userspace");

    function agentName() {
      if (!agent || agent.selectedIndex < 0) return agentLabel;
      var t = (agent.options[agent.selectedIndex].text || "").trim();
      var i = t.indexOf(" (");
      return i > 0 ? t.slice(0, i) : (t || agentLabel);
    }
    function updateFlow() {
      if (flowListen) flowListen.textContent = ":" + (listen && listen.value.trim() ? listen.value.trim() : listenLabel);
      if (flowAgent) flowAgent.textContent = agentName();
      if (flowTarget) flowTarget.textContent = (target && target.value.trim()) ? effectiveTarget(listen ? listen.value.trim() : "", target.value.trim()) : targetLabel;
    }
    function updateMode() {
      if (proxyOnly) proxyOnly.hidden = !(proxyRadio && proxyRadio.checked);
    }
    // PROXY protocol requires vps_mode=proxy, which only applies to TCP (proto.Rule.Validate).
    function updateUserspaceMode() {
      if (!usProxyCheckbox || !usModeHidden) return;
      usModeHidden.value = usProxyCheckbox.checked ? "proxy" : "kernel";
    }
    function updateProto() {
      var udp = proto && proto.value === "udp";
      if (proxyRadio) proxyRadio.disabled = udp;
      if (udp && proxyRadio && proxyRadio.checked && kernelRadio) kernelRadio.checked = true;
      if (usProxyCheckbox) {
        usProxyCheckbox.disabled = udp;
        if (udp && usProxyCheckbox.checked) usProxyCheckbox.checked = false;
      }
      updateMode();
      updateUserspaceMode();
    }
    [listen, target].forEach(function (el) { if (el) el.addEventListener("input", updateFlow); });
    if (agent) agent.addEventListener("change", updateFlow);
    if (proto) proto.addEventListener("change", updateProto);
    form.querySelectorAll('input[name="vps_mode"]').forEach(function (r) { r.addEventListener("change", updateMode); });
    if (usProxyCheckbox) usProxyCheckbox.addEventListener("change", updateUserspaceMode);
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

  // レート制限の各行：「制限しない」を選ぶと数値と単位を無効にする（見た目の補助。判定は
  // nolimit の値そのもので行うので、この JS が動かなくても保存の挙動は変わらない）。
  function initRateForm() {
    document.querySelectorAll(".rate-row").forEach(function (row) {
      var checkbox = row.querySelector('input[type="checkbox"]');
      var count = row.querySelector('input[type="number"]');
      var unit = row.querySelector("select");
      if (!checkbox || !count || !unit) return;
      function sync() {
        count.disabled = checkbox.checked;
        unit.disabled = checkbox.checked;
      }
      checkbox.addEventListener("change", sync);
      sync();
    });
  }

  // ルール詳細ページの分割区画:選んだ位置での 2 つの結果(受信範囲→宛先範囲)を、送信前に
  // その場で計算して見せる(仕様 10.1 節)。無効な値(範囲外)なら何も出さない。
  function initSplitForm() {
    var form = document.getElementById("split-form");
    if (!form) return;
    var select = document.getElementById("split-at");
    var preview = document.getElementById("split-preview");
    var lo = parseInt(form.dataset.listenLo, 10);
    var hi = parseInt(form.dataset.listenHi, 10);
    var host = form.dataset.targetHost;
    var port = parseInt(form.dataset.targetPort, 10);
    function rangeStr(a, b) { return a === b ? String(a) : a + "-" + b; }
    function update() {
      var at = select && parseInt(select.value, 10);
      if (!preview) return;
      if (!(at > lo && at <= hi) || !host || isNaN(port)) {
        preview.textContent = "";
        return;
      }
      var headHiPort = port + (at - 1 - lo);
      var tailLoPort = port + (at - lo);
      var tailHiPort = port + (hi - lo);
      preview.textContent =
        rangeStr(lo, at - 1) + " → " + host + ":" + rangeStr(port, headHiPort) +
        "   /   " + rangeStr(at, hi) + " → " + host + ":" + rangeStr(tailLoPort, tailHiPort);
    }
    if (select) select.addEventListener("change", update);
    update();
  }

  // 名前の入力で確かめる削除(エージェントの詳細ページの「危険な操作」)。名前が一致するまで送信の
  // ボタンを押せなくする。補助にとどまり、照合は server が行う(設計文書 10.1 節)
  function initNameConfirm() {
    document.querySelectorAll("form.name-confirm-form").forEach(function (form) {
      var input = form.querySelector('input[name="confirm_name"]');
      var button = form.querySelector('button[type="submit"]');
      if (!input || !button) return;
      function sync() { button.disabled = input.value !== form.dataset.name; }
      input.addEventListener("input", sync);
      sync();
    });
  }

  function init() { start(); confirmForms(); initRuleForm(); initRuleGroups(); initRateForm(); initSplitForm(); initNameConfirm(); }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
