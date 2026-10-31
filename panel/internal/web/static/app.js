// Small helpers on top of Tabler. Every page also works without them: a form then submits without asking.
(function () {
  "use strict";

  // Ask before a form with data-confirm (on the form or on the button that sent it) is sent.
  var modalEl = document.getElementById("confirm-modal");
  var modal = modalEl && window.bootstrap ? new bootstrap.Modal(modalEl) : null;
  var pending = null;

  document.addEventListener("submit", function (ev) {
    var form = ev.target, btn = ev.submitter;
    var text = (btn && btn.dataset.confirm) || form.dataset.confirm;
    if (text && form.dataset.confirmed !== "1" && modal) {
      ev.preventDefault();
      pending = { form: form, btn: btn };
      modalEl.querySelector("[data-confirm-text]").textContent = text;
      var ok = modalEl.querySelector("[data-confirm-ok]");
      ok.textContent = (btn && btn.dataset.confirmOk) || form.dataset.confirmOk || "确定";
      modal.show();
      return;
    }
    form.dataset.confirmed = "";
    busy(btn || form.querySelector("button[type=submit],button:not([type])"));
  });

  if (modalEl) {
    modalEl.querySelector("[data-confirm-ok]").addEventListener("click", function () {
      if (!pending) return;
      var p = pending;
      pending = null;
      modal.hide();
      p.form.dataset.confirmed = "1";
      if (p.form.requestSubmit) p.form.requestSubmit(p.btn || undefined); else p.form.submit();
    });
  }

  // A button that started something slow shows that it is working, and cannot be pressed twice. It is
  // disabled only after the browser has taken the form's values (a disabled button sends nothing).
  function busy(btn) {
    if (!btn || btn.dataset.noBusy !== undefined) return;
    setTimeout(function () {
      btn.disabled = true;
      var label = btn.dataset.busy || "处理中…";
      btn.innerHTML = "";
      var s = document.createElement("span");
      s.className = "spinner-border spinner-border-sm me-2";
      s.setAttribute("aria-hidden", "true");
      btn.appendChild(s);
      btn.appendChild(document.createTextNode(label));
    }, 0);
  }

  // Copy buttons: data-copy="#element" copies that element's text; the button's <span> says it worked.
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-copy]");
    if (!btn) return;
    var src = document.querySelector(btn.dataset.copy);
    if (!src || !navigator.clipboard) return;
    navigator.clipboard.writeText(src.textContent.trim()).then(function () {
      var label = btn.querySelector("span");
      if (!label) return;
      if (!btn.dataset.label) btn.dataset.label = label.textContent;
      label.textContent = "已复制";
      setTimeout(function () { label.textContent = btn.dataset.label; }, 1600);
    });
  });
})();
