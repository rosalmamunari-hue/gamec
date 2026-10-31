// Follow the system's light or dark setting. Loaded in <head> so the page never flashes the wrong colours.
(function () {
  var m = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)");
  function apply() { document.documentElement.setAttribute("data-bs-theme", m && m.matches ? "dark" : "light"); }
  apply();
  if (m && m.addEventListener) m.addEventListener("change", apply);
})();
