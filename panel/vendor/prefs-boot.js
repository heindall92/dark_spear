(function () {
  var h = document.documentElement;
  var t = localStorage.getItem("ds-theme") || "light";
  var l = localStorage.getItem("ds-lang") || "es";
  if (t !== "dark") t = "light";
  if (l !== "en") l = "es";
  h.classList.remove("light", "dark");
  h.classList.add(t);
  h.lang = l;
  if (localStorage.getItem("ds-sidebar") === "collapsed") {
    h.classList.add("sidebar-collapsed");
  }
})();
