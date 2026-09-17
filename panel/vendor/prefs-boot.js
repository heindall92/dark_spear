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
  try {
    var st = JSON.parse(localStorage.getItem("ds-settings") || "{}");
    if (!st || st.v !== 2) {
      localStorage.setItem("ds-settings", JSON.stringify({
        v: 2,
        orgName: "",
        orgEmail: "",
        tz: "",
        classification: "",
        "notify-critical": !st || st["notify-critical"] !== false,
        "notify-high": !st || st["notify-high"] !== false,
        "notify-done": !st || st["notify-done"] !== false
      }));
    }
  } catch (e) { /* ignore */ }
  try {
    var pr = JSON.parse(localStorage.getItem("ds-profile") || "{}");
    if (!pr || pr.v !== 2) {
      localStorage.setItem("ds-profile", JSON.stringify({ v: 2 }));
    }
  } catch (e) { /* ignore */ }
})();
