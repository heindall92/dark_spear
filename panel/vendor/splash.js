(function () {
  if (sessionStorage.getItem("ds-splash") === "1") return;
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    sessionStorage.setItem("ds-splash", "1");
    return;
  }

  function boot() {
    if (sessionStorage.getItem("ds-splash") === "1") return;
    var wrap = document.createElement("div");
    wrap.id = "ds-splash";
    wrap.className = "ds-splash";
    wrap.setAttribute("role", "dialog");
    wrap.setAttribute("aria-label", "Dark Spear");
    var video = document.createElement("video");
    video.src = "vendor/splash.mp4";
    video.muted = true;
    video.autoplay = true;
    video.playsInline = true;
    video.setAttribute("playsinline", "");
    video.setAttribute("muted", "");
    wrap.appendChild(video);
    document.body.appendChild(wrap);

    var finished = false;
    function done() {
      if (finished) return;
      finished = true;
      sessionStorage.setItem("ds-splash", "1");
      wrap.classList.add("ds-splash-out");
      setTimeout(function () {
        if (wrap.parentNode) wrap.parentNode.removeChild(wrap);
      }, 420);
    }

    video.addEventListener("ended", done);
    video.addEventListener("error", done);
    wrap.addEventListener("click", done);
    wrap.addEventListener("keydown", function (e) {
      if (e.key === "Escape" || e.key === "Enter" || e.key === " ") done();
    });
    setTimeout(done, 8000);
    var play = video.play();
    if (play && play.catch) play.catch(done);
  }

  if (document.body) boot();
  else document.addEventListener("DOMContentLoaded", boot);
})();
