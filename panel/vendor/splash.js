(function () {
  var KEY = "ds-splash";

  function seen() {
    try {
      return localStorage.getItem(KEY) === "1";
    } catch (e) {
      return false;
    }
  }

  function markSeen() {
    try {
      localStorage.setItem(KEY, "1");
    } catch (e) {}
  }

  if (seen()) return;
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    markSeen();
    return;
  }

  function boot() {
    if (seen()) return;
    var wrap = document.createElement("div");
    wrap.id = "ds-splash";
    wrap.className = "ds-splash";
    wrap.setAttribute("role", "dialog");
    wrap.setAttribute("aria-label", "Dark Spear");
    wrap.tabIndex = -1;

    var video = document.createElement("video");
    video.src = "vendor/splash.mp4";
    video.autoplay = true;
    video.playsInline = true;
    video.setAttribute("playsinline", "");
    video.preload = "auto";
    video.volume = 1;

    var skip = document.createElement("button");
    skip.type = "button";
    skip.className = "ds-splash-skip";
    skip.textContent = "Saltar";

    wrap.appendChild(video);
    wrap.appendChild(skip);
    document.body.appendChild(wrap);
    wrap.focus();

    var finished = false;
    function done() {
      if (finished) return;
      finished = true;
      markSeen();
      video.pause();
      wrap.classList.add("ds-splash-out");
      setTimeout(function () {
        if (wrap.parentNode) wrap.parentNode.removeChild(wrap);
      }, 420);
    }

    function playWithSound() {
      video.muted = false;
      var play = video.play();
      if (play && play.catch) {
        play.catch(function () {
          video.muted = true;
          video.play().then(function () {
            wrap.addEventListener("click", function unmute(e) {
              if (e.target === skip) return;
              video.muted = false;
              video.play();
              wrap.removeEventListener("click", unmute);
            });
          }).catch(done);
        });
      }
    }

    video.addEventListener("ended", done);
    video.addEventListener("error", done);
    skip.addEventListener("click", function (e) {
      e.stopPropagation();
      done();
    });
    wrap.addEventListener("keydown", function (e) {
      if (e.key === "Escape") done();
    });
    video.addEventListener("loadedmetadata", function () {
      var ms = Math.max(4000, (video.duration || 8) * 1000 + 800);
      setTimeout(done, ms);
    });
    setTimeout(done, 20000);
    playWithSound();
  }

  if (document.body) boot();
  else document.addEventListener("DOMContentLoaded", boot);
})();
