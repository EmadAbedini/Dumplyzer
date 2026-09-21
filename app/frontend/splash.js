(function () {
  document.addEventListener(
    "contextmenu",
    function (e) {
      e.preventDefault();
    },
    true,
  );

  var revealed = false;
  function reveal() {
    if (revealed) {
      return;
    }
    revealed = true;
    var invoke =
      window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke;
    if (invoke) {
      invoke("splash_ready").catch(function () {});
    }
  }

  var img = document.querySelector("img");
  if (!img) {
    reveal();
    return;
  }
  if (typeof img.decode === "function") {
    img.decode().then(reveal, reveal);
  } else if (img.complete) {
    reveal();
  } else {
    img.addEventListener("load", reveal);
    img.addEventListener("error", reveal);
  }
})();
